# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore fzjpepe Primi

<#
.SYNOPSIS
    Search GitHub Issues and Pull Requests for records related to a given
    exception signature.

.DESCRIPTION
    Given a top-level exception message and (optionally) an inner exception,
    script name, or discriminator function name, this helper runs targeted
    `gh search issues` queries against the repository and classifies each
    result as either a possible duplicate or a similar-but-not-identical
    issue.

    Duplicate = the issue's title or body contains BOTH the normalized
                top-level phrase AND the normalized inner-exception phrase
                (or a close paraphrase).
    Similar   = the issue matches the top-level OR the inner-exception
                phrase (but not both). A discriminator-function-name
                match alone does NOT qualify -- the same enclosing
                function can fail for unrelated reasons at different
                call sites. Function-only matches are discarded and
                counted in DiscardedFunctionOnly for transparency.

    Result objects are returned; the caller renders them into their own
    report format. All strings pulled from issue bodies are UNTRUSTED
    content and must be redacted + HTML-encoded by the caller before
    quoting.

.PARAMETER Repository
    Owner/repo, e.g. 'microsoft/CSS-Exchange'.

.PARAMETER TopLevelException
    The top-level exception message, redacted by the caller.

.PARAMETER InnerException
    The inner exception message, redacted by the caller. Optional but
    strongly recommended -- duplicate classification requires it.

.PARAMETER ScriptName
    The analyzed script name (e.g. 'HealthChecker.ps1') for scoped queries.

.PARAMETER DiscriminatorFunction
    The failing function name from the stack (e.g.
    'Invoke-JobOrganizationInformation').

.PARAMETER MaxResults
    Cap on total unique issues examined; default 20.

.OUTPUTS
    PSCustomObject with:
      .Duplicates              [PSCustomObject[]] Number, State, Title, Url, Reason
      .Similar                 [PSCustomObject[]] Number, State, Title, Url, Reason
      .QueriesRun              [string[]]
      .TotalResultsExamined    [int]
      .DiscardedFunctionOnly   [int]  # count of results that matched
                                      # only on discriminator function
                                      # name and were filtered out
      .Status                  'Ok' | 'PartialLookup' | 'GhUnavailable' | 'AuthFailure' | 'RateLimited' | 'Error'
      .StatusDetail            [string]

.NOTES
    Trust boundary: issue titles and bodies are untrusted content and may
    carry adversarial instructions. The caller MUST redact and HTML-encode
    every returned string before rendering.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    # Defense-in-depth: reject any $Repository value that is not of the
    # shape `owner/repo`, where each component starts and ends with an
    # alphanumeric and only contains [A-Za-z0-9._-] in between. This
    # matches GitHub's own repo-name grammar more closely and — most
    # importantly — rejects traversal-shaped values like `../evil`
    # (where `..` would otherwise match `[.]+`). The pattern also
    # cannot smuggle whitespace, path separators, or shell
    # metacharacters into `gh --repo $Repository` or into the
    # `/repos/$Repository/...` URL segment. Enforcement at the param
    # declaration means downstream code paths cannot forget to
    # validate — the param binding fails before any body runs.
    [ValidatePattern('\A[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?/[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?\z')]
    [string]$Repository,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw "TopLevelException cannot be empty or whitespace-only. Callers must supply a real exception message; an empty search would produce Status='Ok' with zero results and misrepresent 'no related issue found' to downstream reports."
            }
            return $true
        })]
    [string]$TopLevelException,

    [string]$InnerException,

    [string]$ScriptName,

    [string]$DiscriminatorFunction,

    [ValidateRange(1, 100)]
    [int]$MaxResults = 20
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
# Iter-23 (RD-branch-8): explicitly disable native-command
# error promotion inside this script's scope. If the caller
# enabled $PSNativeCommandUseErrorActionPreference, a nonzero
# `gh` exit would throw NativeCommandExitException BEFORE our
# `$LASTEXITCODE` handling ran — breaking the structured
# `Status = 'AuthFailure' / 'RateLimited' / 'Error'` result
# contract this script advertises.
$PSNativeCommandUseErrorActionPreference = $false

# ---------------------------------------------------------------------------
# Normalize an exception string so lexical searches and substring comparisons
# are stable across runs. This is redaction-adjacent but not the same thing
# as the caller's PII redaction -- it strips VOLATILE-BUT-NOT-SENSITIVE
# substrings (random module suffixes, timestamps, absolute paths) so that
# two runs of the same failure produce comparable phrases.
# ---------------------------------------------------------------------------
function ConvertTo-NormalizedPhrase {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $s = $Text
    # Strip Windows absolute paths (already redacted by caller, but path
    # tail can still be volatile per-machine).
    $s = [regex]::Replace($s, '[A-Za-z]:\\[^\s"'']+', '<path>')
    # Strip UNC paths.
    $s = [regex]::Replace($s, '\\\\[^\s"'']+', '<unc>')
    # Strip randomized temp module names like tmpEXO_3fzjpepe.o0p
    $s = [regex]::Replace($s, 'tmpEXO_[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)?', 'tmpEXO_<random>')
    # Strip GUIDs.
    $s = [regex]::Replace($s, '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '<guid>', 'IgnoreCase')
    # Strip timestamps [MM/dd/yyyy HH:mm:ss.fffffff].
    $s = [regex]::Replace($s, '\[\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?\]', '<ts>')
    # Collapse whitespace.
    $s = [regex]::Replace($s, '\s+', ' ').Trim()
    return $s
}

# ---------------------------------------------------------------------------
# Reduce a normalized phrase (which still carries `<path>`, `<unc>`, `<guid>`,
# `<ts>`, and `tmpEXO_<random>` placeholders left in by ConvertTo-NormalizedPhrase)
# to a form that is safe to submit as an EXACT-substring GitHub search.
#
# GitHub's search does NOT treat `<path>` (or any other placeholder we insert)
# as a wildcard: a quoted query `"Failure at <path>"` requires the literal
# substring `Failure at <path>` to appear in the issue, which no real issue
# body ever contains. Leaving the placeholders in the search phrase silently
# guarantees zero matches — the caller sees Status='Ok' with empty results
# and (correctly, by contract) reports "no related issue found" even though
# a genuine duplicate exists in the tracker.
#
# The placeholders remain useful for LOCAL classification (comparing issue
# body substrings to the current failure); this reducer is only applied to
# the phrase that is actually submitted to `gh`.
# ---------------------------------------------------------------------------
function ConvertTo-SearchablePhrase {
    param([string]$NormalizedText)
    if ([string]::IsNullOrWhiteSpace($NormalizedText)) { return '' }
    $s = $NormalizedText
    # Drop every placeholder token; GitHub search cannot use them as
    # wildcards. Each placeholder is replaced with a single space so
    # word boundaries stay intact.
    $s = $s -replace '<path>', ' '
    $s = $s -replace '<unc>', ' '
    $s = $s -replace '<guid>', ' '
    $s = $s -replace '<ts>', ' '
    $s = $s -replace 'tmpEXO_<random>', ' '
    # Collapse whitespace + trim.
    $s = [regex]::Replace($s, '\s+', ' ').Trim()
    return $s
}

# Extract a short distinctive phrase (~40-80 chars) from a normalized
# message for use inside `gh search issues`. gh's search is token-based,
# not phrase-based, and long phrases fail to match; short quoted phrases
# work best. Never cut mid-token — end at the last word boundary within
# the budget so we do not emit fragments like "DeserializePrimi".
function Get-DistinctivePhrase {
    param([string]$NormalizedText)
    if ([string]::IsNullOrWhiteSpace($NormalizedText)) { return $null }
    # Prefer the FIRST line up to any ':' followed by whitespace; that is
    # typically the exception class + one-line message.
    $firstLine = ($NormalizedText -split '\r?\n')[0]
    if ($firstLine.Length -le 80) { return $firstLine }
    # Cut at the last full word within the 80-char budget.
    $budget = $firstLine.Substring(0, 80)
    $m = [regex]::Match($budget, '\A(.+)\b\W')
    if ($m.Success) { return $m.Groups[1].Value.TrimEnd() }
    # Fallback: last whitespace within the budget.
    $lastSpace = $budget.LastIndexOf(' ')
    if ($lastSpace -gt 20) { return $budget.Substring(0, $lastSpace).TrimEnd() }
    # Nothing better — return the untruncated line rather than a mid-token cut.
    return $firstLine
}

# Escape a search phrase for `gh search issues`. GitHub search treats
# double-quote as the phrase delimiter and has query-syntax operators
# (AND/OR/NOT/is:/state:/etc). We want to submit the phrase as literal
# text. Remove embedded double-quotes and any leading operator-like
# tokens so a crafted exception cannot alter the query. The result is
# always safe to interpolate inside outer double quotes.
function Get-SafeQueryPhrase {
    param([string]$Phrase)
    if ([string]::IsNullOrWhiteSpace($Phrase)) { return '' }
    $p = $Phrase
    # Strip characters that alter query semantics.
    $p = [regex]::Replace($p, '[\"`\r\n\t]', ' ')
    # Strip characters that are search-syntax metacharacters (parens,
    # brackets, colons, angle brackets) — replace with space so token
    # structure is preserved but no operator escapes.
    $p = [regex]::Replace($p, '[\(\)\[\]\{\}\<\>:]', ' ')
    # Neutralize GitHub search's Boolean operators when they appear as
    # standalone UPPERCASE tokens. Left as-is, a crafted exception
    # phrase like `Cannot deserialize AND rethrow` becomes a Boolean
    # query that broadens the search away from the literal exception,
    # fills the result window with noise, and can bury the real match.
    # Downcase so gh receives them as ordinary words. Case is meaningful
    # to the GitHub search grammar; lowercase versions are treated as
    # search terms, not operators.
    $p = [regex]::Replace($p, '\b(AND|OR|NOT)\b', { param($m) $m.Value.ToLowerInvariant() })
    # Collapse whitespace and trim.
    $p = [regex]::Replace($p, '\s+', ' ').Trim()
    return $p
}

function Invoke-GhSearch {
    param(
        [string]$Query,
        [int]$Limit,
        # Iter-23 (RD-branch-12): callers pass -ExactPhrase for
        # exception-content queries. `Get-SafeQueryPhrase` strips
        # all double-quotes (they are query-syntax metacharacters
        # in adversarial input), so the caller cannot pre-quote
        # the phrase. Instead the caller flags "this is an exact
        # phrase" and this helper adds a trusted outer pair of
        # quotes AFTER sanitization. Without this, exception text
        # like `The remote server returned an error` is submitted
        # as tokens, matches unrelated network issues, and buries
        # the actual issue that quoted the phrase verbatim.
        [switch]$ExactPhrase
    )
    # Repository must have been validated by the caller (owner/repo
    # shape check at param time). Do NOT let the phrase inject its own
    # `repo:` qualifier or trailing operators.
    $safeQuery = Get-SafeQueryPhrase $Query
    if ([string]::IsNullOrWhiteSpace($safeQuery)) {
        return @{ Exit = 1; Raw = 'empty query after sanitization'; QArg = ''; FailureKind = 'EmptyQuery' }
    }
    # `--repo` flag is the only reliable way to scope `gh search issues`
    # to one repo — a `repo:<owner>/<name>` qualifier embedded in the
    # positional query string is silently ignored and the search leaks
    # across all of GitHub. Prepend the qualifier is NOT sufficient.
    # Do NOT append `repo:` to the free-text argument.
    # Iter-23 (RD-branch-13): prefix `github.com/` on the repo
    # argument so an inherited or hostile GH_HOST cannot redirect
    # this search to another GitHub-flavored host. Matches the
    # release helper's `gh release list --repo github.com/<repo>`
    # pattern.
    # Iter-23 (RD-branch-12): when the caller asked for an exact
    # phrase, wrap the sanitized text in a trusted outer pair of
    # double-quotes. Get-SafeQueryPhrase already stripped any
    # internal quotes and query-syntax metacharacters, so the
    # outer pair cannot be broken by adversarial content.
    if ($ExactPhrase) {
        $qArg = "`"$safeQuery`" in:title,body"
    } else {
        $qArg = "$safeQuery in:title,body"
    }
    $qualifiedRepo = "github.com/$Repository"
    $out = & gh search issues $qArg --repo $qualifiedRepo --limit $Limit --json 'number,state,title,url,body' 2>&1
    $exit = $LASTEXITCODE
    return @{
        Exit        = $exit
        Raw         = ($out -join "`n")
        QArg        = $qArg
        FailureKind = if ($exit -eq 0) { $null } else { 'GhExit' }
    }
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
$gh = Get-Command gh -ErrorAction SilentlyContinue
if ($null -eq $gh) {
    return [PSCustomObject]@{
        Duplicates            = @()
        Similar               = @()
        QueriesRun            = @()
        TotalResultsExamined  = 0
        DiscardedFunctionOnly = 0
        Status                = 'GhUnavailable'
        StatusDetail          = 'gh CLI not found on PATH.'
    }
}

# Verify auth (quietly; do not fail hard if gh emits noise on stderr).
# Iter-23 (RD-branch-13): pin to github.com so an inherited or
# hostile GH_HOST cannot direct the auth check (and any subsequent
# ambient credential attachment) at a different GitHub-flavored
# host.
$authOut = & gh auth status --hostname github.com 2>&1
if ($LASTEXITCODE -ne 0) {
    return [PSCustomObject]@{
        Duplicates            = @()
        Similar               = @()
        QueriesRun            = @()
        TotalResultsExamined  = 0
        DiscardedFunctionOnly = 0
        Status                = 'AuthFailure'
        StatusDetail          = ($authOut -join "`n")
    }
}

# ---------------------------------------------------------------------------
# Build search phrases
# ---------------------------------------------------------------------------
$normTop = ConvertTo-NormalizedPhrase -Text $TopLevelException
$normInner = ConvertTo-NormalizedPhrase -Text $InnerException
# Reduce placeholders BEFORE picking the distinctive phrase — see
# ConvertTo-SearchablePhrase for why leaving `<path>` etc. in the
# submitted phrase silently zeroes out every search.
$searchTop = ConvertTo-SearchablePhrase -NormalizedText $normTop
$searchInner = ConvertTo-SearchablePhrase -NormalizedText $normInner
$topPhrase = Get-DistinctivePhrase -NormalizedText $searchTop
$innerPhrase = Get-DistinctivePhrase -NormalizedText $searchInner

# Iter-23 (RD-branch-12): each query is now a hashtable carrying
# an ExactPhrase flag. Exception-content phrases MUST be submitted
# with outer quotes so GitHub's search returns exact-substring
# matches; identifier tokens (function names, script stem)
# intentionally use token search.
$queries = @()
if ($topPhrase) { $queries += @{ Query = $topPhrase; ExactPhrase = $true } }
if ($innerPhrase -and $innerPhrase -ne $topPhrase) { $queries += @{ Query = $innerPhrase; ExactPhrase = $true } }
if ($DiscriminatorFunction) { $queries += @{ Query = $DiscriminatorFunction; ExactPhrase = $false } }
if ($ScriptName) {
    $scriptStem = [System.IO.Path]::GetFileNameWithoutExtension($ScriptName)
    if ($topPhrase) {
        # A single distinctive token from the top-level phrase, plus the
        # script stem, catches script-scoped issues that do not quote the
        # exception verbatim.
        $topTokens = ($topPhrase -split '\s+' | Where-Object { $_.Length -ge 6 }) | Select-Object -First 1
        if ($topTokens) { $queries += @{ Query = "$scriptStem $topTokens"; ExactPhrase = $false } }
    }
}

# ---------------------------------------------------------------------------
# Execute queries and deduplicate by issue number
# ---------------------------------------------------------------------------
$aggregate = @{}
$queriesRun = @()
# Iter-23 (RD-branch-4): track query-level failures explicitly.
# Previously, non-rate-limit `gh` errors and JSON parse errors
# were silently swallowed, and the function still returned
# Status='Ok'. That masked network / auth / repo-access failures
# as "no related issue", which caused analyze-debug-files to
# skip the "lookup unavailable" note. Now we count both kinds of
# failure and downgrade the returned Status when appropriate.
$searchFailures = @()

foreach ($qItem in $queries) {
    if ($aggregate.Count -ge $MaxResults) { break }
    $result = Invoke-GhSearch -Query $qItem.Query -Limit ([Math]::Min(10, ($MaxResults - $aggregate.Count))) -ExactPhrase:$qItem.ExactPhrase
    # Record the query actually SENT to gh (post-sanitization, with
    # in:title,body qualifier). The user-facing report should show what
    # was searched, not what we wanted to search — the two can differ
    # when adversarial punctuation, Boolean operators, or truncation
    # rewriting is applied.
    if ($result.ContainsKey('QArg') -and $result.QArg) {
        $queriesRun += $result.QArg
    } else {
        $queriesRun += $qItem.Query
    }
    if ($result.Exit -ne 0) {
        if ($result.Raw -match 'rate limit') {
            return [PSCustomObject]@{
                Duplicates            = @()
                Similar               = @()
                QueriesRun            = $queriesRun
                TotalResultsExamined  = 0
                DiscardedFunctionOnly = 0
                Status                = 'RateLimited'
                StatusDetail          = 'GitHub search rate limit hit.'
            }
        }
        # Iter-23 (RD-branch-4): record this failure but continue —
        # a single failing query does not mean the whole lookup
        # failed, but if ALL queries fail we downgrade Status
        # below.
        $searchFailures += [PSCustomObject]@{
            Query = $qItem.Query
            Kind  = 'GhExit'
            Raw   = $result.Raw
        }
        continue
    }
    try {
        $parsed = $result.Raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        # Iter-23 (RD-branch-4): JSON parse failure is a real
        # failure — do not silently discard. Track it so the
        # caller can distinguish "no related issue" from
        # "GitHub returned malformed output".
        $searchFailures += [PSCustomObject]@{
            Query = $qItem.Query
            Kind  = 'JsonParse'
            Raw   = $result.Raw
        }
        continue
    }
    foreach ($item in @($parsed)) {
        if ($null -eq $item) { continue }
        if (-not $aggregate.ContainsKey($item.number)) {
            $aggregate[$item.number] = $item
        }
    }
}

# ---------------------------------------------------------------------------
# Classify each aggregated result
#
# Rule (tightened): "Similar" requires an EXCEPTION-CONTENT match --- either
# the top-level phrase or the inner-exception phrase must appear in the
# normalized issue title+body. A match on the discriminator function name
# alone is NOT sufficient: the same enclosing function can fail for
# unrelated reasons (different call sites, different cmdlets, different
# exception classes), and callers noticed that function-only matches
# flooded the "Similar" list with noise. When the function name ALSO
# matches on top of an exception-content match, it is recorded as
# additional context on the Reason field, not as a standalone trigger.
# Results that only match on the function name are counted in
# DiscardedFunctionOnly so the caller can see how much was filtered out.
# ---------------------------------------------------------------------------
$duplicates = @()
$similar = @()
$discardedFunctionOnly = 0

foreach ($num in ($aggregate.Keys | Sort-Object)) {
    $item = $aggregate[$num]
    $normBody = ConvertTo-NormalizedPhrase -Text (($item.title + "`n" + $item.body))
    $matchTop = $topPhrase -and $normBody.IndexOf($topPhrase, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    $matchInner = $innerPhrase -and $normBody.IndexOf($innerPhrase, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    $matchFn = $DiscriminatorFunction -and $normBody.IndexOf($DiscriminatorFunction, [System.StringComparison]::OrdinalIgnoreCase) -ge 0

    if ($matchTop -and $matchInner) {
        $reasonParts = @('top-level exception phrase', 'inner exception phrase')
        if ($matchFn) { $reasonParts += "$DiscriminatorFunction (additional context)" }
        $duplicates += [PSCustomObject]@{
            Number = [int]$item.number
            State  = [string]$item.state
            Title  = [string]$item.title
            Url    = [string]$item.url
            Reason = ($reasonParts -join ' + ')
        }
    } elseif ($matchTop -or $matchInner) {
        $reasonParts = @()
        if ($matchTop) { $reasonParts += 'top-level exception phrase' }
        if ($matchInner) { $reasonParts += 'inner exception phrase' }
        if ($matchFn) { $reasonParts += "$DiscriminatorFunction (additional context)" }
        $similar += [PSCustomObject]@{
            Number = [int]$item.number
            State  = [string]$item.state
            Title  = [string]$item.title
            Url    = [string]$item.url
            Reason = ($reasonParts -join ' + ')
        }
    } elseif ($matchFn) {
        # Function name only --- same function can fail for unrelated
        # reasons. Filtered out.
        $discardedFunctionOnly++
    }
    # Items that matched no criterion are dropped silently (noise from
    # the broad `<scriptStem> <token>` query).
}

# Iter-23 (RD-branch-4): decide final Status based on query
# outcomes. All queries failing = Error; some failing but at
# least one succeeded = PartialLookup (retains any results
# collected); no failures = Ok.
$queryCount = $queries.Count
$failureCount = $searchFailures.Count
if ($queryCount -gt 0 -and $failureCount -eq $queryCount) {
    # Every query failed. Cannot claim "no related issues" —
    # this is an error path the caller must surface.
    $finalStatus = 'Error'
    $finalDetail = "All $queryCount search queries failed (kinds: $(($searchFailures | ForEach-Object { $_.Kind } | Sort-Object -Unique) -join ', '))."
} elseif ($failureCount -gt 0) {
    $finalStatus = 'PartialLookup'
    $finalDetail = "$failureCount of $queryCount queries failed (kinds: $(($searchFailures | ForEach-Object { $_.Kind } | Sort-Object -Unique) -join ', ')). Results below may be incomplete."
} else {
    $finalStatus = 'Ok'
    $finalDetail = ''
}

return [PSCustomObject]@{
    Duplicates            = $duplicates
    Similar               = $similar
    QueriesRun            = $queriesRun
    TotalResultsExamined  = $aggregate.Count
    DiscardedFunctionOnly = $discardedFunctionOnly
    Status                = $finalStatus
    StatusDetail          = $finalDetail
}
