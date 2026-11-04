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

    Duplicate = the issue's title or body matches BOTH the normalized
                top-level signature AND the normalized inner-exception
                signature. Matching requires every stable excerpt in
                its original order, using case-insensitive substring
                comparisons against normalized issue text. Excerpts
                are bounded by paths, GUIDs, timestamps, randomized
                module names, or caller redaction placeholders. The
                shortened search excerpt is only used for retrieval.
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
      .Status                  'Ok' | 'PartialLookup' | 'GhUnavailable' | 'AuthFailure' | 'RateLimited' | 'NoSearchablePhrase' | 'Error'
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
    # Consume whole quoted paths before unquoted forms stop at whitespace.
    $quotedPathPattern = '["\u201c](?:[A-Za-z]:\\|\\\\)[^"\u201d\r\n]*["\u201d]|[''\u2018](?:[A-Za-z]:\\|\\\\)[^''\u2019\r\n]*[''\u2019]'
    $s = [regex]::Replace($s, $quotedPathPattern, '<path>')
    # Strip Windows absolute paths (already redacted by caller, but path
    # tail can still be volatile per-machine).
    $s = [regex]::Replace($s, '[A-Za-z]:\\[^\s"''\u2018-\u201d]+', '<path>')
    # Strip UNC paths.
    $s = [regex]::Replace($s, '\\\\[^\s"''\u2018-\u201d]+', '<unc>')
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
# Extract stable contiguous spans. GitHub exact searches cannot use
# placeholders as wildcards, nor can they join text from opposite sides of a
# removed token. Caller placeholders (such as <user>) are boundaries too.
# ---------------------------------------------------------------------------
function Get-StableExceptionSpan {
    param([string]$NormalizedText)
    if ([string]::IsNullOrWhiteSpace($NormalizedText)) { return }
    foreach ($span in [regex]::Split($NormalizedText, '(?:tmpEXO_)?<[^<>]*>')) {
        $candidate = [regex]::Replace($span, '\A[\s''"\u2018-\u201d]+|[\s''"\u2018-\u201d]+\z', '')
        if ($candidate -match '[\p{L}\p{N}]') { $candidate }
    }
}

function Test-ExceptionSignature {
    param(
        [string]$Text,
        [string[]]$Spans
    )
    if ($null -eq $Spans -or $Spans.Count -eq 0) { return $false }
    $offset = 0
    foreach ($span in $Spans) {
        $index = $Text.IndexOf($span, $offset, [System.StringComparison]::OrdinalIgnoreCase)
        if ($index -lt 0) { return $false }
        $offset = $index + $span.Length
    }
    return $true
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
    $safeQuery = Get-SafeQueryPhrase -Phrase $Query
    if ([string]::IsNullOrWhiteSpace($safeQuery)) {
        return @{ Exit = 1; Raw = 'empty query after sanitization'; QArg = ''; FailureKind = 'EmptyQuery' }
    }
    # Search's --repo accepts owner/repo, not host-qualified names.
    # Pin its host separately so inherited GH_HOST cannot redirect the query.
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
    # Iter-24 (Copilot review): pass `$qArg` AFTER an explicit `--`
    # end-of-options marker so gh cannot interpret a query that
    # begins with `-` or `--` as an option flag.
    # `Get-SafeQueryPhrase` scrubs internal meta-characters but
    # preserves leading hyphens — non-exact queries built from
    # log-influenced `$DiscriminatorFunction` / `$ScriptName`
    # can otherwise reach `gh search issues` as tokens like
    # `--author evil in:title,body`, which the argument parser
    # rejects as "unknown flag" and fails the entire lookup for
    # the affected query. `--` guarantees the value is treated
    # as the search query positional regardless of leading
    # characters, and is defense in depth against future gh
    # versions where a currently-unknown leading flag becomes
    # recognized.
    $originalGhHost = $env:GH_HOST
    try {
        $env:GH_HOST = 'github.com'
        $out = & gh search issues --include-prs --repo $Repository --limit $Limit --json 'number,state,title,url,body' -- $qArg 2>&1
        $exit = $LASTEXITCODE
    } finally {
        $env:GH_HOST = $originalGhHost
    }
    return @{
        Exit        = $exit
        Raw         = ($out -join "`n")
        QArg        = $qArg
        FailureKind = if ($exit -eq 0) { $null } else { 'GhExit' }
    }
}

# A function-only query cannot satisfy the exception-content classifier.
$normTop = ConvertTo-NormalizedPhrase -Text $TopLevelException
$normInner = ConvertTo-NormalizedPhrase -Text $InnerException
$topSpans = @(Get-StableExceptionSpan -NormalizedText $normTop)
$innerSpans = @(Get-StableExceptionSpan -NormalizedText $normInner)
if ($topSpans.Count -eq 0 -and $innerSpans.Count -eq 0) {
    return [PSCustomObject]@{
        Duplicates            = @()
        Similar               = @()
        QueriesRun            = @()
        TotalResultsExamined  = 0
        DiscardedFunctionOnly = 0
        Status                = 'NoSearchablePhrase'
        StatusDetail          = 'No distinctive phrase survived normalization of TopLevelException or InnerException. ScriptName and DiscriminatorFunction cannot classify issues without exception content. GitHub search was not attempted.'
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
# Keep the full spans for classification; shorten only the retrieval query.
$topPhrase = if ($topSpans.Count -gt 0) { Get-DistinctivePhrase -NormalizedText $topSpans[0] } else { $null }
$innerPhrase = if ($innerSpans.Count -gt 0) { Get-DistinctivePhrase -NormalizedText $innerSpans[0] } else { $null }

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
$successfulQueries = 0
$rateLimited = $false

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
            $searchFailures += [PSCustomObject]@{
                Query = $qItem.Query
                Kind  = 'RateLimited'
                Raw   = $result.Raw
            }
            $rateLimited = $true
            break
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
    $successfulQueries++
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
    # Require the full stable signature, not just the broader query excerpt.
    # Keep placeholders so a span cannot bridge removed tokens in issue text.
    $normBody = ConvertTo-NormalizedPhrase -Text ($item.title + "`n" + $item.body)
    $matchTop = Test-ExceptionSignature -Text $normBody -Spans $topSpans
    $matchInner = Test-ExceptionSignature -Text $normBody -Spans $innerSpans
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

# Preserve completed-query evidence when a later request fails or is rate-limited.
$queryCount = $queriesRun.Count
$failureCount = $searchFailures.Count
if ($failureCount -gt 0 -and $successfulQueries -gt 0) {
    $finalStatus = 'PartialLookup'
    $finalDetail = "$failureCount of $queryCount attempted queries failed (kinds: $(($searchFailures | ForEach-Object { $_.Kind } | Sort-Object -Unique) -join ', ')). Results below may be incomplete."
    if ($rateLimited) {
        $finalDetail += ' GitHub search rate limit hit; further queries were not attempted.'
    }
} elseif ($rateLimited) {
    $finalStatus = 'RateLimited'
    $finalDetail = 'GitHub search rate limit hit; no queries completed successfully.'
} elseif ($failureCount -gt 0) {
    # Every query failed. Cannot claim "no related issues" —
    # this is an error path the caller must surface.
    $finalStatus = 'Error'
    $finalDetail = "All $queryCount search queries failed (kinds: $(($searchFailures | ForEach-Object { $_.Kind } | Sort-Object -Unique) -join ', '))."
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
