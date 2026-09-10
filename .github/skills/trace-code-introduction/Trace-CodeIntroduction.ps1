# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Identify when a specific range of source code was introduced and
    assess whether the introducing change was intentional or a possible
    regression.

.DESCRIPTION
    Given a repository-relative path, a 1-based inclusive line range, and
    a pinned commit SHA that represents the current form of the range,
    this helper walks the range's history with `git log -L` to find the
    most-recent commit that touched it and (optionally) the merged Pull
    Request that introduced that commit.

    A conservative heuristic then classifies the change as:

      Intentional         -- the introducing commit adds a new guard,
                             defensive check, or feature branch to the
                             range and the diff does not remove any
                             equivalent guard.
      LikelyOversight     -- the diff is small and touches conditional
                             logic (`if`, `-and`, `-or`, `-ne`, `-eq`,
                             `IsNull`) in a way that a reviewer might
                             plausibly have missed an edge case, but
                             there is no evidence the previous form
                             handled the case that now fails.
      PossibleRegression  -- the BEFORE form contained a guard, check,
                             or exit path that the AFTER form removes or
                             narrows. This is the only verdict that
                             merits opening a "regression?" question with
                             the PR author.
      Indeterminate       -- range history is unavailable, or the diff
                             is dominated by refactors and cannot be
                             classified confidently.

    The verdict is a HEURISTIC. The final call belongs to a human
    reviewer.

.PARAMETER Path
    File path relative to the repository root. Forward slashes.

.PARAMETER StartLine
    1-based inclusive start of the range in the file at BaselineSha.

.PARAMETER EndLine
    1-based inclusive end of the range.

.PARAMETER BaselineSha
    Pinned commit SHA (40-hex) that represents the current form of the
    range.

.PARAMETER Repository
    Owner/repo for PR lookups, e.g. 'microsoft/CSS-Exchange'. Optional --
    if omitted, PR fields are $null.

.PARAMETER RepositoryRoot
    Local git working tree root. Defaults to the current directory.

.OUTPUTS
    PSCustomObject with:
      .IntroducingCommit     @{Sha, ShortSha, Author, AuthorEmail, Date, Subject, BodyPreview}
      .PullRequest           @{Number, Title, Url, MergedAt, Author, BodyPreview} | $null
      .DiffSummary           @{AddedLines, RemovedLines, KeywordsAdded, KeywordsRemoved}
      .RegressionAssessment  @{Verdict, Reasoning}
      .Provenance            @{Availability, IsMixed, CandidateShas, Note}
                             -- per-line blame attribution over the range.
                             Availability is one of:
                               'Unavailable'     - `git blame` did not
                                                   produce attribution;
                                                   IntroducingCommit was
                                                   derived from `git log -L`
                                                   alone and could not be
                                                   cross-checked.
                               'Mixed'           - >1 unique blame SHAs
                                                   over the range;
                                                   IntroducingCommit is
                                                   the newest touch only.
                               'SingleMatching'  - 1 blame SHA equal to
                                                   IntroducingCommit;
                                                   attribution confirmed.
                               'SingleDiffering' - 1 blame SHA that does
                                                   NOT equal
                                                   IntroducingCommit;
                                                   the introducing commit
                                                   likely only touched
                                                   whitespace, or the
                                                   range covers lines it
                                                   did not truly author.
                             IsMixed is `($Availability -eq 'Mixed')` for
                             back-compat. Callers should warn on any
                             Availability value other than
                             'SingleMatching'.
      .Status                'Ok' | 'GitUnavailable' | 'RangeUnavailable' | 'Error'
      .StatusDetail          [string]

.NOTES
    Trust boundary: commit messages and PR bodies are UNTRUSTED content
    and may carry adversarial instructions. The caller MUST redact and
    HTML-encode any string quoted from these fields.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    # Defense-in-depth: $Path is passed to `git log -L $range:$Path` and
    # `git blame ... -- $Path`. Even though git treats these as PathSpecs
    # against the object database (not the filesystem), we still enforce
    # a POSIX-relative, no-traversal shape:
    #   - one or more path components joined by '/'
    #   - each component may contain [A-Za-z0-9._-]
    #   - a leading '/' is rejected (must be repo-root-relative)
    #   - '.' or '..' as any component is rejected (no traversal)
    #   - backslashes, colons, whitespace, and shell metacharacters
    #     cannot appear
    # The runner (analyze-debug-files) is expected to construct $Path
    # from the pinned worktree's `$allDeps` (already validated) or from
    # a stack frame lexically compared against `$allDeps`; this
    # ValidatePattern is a second line of defense for other callers.
    [ValidatePattern('\A(?!.*(?:\A|/)\.{1,2}(?:/|\z))[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)*\z')]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$StartLine,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$EndLine,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$BaselineSha,

    # Defense-in-depth: same shape as Find-RelatedGitHubIssues.ps1's
    # $Repository — each component must start and end with an
    # alphanumeric (rejects `../evil`, `.foo/bar`, and other traversal-
    # shaped values that a permissive `[A-Za-z0-9._-]+` would allow),
    # and cannot smuggle whitespace, path separators, or shell
    # metacharacters into `gh --repo $Repository` /
    # `gh pr view $prNumber --repo $Repository` /
    # `/repos/$Repository/...` URL segments. Optional here; when
    # omitted, PR lookup is skipped.
    [ValidatePattern('\A[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?/[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?\z')]
    [string]$Repository,

    [string]$RepositoryRoot = (Get-Location).Path
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
# Iter-23 (RD-branch-8): explicitly disable native-command
# error promotion inside this script's scope. If the caller
# enabled $PSNativeCommandUseErrorActionPreference, a nonzero
# `git` or `gh` exit would throw NativeCommandExitException
# BEFORE our `$LASTEXITCODE` handling ran — breaking the
# structured `Status = 'GitUnavailable' / 'Error' /
# 'RangeUnavailable'` result contract this script advertises.
$PSNativeCommandUseErrorActionPreference = $false

if ($EndLine -lt $StartLine) { throw "EndLine ($EndLine) < StartLine ($StartLine)." }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
$git = Get-Command git -ErrorAction SilentlyContinue
if ($null -eq $git) {
    return [PSCustomObject]@{
        IntroducingCommit    = $null
        PullRequest          = $null
        DiffSummary          = $null
        RegressionAssessment = $null
        Provenance           = $null
        Status               = 'GitUnavailable'
        StatusDetail         = 'git not found on PATH.'
    }
}

Push-Location -LiteralPath $RepositoryRoot -ErrorAction Stop
try {
    # Verify commit exists locally.
    & git --no-pager cat-file -e "$BaselineSha^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        return [PSCustomObject]@{
            IntroducingCommit    = $null
            PullRequest          = $null
            DiffSummary          = $null
            RegressionAssessment = $null
            Provenance           = $null
            Status               = 'Error'
            StatusDetail         = "Commit $BaselineSha is not present locally."
        }
    }

    # Two-phase approach — no sentinel parsing of a stream that mixes
    # untrusted commit bodies with our own delimiters.
    #
    # Phase 1: list commit SHAs that touched the range, most recent first.
    # `-s` suppresses the diff so the output is exactly one SHA per line
    # (%H cannot contain a newline).
    $range = "$StartLine,$EndLine"
    $shaListArgs = @('--no-pager', 'log', '--format=%H', "-L$range`:$Path", '-s', $BaselineSha)
    $shaListOut = & git @shaListArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        return [PSCustomObject]@{
            IntroducingCommit    = $null
            PullRequest          = $null
            DiffSummary          = $null
            RegressionAssessment = $null
            Provenance           = $null
            Status               = 'RangeUnavailable'
            StatusDetail         = ($shaListOut -join "`n")
        }
    }
    $shas = @($shaListOut | Where-Object { $_ -is [string] -and $_ -match '\A[0-9a-fA-F]{40}\z' })
    if ($shas.Count -eq 0) {
        return [PSCustomObject]@{
            IntroducingCommit    = $null
            PullRequest          = $null
            DiffSummary          = $null
            RegressionAssessment = [PSCustomObject]@{ Verdict = 'Indeterminate'; Reasoning = 'git log -L returned no history for the range.' }
            Provenance           = $null
            Status               = 'Ok'
            StatusDetail         = ''
        }
    }

    # Phase 1.5: per-line provenance via `git blame`. This distinguishes
    # "the newest commit to touch the range" (Phase 1) from "the commit
    # that actually produced the failing lines". `-w` ignores
    # whitespace-only changes so a formatting/reformat commit cannot
    # hijack the range.
    #
    # Track blame availability separately from the SHA count. A failed
    # `git blame` invocation must NOT be reported as "single-commit
    # provenance" — a caller reading `IsMixed=$false` would otherwise
    # trust the introducing commit even when no attribution was
    # possible.
    $blameArgs = @('--no-pager', 'blame', '-w', '--line-porcelain', "-L$range", $BaselineSha, '--', $Path)
    $blameOut = & git @blameArgs 2>&1
    $blameOk = ($LASTEXITCODE -eq 0)
    $blameShas = @()
    if ($blameOk) {
        # Porcelain first line of each entry is `<sha> <origLine> <finalLine> [<groupSize>]`.
        foreach ($ln in $blameOut) {
            if ($ln -is [string] -and $ln -match '\A([0-9a-fA-F]{40})\s+\d+\s+\d+') {
                $blameShas += $Matches[1].ToLowerInvariant()
            }
        }
    }
    $blameShas = @($blameShas | Sort-Object -Unique)

    # Phase 2: fetch each metadata field of the newest commit through
    # separate `git show -s --format=%X` calls. All the atomic fields
    # (%H, %h, %an, %ae, %aI, %s) are guaranteed single-line by git —
    # ident lines cannot contain LF, and %s is git's one-line subject.
    # This eliminates any parsing ambiguity between our delimiters and
    # untrusted commit content.
    #
    # Each call is validated: `$LASTEXITCODE` must be 0 AND the result
    # must be non-null. A silent failure (object disappearance mid-run,
    # repository corruption, or interrupted git) that produces empty
    # output would otherwise cause `.Trim()` on `$null` to throw and
    # crash the caller with a generic error instead of a structured
    # 'Error' status.
    $sha = $shas[0]
    $getField = {
        param([string]$Fmt)
        $out = & git --no-pager show -s "--format=$Fmt" $sha 2>&1
        return @{
            Ok    = ($LASTEXITCODE -eq 0)
            Value = if ($out -is [array]) { $out } else { @($out) }
            Raw   = ($out -join "`n")
        }
    }
    $fieldFailures = @()
    $shortShaRes = & $getField '%h'
    $authorRes   = & $getField '%an'
    $emailRes    = & $getField '%ae'
    $dateRes     = & $getField '%aI'
    $subjectRes  = & $getField '%s'
    $bodyRes     = & $getField '%b'
    foreach ($pair in @(
            @{ Name = '%h'; Res = $shortShaRes },
            @{ Name = '%an'; Res = $authorRes },
            @{ Name = '%ae'; Res = $emailRes },
            @{ Name = '%aI'; Res = $dateRes },
            @{ Name = '%s'; Res = $subjectRes },
            @{ Name = '%b'; Res = $bodyRes })) {
        if (-not $pair.Res.Ok) { $fieldFailures += "$($pair.Name): $($pair.Res.Raw)" }
    }
    if ($fieldFailures.Count -gt 0) {
        return [PSCustomObject]@{
            IntroducingCommit    = $null
            PullRequest          = $null
            DiffSummary          = $null
            RegressionAssessment = $null
            Provenance           = $null
            Status               = 'Error'
            StatusDetail         = "git show failed for commit $sha field(s): $($fieldFailures -join '; ')"
        }
    }
    $shortSha = ($shortShaRes.Raw).Trim()
    $author   = ($authorRes.Raw).Trim()
    $email    = ($emailRes.Raw).Trim()
    $date     = ($dateRes.Raw).Trim()
    $subject  = ($subjectRes.Raw).Trim()
    # Body may be multi-line; do NOT collapse newlines and do NOT trim
    # interior whitespace — only trim the outer.
    $body = ($bodyRes.Value -join "`n").Trim()
    $bodyPreview = if ($body.Length -gt 800) { $body.Substring(0, 800) + '...' } else { $body }

    # Phase 3: diff for just the newest commit at the pinned range.
    # Suppress the header with an empty --format; keep the patch.
    # Iter-23 (RD-branch-3): root at $BaselineSha (not $sha). The
    # line-range `$range` is expressed in $BaselineSha's file
    # coordinates; walking from $sha (an older commit) reinterprets
    # those numbers against $sha's file layout, which can either
    # error or produce a diff for the wrong lines. `-1 $BaselineSha`
    # limits the traversal to the SINGLE newest commit that touched
    # the range from $BaselineSha's history — which is $sha itself
    # (identical to Phase 1's `$shas[0]`).
    $diffArgs = @('--no-pager', 'log', '--format=', "-L$range`:$Path", '-1', $BaselineSha)
    $diffOut = & git @diffArgs 2>&1
    # Iter-23 (RD-branch-3): a diff-command FAILURE must not be
    # silently swallowed. If Phase 1 confirmed $sha touched the
    # range but Phase 3 could not produce the diff, we cannot
    # reliably classify the change — return `Indeterminate` with
    # the failure detail instead of an empty-diff `LikelyOversight`
    # verdict.
    if ($LASTEXITCODE -ne 0) {
        return [PSCustomObject]@{
            IntroducingCommit    = [PSCustomObject]@{
                Sha         = $sha
                ShortSha    = $shortSha
                Author      = $author
                AuthorEmail = $email
                Date        = $date
                Subject     = $subject
                BodyPreview = $bodyPreview
            }
            PullRequest          = $null
            DiffSummary          = $null
            RegressionAssessment = [PSCustomObject]@{
                Verdict   = 'Indeterminate'
                Reasoning = "Phase 3 diff extraction failed: $(($diffOut | Select-Object -First 2) -join ' | ')"
            }
            Provenance           = $null
            Status               = 'Ok'
            StatusDetail         = ''
        }
    }

    # Parse the diff hunk to build DiffSummary.
    $addedLines = @()
    $removedLines = @()
    foreach ($ln in $diffOut) {
        if ($ln -match '^\+[^+]' -or ($ln -match '^\+$')) {
            $addedLines += $ln.Substring(1)
        } elseif ($ln -match '^-[^-]' -or ($ln -match '^-$')) {
            $removedLines += $ln.Substring(1)
        }
    }

    # Guard-keyword extraction. Strip PS comments and quoted string
    # literals first, so guard tokens embedded in narrative text don't
    # count. Use PowerShell's own tokenizer so backtick-escaped quotes
    # inside expandable strings (`"), doubled single-quotes ('' inside
    # a literal string), here-strings, and `# comments beginning at any
    # unquoted position are all handled the same way the runtime does
    # — a hand-rolled regex cannot cover these cases correctly.
    $guardPattern = '-eq|-ne|-and|-or|-not\b|\bif\b|\belseif\b|\bIsNullOr(?:Empty|WhiteSpace)\b|\bTest-Path\b|\bthrow\b|\bcontinue\b|\breturn\b'
    $stripCommentsAndStrings = {
        param([string]$line)
        if ([string]::IsNullOrEmpty($line)) { return '' }
        $tokens = $null
        $errors = $null
        try {
            [void][System.Management.Automation.Language.Parser]::ParseInput(
                $line, [ref]$tokens, [ref]$errors)
        } catch {
            # Parser threw on a malformed fragment; fall back to a very
            # conservative regex strip so the caller still gets a
            # best-effort answer instead of a crash. This path is only
            # reached on genuinely broken input (adversarial or
            # partially-truncated diff hunks).
            $t = [regex]::Replace($line, '"[^"]*"', '""')
            $t = [regex]::Replace($t, "'[^']*'", "''")
            $t = [regex]::Replace($t, '#.*$', '')
            return $t
        }
        if ($null -eq $tokens -or $tokens.Count -eq 0) { return '' }
        $sb = [System.Text.StringBuilder]::new()
        foreach ($tok in $tokens) {
            # Exclude comment and every string-flavored token kind
            # (StringLiteral, StringExpandable, HereStringLiteral,
            # HereStringExpandable) plus EndOfInput.
            $k = $tok.Kind.ToString()
            if ($k -eq 'Comment' -or $k -eq 'EndOfInput' -or $k -like 'String*' -or $k -like 'HereString*') {
                continue
            }
            [void]$sb.Append(' ')
            [void]$sb.Append($tok.Text)
        }
        return $sb.ToString()
    }
    $cleanAdded = @($addedLines | ForEach-Object { & $stripCommentsAndStrings $_ })
    $cleanRemoved = @($removedLines | ForEach-Object { & $stripCommentsAndStrings $_ })
    # Wrap the ENTIRE pipeline (including Sort-Object) in @(...) — under
    # Set-StrictMode -Version 3.0, Sort-Object returning $null for an empty
    # input throws when .Count is accessed later.
    $keywordsAdded = @(@([regex]::Matches(($cleanAdded -join "`n"), $guardPattern, 'IgnoreCase') | ForEach-Object { $_.Value.Trim() }) | Sort-Object -Unique)
    $keywordsRemoved = @(@([regex]::Matches(($cleanRemoved -join "`n"), $guardPattern, 'IgnoreCase') | ForEach-Object { $_.Value.Trim() }) | Sort-Object -Unique)

    $diffSummary = [PSCustomObject]@{
        AddedLines      = $addedLines.Count
        RemovedLines    = $removedLines.Count
        KeywordsAdded   = $keywordsAdded
        KeywordsRemoved = $keywordsRemoved
    }

    # ---------------------------------------------------------------------
    # Regression assessment heuristic. Deliberately conservative.
    # ---------------------------------------------------------------------
    $verdict = 'Indeterminate'
    $reasoningParts = @()

    # Keywords present BEFORE but NOT after -> guard removed. Strong signal.
    $keywordsLost = @($keywordsRemoved | Where-Object { $_ -notin $keywordsAdded })
    if ($keywordsLost.Count -gt 0) {
        $verdict = 'PossibleRegression'
        $reasoningParts += "BEFORE form contained conditional keywords not present in AFTER form: $($keywordsLost -join ', ')."
    }

    # Keywords added but not removed -> new guard/feature. Suggests intent.
    $keywordsGained = @($keywordsAdded | Where-Object { $_ -notin $keywordsRemoved })
    if ($keywordsGained.Count -gt 0 -and $verdict -eq 'Indeterminate') {
        $verdict = 'Intentional'
        $reasoningParts += "AFTER form introduces conditional keywords absent from BEFORE: $($keywordsGained -join ', ')."
    }

    # Small diff, conditional keywords stable -> LikelyOversight only if
    # the diff kept the same guards but added new call sites that could
    # break them.
    # Iter-23 (RD-branch-11): tighten the "small additive" heuristic
    # so comment-only, whitespace-only, empty, and other non-code
    # diffs stay `Indeterminate`. Require at least one added line
    # whose PowerShell-stripped form (comments and quoted strings
    # removed) contains a non-whitespace executable token. Without
    # this guard, a copyright-header edit or a `Write-Verbose` string
    # tweak classifies as `LikelyOversight`.
    $addedExecutableTokenPresent = $false
    foreach ($cleanLine in $cleanAdded) {
        if (-not [string]::IsNullOrWhiteSpace($cleanLine)) {
            $addedExecutableTokenPresent = $true
            break
        }
    }
    if ($verdict -eq 'Indeterminate' -and $addedLines.Count -le 8 -and $removedLines.Count -le 2 -and $keywordsAdded.Count -eq 0 -and $addedExecutableTokenPresent) {
        $verdict = 'LikelyOversight'
        $reasoningParts += "Small additive diff ($($addedLines.Count) lines added, $($removedLines.Count) removed) with no new conditional logic; existing guards were not tightened for the added path."
    }

    if ($reasoningParts.Count -eq 0) {
        $reasoningParts += "Diff pattern does not match any known regression signature; leaving verdict as Indeterminate."
    }

    $regression = [PSCustomObject]@{
        Verdict   = $verdict
        Reasoning = ($reasoningParts -join ' ')
    }

    # ---------------------------------------------------------------------
    # PR lookup
    # ---------------------------------------------------------------------
    $pr = $null
    $prNumber = $null

    # PR lookup — ONLY via the /commits/<sha>/pulls API. The commit
    # subject is untrusted content: extracting `#NNN` from it can steer
    # the lookup to an unrelated PR (adversarial), and ordinary
    # subjects often reference the RESOLVED issue rather than the
    # merging PR. Do not parse the subject.
    #
    # We also require that the API-selected PR is in a MERGED state.
    # A closed-unmerged or open PR is not evidence of what shipped.
    if ($Repository -and ($Repository -match '\A[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?/[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?\z')) {
        $gh = Get-Command gh -ErrorAction SilentlyContinue
        if ($gh) {
            $apiPath = "/repos/$Repository/commits/$sha/pulls"
            # Iter-23 (RD-branch-13): pin to github.com so an
            # inherited or hostile GH_HOST cannot redirect the
            # /repos/... commit-pulls lookup to another GitHub-
            # flavored host and potentially attach ambient
            # enterprise credentials.
            $apiOut = & gh api --hostname github.com -H "Accept: application/vnd.github+json" $apiPath 2>&1
            if ($LASTEXITCODE -eq 0) {
                try {
                    $apiParsed = $apiOut | ConvertFrom-Json -ErrorAction Stop
                    $mergedCandidate = @($apiParsed | Where-Object { $_.merged_at })
                    if ($mergedCandidate.Count -gt 0) {
                        # Deterministic: take the earliest merged PR that
                        # contains this commit.
                        $chosen = $mergedCandidate | Sort-Object -Property merged_at | Select-Object -First 1
                        if ($chosen.number -match '\A\d+\z' -or $chosen.number -is [int]) {
                            $prNumber = [int]$chosen.number
                        }
                    }
                } catch {
                    Write-Verbose "PR API lookup ConvertFrom-Json failed (optional data, continuing): $($_.Exception.Message)"
                }
            }
        }
    }

    if ($prNumber -and $Repository) {
        $gh = Get-Command gh -ErrorAction SilentlyContinue
        if ($gh) {
            # Iter-23 (RD-branch-13): prefix `github.com/` on the
            # repo argument so an inherited or hostile GH_HOST
            # cannot redirect this lookup. Matches the release
            # helper's `--repo github.com/<repo>` pattern.
            $qualifiedRepo = "github.com/$Repository"
            $prJson = & gh pr view $prNumber --repo $qualifiedRepo --json 'number,title,url,body,mergedAt,author' 2>&1
            if ($LASTEXITCODE -eq 0) {
                try {
                    $prObj = $prJson | ConvertFrom-Json -ErrorAction Stop
                    # Extra defensive check: PR number returned must
                    # match what we asked for; if not, drop it.
                    if ([int]$prObj.number -ne $prNumber) { throw "PR number mismatch." }
                    $prBody = if ($prObj.body) { [string]$prObj.body } else { '' }
                    $prBodyPreview = if ($prBody.Length -gt 800) { $prBody.Substring(0, 800) + '...' } else { $prBody }
                    $prAuthor = if ($prObj.author -and $prObj.author.PSObject.Properties.Name -contains 'login') { [string]$prObj.author.login } else { '' }
                    $pr = [PSCustomObject]@{
                        Number      = [int]$prObj.number
                        Title       = [string]$prObj.title
                        Url         = [string]$prObj.url
                        MergedAt    = [string]$prObj.mergedAt
                        Author      = $prAuthor
                        BodyPreview = $prBodyPreview
                    }
                } catch {
                    Write-Verbose "gh pr view parse failed (optional data, continuing): $($_.Exception.Message)"
                }
            }
        }
    }

    return [PSCustomObject]@{
        IntroducingCommit    = [PSCustomObject]@{
            Sha         = $sha
            ShortSha    = $shortSha
            Author      = $author
            AuthorEmail = $email
            Date        = $date
            Subject     = $subject
            BodyPreview = $bodyPreview
        }
        PullRequest          = $pr
        DiffSummary          = $diffSummary
        RegressionAssessment = $regression
        Provenance           = & {
            # Resolve the four provenance states from
            # ($blameOk, $blameShas, $sha). The runner treats any value
            # other than 'SingleMatching' as a warning.
            #   Unavailable      - `git blame` failed (no attribution possible)
            #   Mixed            - >1 unique blame SHAs
            #   SingleMatching   - 1 blame SHA == $sha
            #   SingleDiffering  - 1 blame SHA != $sha (whitespace-only
            #                      touch by IntroducingCommit or wrong
            #                      range)
            $blameLower = if ($blameShas.Count -eq 1) { $blameShas[0].ToLowerInvariant() } else { $null }
            $shaLower   = $sha.ToLowerInvariant()
            if (-not $blameOk) {
                $availability = 'Unavailable'
                $note = 'git blame did not produce attribution for the selected range; the IntroducingCommit result was derived from `git log -L` alone and could not be cross-checked.'
            } elseif ($blameShas.Count -gt 1) {
                $availability = 'Mixed'
                $note = "The selected range spans lines produced by $($blameShas.Count) different commits (per `git blame -w`). The 'IntroducingCommit' field is the newest commit that touched the range; other candidates may better explain specific lines. Narrow the range or consult the candidate list before drawing a single conclusion."
            } elseif ($blameShas.Count -eq 1 -and $blameLower -eq $shaLower) {
                $availability = 'SingleMatching'
                $note = 'All lines in the selected range are attributed by `git blame -w` to the same commit reported as IntroducingCommit.'
            } else {
                $availability = 'SingleDiffering'
                $note = "git blame -w attributes every line in the range to $($blameShas[0]), which differs from the IntroducingCommit ($shaLower). The IntroducingCommit likely only touched whitespace, or the range covers lines not truly authored by it."
            }
            [PSCustomObject]@{
                Availability  = $availability
                IsMixed       = ($availability -eq 'Mixed')
                CandidateShas = $blameShas
                Note          = $note
            }
        }
        Status               = 'Ok'
        StatusDetail         = ''
    }
} finally {
    Pop-Location
}
