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
                                                   produce attribution,
                                                   or history is cut off
                                                   by a shallow boundary;
                                                   a populated
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
      .Status                'Ok' | 'PartialLookup' | 'GitUnavailable' | 'RangeUnavailable' | 'Error'
      .StatusDetail          [string]
                             PartialLookup retains local trace evidence
                             when requested PR enrichment fails.

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

. $PSScriptRoot\..\..\skill-lib\Resolve-SkillLocalPath.ps1

$resolvedRepositoryRoot = Resolve-SkillLocalPath -Path $RepositoryRoot
if ($null -eq $resolvedRepositoryRoot) {
    return [PSCustomObject]@{
        IntroducingCommit    = $null
        PullRequest          = $null
        DiffSummary          = $null
        RegressionAssessment = $null
        Provenance           = $null
        Status               = 'Error'
        StatusDetail         = "RepositoryRoot '$RepositoryRoot' failed local-path validation (UNC, network drive, NT device namespace, non-FileSystem PSDrive, SUBST/DefineDosDevice drive, missing directory, or reparse-point-redirected root)."
    }
}

$RepositoryRoot = $resolvedRepositoryRoot

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
        # `git log -L` exited cleanly but produced no matching commit
        # SHA — the range has no attributable history at this baseline
        # (empty output, or output that did not include a %H line).
        # The status contract advertises `RangeUnavailable` for exactly
        # this case; returning `Ok` here would let a caller treat a
        # null `IntroducingCommit` as "successful lookup" and skip the
        # unavailable-lookup fallback the analyze-debug-files runner
        # relies on. See the .Status contract in the header comment.
        return [PSCustomObject]@{
            IntroducingCommit    = $null
            PullRequest          = $null
            DiffSummary          = $null
            RegressionAssessment = [PSCustomObject]@{ Verdict = 'Indeterminate'; Reasoning = 'git log -L returned no history for the range.' }
            Provenance           = $null
            Status               = 'RangeUnavailable'
            StatusDetail         = 'git log -L returned no commit SHAs for the range.'
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
        # Empirically, `git blame --line-porcelain` marks a boundary or
        # root commit by emitting a standalone `boundary` header line
        # AFTER the sha line — the sha line itself is NOT prefixed with
        # `^`. That prefix is only produced by the DEFAULT (non-porcelain)
        # `git blame` output. This regex still accepts an optional `\^?`
        # as a defensive superset: it is a no-op against current git
        # porcelain (matching zero characters), but it protects against
        # future format tweaks or non-git blame implementations that
        # unify the two output shapes. The critical fix is above — track
        # `$blameOk` independently so an empty `$blameShas` list from a
        # valid-but-empty porcelain run does not fall through to a
        # single-SHA branch that indexes `[0]` under strict mode.
        foreach ($ln in $blameOut) {
            if ($ln -is [string] -and $ln -match '\A\^?([0-9a-fA-F]{40})\s+\d+\s+\d+') {
                $blameShas += $Matches[1].ToLowerInvariant()
            }
        }
    }
    $blameShas = @($blameShas | Sort-Object -Unique)

    $historyDetail = ''
    $shallowOut = & git --no-pager rev-parse --is-shallow-repository 2>&1
    $shallowState = ($shallowOut -join "`n").Trim()
    if ($LASTEXITCODE -ne 0 -or ($shallowState -cne 'true' -and $shallowState -cne 'false')) {
        $historyDetail = 'Could not verify whether the local Git history is shallow; introduction attribution is unavailable.'
    } elseif ($shallowState -ceq 'true') {
        $historyCandidates = @((@($shas[0]) + $blameShas) | Sort-Object -Unique)
        $parentOut = & git --no-pager rev-list --parents --no-walk @historyCandidates 2>&1
        $parentRows = @($parentOut | Where-Object {
                $_ -is [string] -and $_ -cmatch '\A[0-9a-f]{40}(?: [0-9a-f]{40})*\z'
            })
        if ($LASTEXITCODE -ne 0 -or $parentRows.Count -ne $historyCandidates.Count) {
            $historyDetail = 'Could not verify visible commit parents in the shallow repository; introduction attribution is unavailable.'
        } else {
            foreach ($candidate in $parentRows) {
                if ($candidate -cnotmatch '\A[0-9a-f]{40}\z') { continue }
                # Shallow roots hide real parents; genuine root commits have none.
                $commitOut = @(& git --no-pager cat-file commit $candidate 2>&1)
                if ($LASTEXITCODE -ne 0 -or $commitOut.Count -eq 0) {
                    $historyDetail = "Could not verify raw parents for apparent root $candidate; introduction attribution is unavailable."
                    break
                }
                foreach ($header in $commitOut) {
                    if ([string]::IsNullOrEmpty([string]$header)) { break }
                    if ($header -cmatch '\Aparent [0-9a-f]{40}\z') {
                        $historyDetail = "The selected history reaches shallow boundary $candidate; introduction attribution is incomplete. Deepen the local history and retry against the same BaselineSha."
                        break
                    }
                }
                if ($historyDetail) { break }
            }
        }
    }
    if ($historyDetail) {
        return [PSCustomObject]@{
            IntroducingCommit    = $null
            PullRequest          = $null
            DiffSummary          = $null
            RegressionAssessment = [PSCustomObject]@{
                Verdict   = 'Indeterminate'
                Reasoning = $historyDetail
            }
            Provenance           = [PSCustomObject]@{
                Availability  = 'Unavailable'
                IsMixed       = $false
                CandidateShas = $blameShas
                Note          = $historyDetail
            }
            Status               = 'RangeUnavailable'
            StatusDetail         = $historyDetail
        }
    }

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
    # `-c diff.noPrefix=false` overrides any user- or repo-level
    # `diff.noPrefix=true` config so headers are always emitted as
    # `--- a/path` and `+++ b/path`. Without this override, git emits
    # `--- path` / `+++ path` for modified files, which the header
    # regex below (anchored on `a/`, `b/`, or `/dev/null`) would fail
    # to recognize — the header line would then be miscounted as an
    # added source line and could cross the classification threshold.
    # (Git configuration variable names are case-insensitive, so this
    # `noPrefix` form matches the same config key that git's own docs
    # spell as a single lowercase token.)
    $diffArgs = @('--no-pager', '-c', 'diff.noPrefix=false', 'log', '--format=', "-L$range`:$Path", '-1', $BaselineSha)
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
            # Iter-25 (Copilot review): downstream SKILL.md (analyze-debug-files)
            # gates the "lookup unavailable" note on `Status -ne 'Ok'`. Returning
            # `Status = 'Ok'` here made a failed Phase 3 render as a successful
            # provenance lookup with a null `DiffSummary` — masking the failure
            # from the report reader. Use `Status = 'Error'` so the sibling skill
            # emits the standard unavailable-lookup note, and preserve the
            # failure context in `StatusDetail`. `IntroducingCommit` stays
            # populated because Phase 1 + Phase 2 succeeded — the commit metadata
            # is genuine even though the diff-derived assessment is not.
            Status               = 'Error'
            StatusDetail         = "Phase 3 diff extraction failed: $(($diffOut | Select-Object -First 2) -join ' | ')"
        }
    }

    # File headers precede the first hunk. Identical prefixes inside a hunk
    # are source text, including here-string lines resembling file headers.
    $addedLines = @()
    $removedLines = @()
    $addedLineNumbers = [System.Collections.Generic.HashSet[int]]::new()
    $removedLineNumbers = [System.Collections.Generic.HashSet[int]]::new()
    $beforePath = $null
    $afterPath = $null
    $beforeMissing = $false
    $afterMissing = $false
    $oldLine = 0
    $newLine = 0
    $inHunk = $false
    foreach ($ln in $diffOut) {
        $s = if ($null -eq $ln) { '' } else { [string]$ln }
        if ($s -match '^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@') {
            $oldLine = [int]$Matches[1]
            $newLine = [int]$Matches[2]
            $inHunk = $true
            continue
        }
        if (-not $inHunk) {
            if ($s -match '^--- (a/|/dev/null)') {
                $beforeMissing = ($s -eq '--- /dev/null')
                $beforePath = if ($beforeMissing) { $Path } else { $s.Substring(6) }
            } elseif ($s -match '^\+\+\+ (b/|/dev/null)') {
                $afterMissing = ($s -eq '+++ /dev/null')
                $afterPath = if ($afterMissing) { $Path } else { $s.Substring(6) }
            }
            continue
        }
        if ($s.StartsWith('+')) {
            $addedLines += $s.Substring(1)
            [void]$addedLineNumbers.Add($newLine++)
        } elseif ($s.StartsWith('-')) {
            $removedLines += $s.Substring(1)
            [void]$removedLineNumbers.Add($oldLine++)
        } elseif ($s.StartsWith(' ')) {
            $oldLine++
            $newLine++
        }
    }

    # Tokenize complete historical files, then select changed-line tokens.
    # A diff fragment alone cannot identify multiline comments or strings.
    $getChangeEvidence = {
        param(
            [string]$Revision,
            [AllowNull()][string]$SourcePath,
            [bool]$Missing,
            [System.Collections.Generic.HashSet[int]]$ChangedLines
        )
        $unavailable = [PSCustomObject]@{
            Available = $false
            Signature = ''
            Keywords  = @()
            HasCode   = $false
        }
        if ($SourcePath -notmatch '\A(?!.*(?:\A|/)\.{1,2}(?:/|\z))[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)*\z') {
            return $unavailable
        }
        $sourceText = ''
        if (-not $Missing) {
            $sourceOut = & git --no-pager show "${Revision}:$SourcePath" 2>&1
            if ($LASTEXITCODE -ne 0) { return $unavailable }
            $sourceText = $sourceOut -join "`n"
            if ($sourceText.StartsWith([string][char]0xFEFF, [System.StringComparison]::Ordinal)) {
                $sourceText = $sourceText.Substring(1)
            }
        }
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput(
            $sourceText, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { return $unavailable }
        $codeParts = [System.Collections.Generic.List[string]]::new()
        $keywords = [System.Collections.Generic.List[string]]::new()
        $pendingTokens = [System.Collections.Generic.Stack[System.Management.Automation.Language.Token]]::new()
        for ($i = $tokens.Count - 1; $i -ge 0; $i--) {
            $pendingTokens.Push($tokens[$i])
        }
        while ($pendingTokens.Count -gt 0) {
            $token = $pendingTokens.Pop()
            # String prose is excluded, but its nested expressions execute.
            if ($token -is [System.Management.Automation.Language.StringExpandableToken] -and
                $null -ne $token.NestedTokens) {
                for ($i = $token.NestedTokens.Count - 1; $i -ge 0; $i--) {
                    $pendingTokens.Push($token.NestedTokens[$i])
                }
            }
            $kind = $token.Kind.ToString()
            $isCommand = ($token.TokenFlags -band [System.Management.Automation.Language.TokenFlags]::CommandName) -ne 0
            if ($kind -in @('Comment', 'EndOfInput', 'NewLine', 'LineContinuation') -or
                (($kind -like 'String*' -or $kind -like 'HereString*' -or $kind -eq 'Generic') -and -not $isCommand)) {
                continue
            }
            $changed = $false
            for ($line = $token.Extent.StartLineNumber; $line -le $token.Extent.EndLineNumber; $line++) {
                if ($ChangedLines.Contains($line)) {
                    $changed = $true
                    break
                }
            }
            if (-not $changed) { continue }
            $codeParts.Add("$kind`:$($token.Text.ToLowerInvariant())")
            switch ($kind) {
                { $_ -in @('Ieq', 'Ceq') } { $keywords.Add('-eq') }
                { $_ -in @('Ine', 'Cne') } { $keywords.Add('-ne') }
                'And' { $keywords.Add('-and') }
                'Or' { $keywords.Add('-or') }
                'Not' { $keywords.Add('-not') }
                { $_ -in @('If', 'ElseIf', 'Throw', 'Continue', 'Return') } { $keywords.Add($kind.ToLowerInvariant()) }
            }
            if ($isCommand -and ($token.Text -split '\\')[-1] -eq 'Test-Path') {
                $keywords.Add('Test-Path')
            }
            if (($token.TokenFlags -band [System.Management.Automation.Language.TokenFlags]::MemberName) -ne 0 -and
                $token.Text -in @('IsNullOrEmpty', 'IsNullOrWhiteSpace')) {
                $keywords.Add($token.Text)
            }
        }
        return [PSCustomObject]@{
            Available = $true
            Signature = $codeParts -join "`n"
            Keywords  = @($keywords | Sort-Object -Unique)
            HasCode   = $codeParts.Count -gt 0
        }
    }
    $beforeEvidence = & $getChangeEvidence -Revision "$sha^" -SourcePath $beforePath -Missing $beforeMissing -ChangedLines $removedLineNumbers
    $afterEvidence = & $getChangeEvidence -Revision $sha -SourcePath $afterPath -Missing $afterMissing -ChangedLines $addedLineNumbers
    $keywordsAdded = @($afterEvidence.Keywords)
    $keywordsRemoved = @($beforeEvidence.Keywords)
    $contextAvailable = ($beforeEvidence.Available -and $afterEvidence.Available)
    $executableChange = ($contextAvailable -and $beforeEvidence.Signature -cne $afterEvidence.Signature)

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
    if (-not $contextAvailable) {
        $reasoningParts += 'Complete historical source could not be read and parsed; lexical context is unavailable.'
    } elseif (-not $executableChange) {
        $reasoningParts += 'Changed lines contain no differing executable tokens after comments, literal string text, and formatting are excluded.'
    }

    # Keywords present BEFORE but NOT after -> guard removed. Strong signal.
    $keywordsLost = @($keywordsRemoved | Where-Object { $_ -notin $keywordsAdded })
    if ($executableChange -and $keywordsLost.Count -gt 0) {
        $verdict = 'PossibleRegression'
        $reasoningParts += "BEFORE form contained conditional keywords not present in AFTER form: $($keywordsLost -join ', ')."
    }

    # Keywords added but not removed -> new guard/feature. Suggests intent.
    $keywordsGained = @($keywordsAdded | Where-Object { $_ -notin $keywordsRemoved })
    if ($executableChange -and $keywordsGained.Count -gt 0 -and $verdict -eq 'Indeterminate') {
        $verdict = 'Intentional'
        $reasoningParts += "AFTER form introduces conditional keywords absent from BEFORE: $($keywordsGained -join ', ')."
    }

    # Small diff, conditional keywords stable -> LikelyOversight only if
    # the diff kept the same guards but added new call sites that could
    # break them.
    # Iter-23 (RD-branch-11): tighten the "small additive" heuristic
    # so comment-only, whitespace-only, empty, and other non-code
    # diffs stay `Indeterminate`. Require at least one added line
    # whose tokens (comments and literal string text excluded)
    # contain a non-whitespace executable token. Without
    # this guard, a copyright-header edit or a `Write-Verbose` string
    # tweak classifies as `LikelyOversight`.
    if ($executableChange -and $verdict -eq 'Indeterminate' -and $addedLines.Count -le 8 -and $removedLines.Count -le 2 -and $keywordsAdded.Count -eq 0 -and $afterEvidence.HasCode) {
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
    $prLookupDetail = ''

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
                    # Join before parse: `gh api` can emit pretty-printed
                    # JSON across multiple native-command output lines.
                    # PowerShell captures native output as string[] with
                    # one entry per line, and `ConvertFrom-Json` parses
                    # each pipeline input independently in Windows
                    # PowerShell 5.1 — a multi-line array then fails on
                    # the first `[`. Join to a single JSON document
                    # before deserializing; failures are reported without
                    # losing the local trace evidence.
                    $apiJoined = if ($apiOut -is [array]) { $apiOut -join [System.Environment]::NewLine } else { [string]$apiOut }
                    $apiParsed = $apiJoined | ConvertFrom-Json -ErrorAction Stop
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
                    $prLookupDetail = "gh api PR lookup output could not be parsed: $($_.Exception.Message)"
                }
            } else {
                $prLookupDetail = "gh api PR lookup failed (exit $LASTEXITCODE): $($apiOut -join ' | ')"
            }
        } else {
            $prLookupDetail = 'gh CLI not found on PATH; PR lookup was not attempted.'
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
                    # Join before parse — same rationale as the /pulls
                    # API call above: `gh pr view --json` can emit
                    # multi-line pretty-printed JSON, and piping an
                    # array of lines directly to `ConvertFrom-Json`
                    # can fail per-line in Windows PowerShell 5.1,
                    # preventing PR metadata enrichment.
                    $prJoined = if ($prJson -is [array]) { $prJson -join [System.Environment]::NewLine } else { [string]$prJson }
                    $prObj = $prJoined | ConvertFrom-Json -ErrorAction Stop
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
                    $prLookupDetail = "gh pr view output could not be parsed: $($_.Exception.Message)"
                }
            } else {
                $prLookupDetail = "gh pr view failed (exit $LASTEXITCODE): $($prJson -join ' | ')"
            }
        } else {
            $prLookupDetail = 'gh CLI not found on PATH; PR details could not be retrieved.'
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
            # Resolve the five provenance states from
            # ($blameOk, $blameShas, $sha). The runner treats any value
            # other than 'SingleMatching' as a warning.
            #   Unavailable      - `git blame` failed OR succeeded with
            #                      zero parseable attributions (defensive
            #                      fallback: even after accepting the
            #                      `^<sha>` boundary marker, an
            #                      unrecognized porcelain shape must not
            #                      throw under Set-StrictMode -Version 3.0
            #                      when the SingleDiffering branch below
            #                      would index `$blameShas[0]`).
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
            } elseif ($blameShas.Count -eq 0) {
                $availability = 'Unavailable'
                $note = 'git blame ran but produced no parseable per-line attributions for the selected range; the IntroducingCommit result was derived from `git log -L` alone and could not be cross-checked.'
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
        Status               = if ($prLookupDetail) { 'PartialLookup' } else { 'Ok' }
        StatusDetail         = $prLookupDetail
    }
} finally {
    Pop-Location
}
