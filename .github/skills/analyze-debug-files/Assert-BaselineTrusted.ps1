# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Validate that a release-tag baseline is trustworthy enough to execute code
    from, and throw if it is not.

.DESCRIPTION
    `Get-BaselineDependencyGraph.ps1` runs `.build/Build.ps1` *from the baseline
    commit*. That makes the baseline a code-execution input, so it must never be
    acted on unverified. This helper enforces eight gates, in order, and throws
    on the first failure:

      0. `RepositoryRoot` is a real local directory (not UNC, DOS-device,
         SUBST-aliased, or reparse-redirected). Gates 5-7 read repository state
         through `git -C`, so a redirected root would vet the wrong repository.
      1. `Status` is a matched result (not a miss, not a degraded lookup).
      2. `ConfirmedTag` is present.
      3. `ConfirmedCommitSha` is a real 40-hex value.
      4. `Repository` is on the allowlist (`microsoft/CSS-Exchange`).
      5. The LOCAL clone's origin URL also points at that repository -- a
         mismatch means the caller is running from a clone that was never vetted.
      6. The commit object exists locally, so materialization cannot silently
         resolve to something else.
      7. The tag resolves locally to EXACTLY the claimed commit. Without this,
         a tampered baseline result could pair a legitimate tag string with an
         unrelated commit. `^{commit}` peels through annotated tags; a
         lightweight tag pointing straight at the commit resolves the same way,
         so only a genuine disagreement is rejected.

    Every failure is a hard refusal. There is deliberately no "soft" status
    return and no fallback to HEAD, to the tag ref alone, or to an unpinned
    commit -- a caller that could ignore a status would defeat the gate.

    NOTE: `Get-BaselineDependencyGraph.ps1` independently re-verifies gate 7
    before it executes anything. That duplication is intentional: this script is
    the documented gate, but nothing proves to the graph helper that it ran.

.PARAMETER Baseline
    The result object from
    `find-release-tag-for-script-version/Find-ReleaseTagForScriptVersion.ps1`.
    Must expose Status, ConfirmedTag, ConfirmedCommitSha, and Repository.

.PARAMETER RepositoryRoot
    Local git working tree to validate against. Defaults to the current
    directory. Validated as a real local directory BEFORE it is handed to
    `git -C`: a UNC, DOS-device, SUBST-aliased, or reparse-point-backed value
    would otherwise make the origin/commit/tag checks below speak for a
    repository other than the one the operator believes they are vetting.

.OUTPUTS
    None. Throws on any gate failure; returns nothing on success.

.EXAMPLE
    $baseline = & .\.github\skills\find-release-tag-for-script-version\Find-ReleaseTagForScriptVersion.ps1 -ScriptName HealthChecker -Version 26.10.02.1907
    & .\.github\skills\analyze-debug-files\Assert-BaselineTrusted.ps1 -Baseline $baseline
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNull()]
    [PSObject]$Baseline,

    [ValidateNotNullOrEmpty()]
    [string]$RepositoryRoot = (Get-Location).Path
)

. $PSScriptRoot\..\..\skill-lib\Resolve-SkillLocalPath.ps1

$allowedRepository = 'microsoft/CSS-Exchange'
$originPattern = '(?i)\A(?:https://github\.com/microsoft/CSS-Exchange(?:\.git)?/?|' +
'git@github\.com:microsoft/CSS-Exchange(?:\.git)?/?|' +
'ssh://git@github\.com/microsoft/CSS-Exchange(?:\.git)?/?)\z'

# 0. The working tree we are about to interrogate must itself be a real local
#    directory. Every gate from 5 onward reads repository state through
#    `git -C $RepositoryRoot`; if that path is UNC, SUBST-aliased, or
#    reparse-redirected, those gates vet a repository the operator never chose.
$resolvedRepositoryRoot = Resolve-SkillLocalPath -Path $RepositoryRoot
if ($null -eq $resolvedRepositoryRoot) {
    throw ("Assert-BaselineTrusted refuses to validate against repository root '$RepositoryRoot' — " +
        "it failed local-path validation. The path is UNC, on a non-local drive, on a " +
        "SUBST/DefineDosDevice alias, or has a junction/symlink ancestor.")
}
$RepositoryRoot = $resolvedRepositoryRoot

# 1. Status must be a matched result (not none / not degraded).
if ($Baseline.Status -notin @('match-earliest', 'match-possibly-not-earliest')) {
    throw "Baseline lookup did not return a matched release (Status '$($Baseline.Status)'); refusing to proceed."
}

# 2. Tag must be present.
if ([string]::IsNullOrWhiteSpace($Baseline.ConfirmedTag)) {
    throw "Baseline is missing ConfirmedTag; refusing to proceed."
}

# 3. Commit SHA must be a real 40-hex value.
if ($Baseline.ConfirmedCommitSha -notmatch '\A[0-9a-fA-F]{40}\z') {
    throw "Baseline ConfirmedCommitSha is not a 40-char hex SHA; refusing to proceed."
}

# 4. Repository allowlist. The dependency-graph step runs `.build/Build.ps1` from
#    the baseline; only do that against a repository whose code is already trusted.
#    `-ne` is case-insensitive by design: GitHub owner/repo names are
#    case-insensitive for routing, so 'Microsoft/CSS-Exchange' is the same
#    repository and must not be rejected.
if ($Baseline.Repository -ne $allowedRepository) {
    throw "Baseline resolution executes .build/Build.ps1 and is restricted to $allowedRepository (got '$($Baseline.Repository)')."
}

# 5. The local repository we will materialize from must match. Read the origin
#    URL WITHOUT any pager or prompt.
$originUrl = git --no-pager -C $RepositoryRoot config --get remote.origin.url
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($originUrl)) {
    throw "Could not read local git origin URL for '$RepositoryRoot'."
}
if ($originUrl -notmatch $originPattern) {
    throw "Local origin does not point to $allowedRepository; refusing to proceed."
}

# 6. The commit must exist locally before we materialize it. `cat-file -e`
#    returns non-zero if the object is missing.
$null = git --no-pager -C $RepositoryRoot cat-file -e "$($Baseline.ConfirmedCommitSha)^{commit}" 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Commit $($Baseline.ConfirmedCommitSha) is not present locally; run 'git fetch --tags' and retry."
}

# 7. Tag must resolve locally to EXACTLY the claimed commit.
if ($Baseline.ConfirmedTag -notmatch '\A[A-Za-z0-9][A-Za-z0-9._\-+/]{0,254}\z') {
    throw "Baseline ConfirmedTag contains characters not permitted in a git ref; refusing to proceed."
}
$tagRef = "refs/tags/$($Baseline.ConfirmedTag)"
$tagPeeled = @(git --no-pager -C $RepositoryRoot rev-parse --verify --end-of-options "$tagRef^{commit}" 2>$null)
if ($LASTEXITCODE -ne 0 -or $tagPeeled.Count -eq 0 -or [string]::IsNullOrWhiteSpace($tagPeeled[0])) {
    throw "Tag $($Baseline.ConfirmedTag) does not resolve to a commit locally; run 'git fetch --tags' and retry."
}
# stderr is discarded rather than merged so a git warning on an otherwise
# successful call cannot be concatenated into the SHA and cause a legitimate
# baseline to be falsely rejected.
if (([string]$tagPeeled[0]).Trim().ToLowerInvariant() -ne $Baseline.ConfirmedCommitSha.ToLowerInvariant()) {
    throw ("Tag $($Baseline.ConfirmedTag) resolves locally to $(([string]$tagPeeled[0]).Trim()) but the baseline " +
        "result claims $($Baseline.ConfirmedCommitSha); refusing to proceed against an unverified pairing.")
}
