# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore toplevel

<#
.SYNOPSIS
    Materialize the dependency graph for a CSS-Exchange script at a pinned
    release baseline, using a per-user per-SHA cache to avoid repeated builds.

.DESCRIPTION
    The `dependency-analysis` skill expects `dist/dependencyHashtable.xml` and
    `dist/dependentHashtable.xml`, but these are gitignored and are produced by
    `.build/Build.ps1` from the current checkout. Building them in a scratch git
    worktree takes roughly three and a half minutes, which dominates the runtime
    of the `analyze-debug-files` skill.

    This helper short-circuits that cost with a per-user, per-SHA cache rooted at
    `$env:LOCALAPPDATA\CSS-Exchange\dependency-cache\<sha>\`. The commit SHA is
    the integrity key: `.build/Build.ps1` output is deterministic per SHA
    (version numbers derive from commit dates frozen in the commit itself), so no
    content hash is needed. The cache is per-user because `LOCALAPPDATA` is not
    roamed, matching the trust model that each user runs against their own vetted
    local clone.

    Two branches:

      Cache hit   -- both XML files plus a matching `metadata.json` are present.
                     Load the XML from cache, touch a `.last-accessed` marker,
                     and skip the worktree entirely.
      Cache miss  -- materialize a scratch worktree at the pinned SHA, run
                     `.build/Build.ps1`, import both XML files, then populate the
                     cache from that same built XML before disposing the worktree.

    The returned `Entry` and `AllDeps` values are always normalized to canonical
    repo-relative paths (forward slashes, matching `git ls-tree` output), so the
    caller can read source with `git show <sha>:<path>` against the current clone
    on either branch. The scratch worktree is removed before this script
    returns; a cleanup failure emits a warning naming the retained path.
    Callers must not depend on the scratch worktree.

    SECURITY: this script executes code from the pinned baseline
    (`.build/Build.ps1`). It therefore enforces hard refusals -- it throws, and
    does NOT return a soft status -- when the enclosing repository is not
    `microsoft/CSS-Exchange`, when the commit SHA is not 40-char hex, when `Tag`
    does not resolve locally to exactly `CommitSha`, or when the
    dependency-cache root or scratch-worktree parent fails local-path
    validation. These gates must never degrade into a recoverable status that a
    caller might ignore. `Status` is reserved for informational outcomes only.

    The tag/commit check is deliberately duplicated from
    `Assert-BaselineTrusted.ps1` gate 7. That script is the documented Step 4
    gate, but nothing proves to this script that it ran, and the consequence of
    skipping it is arbitrary code execution from any commit object present in
    the clone. A control that lives only in a sibling script is a convention.

.PARAMETER CommitSha
    Pinned 40-hex commit SHA for the release baseline. Supply
    `Find-ReleaseTagForScriptVersion.ps1`'s `ConfirmedCommitSha`. Callers should
    still run `Assert-BaselineTrusted.ps1` first -- it checks provenance this
    script cannot see (lookup status, repository allowlist on the *result*) --
    but this script independently re-verifies the tag/commit pairing before
    executing anything.

.PARAMETER Tag
    Release tag the SHA was resolved from, e.g. `v26.10.02.1939`. Must resolve
    locally to exactly `CommitSha` or this script throws. Also recorded in the
    cache entry's `metadata.json` for audit purposes.

.PARAMETER ScriptLeafName
    Leaf filename of the script under analysis, e.g. `HealthChecker.ps1`. Matched
    case-sensitively against dependency-graph keys and `git ls-tree` entries.

.PARAMETER RepositoryRoot
    Local git working tree root. Defaults to `git rev-parse --show-toplevel` from
    the current directory. The resolved repository must be `microsoft/CSS-Exchange`.

.OUTPUTS
    PSCustomObject with:
      .Entry                  repo-relative path of the analyzed script
      .AllDeps                string[] of repo-relative dependency paths,
                              including .Entry, sorted in ordinal order
      .HasErrorHelper         whether AllDeps contains Get-ErrorsThatOccurred.ps1
                              by exact leaf name, for completion classification
      .MaterializationSource  'Cache' | 'BuildAndCached' | 'BuildOnly'
      .BaselineSha            lower-cased 40-hex SHA actually used
      .BaselineTag            the Tag value echoed back
      .Status                 'Ok' | 'PartialGraph'
      .StatusDetail           human-readable detail; $null when Status is 'Ok'

    Status values:
      Ok            -- the dependency graph resolved and was traversed
                       transitively from the entry file.
      PartialGraph  -- no dependency-graph key matched the entry file, so the
                       entry was discovered directly from the pinned tree and
                       AllDeps contains only the entry itself. Downstream
                       correlation has reduced coverage; callers MUST disclose
                       this.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('\A[0-9a-fA-F]{40}\z')]
    [string]$CommitSha,

    # Recorded into metadata.json AND used as the self-enforcing baseline gate
    # below, where it must resolve locally to exactly $CommitSha. The charset is
    # kept identical to `Assert-BaselineTrusted.ps1`'s gate-7 ref-name check so a
    # tag cannot pass Step 4 and then be rejected here. `/` and `+` are legal in
    # git ref names; a leading alphanumeric is required so the value can never be
    # parsed as an option, and the 255 cap matches the ref-name limit.
    [Parameter(Mandatory = $true)]
    [ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9._\-+/]{0,254}\z')]
    [string]$Tag,

    # A leaf filename only. Rejects anything carrying a path separator, drive
    # qualifier, or traversal component so this value cannot widen the
    # `GetFileName($_) -ceq $ScriptLeafName` comparisons below into a path match.
    [Parameter(Mandatory = $true)]
    [ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9._\-]*\.ps1\z')]
    [string]$ScriptLeafName,

    [string]$RepositoryRoot
)

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "Get-BaselineDependencyGraph requires PowerShell 7+ (.build/Build.ps1 uses it)."
}

# The 40-hex shape is enforced by ValidatePattern above; normalize case for use
# as a stable cache directory name.
$sha = $CommitSha.ToLowerInvariant()

. $PSScriptRoot\..\..\skill-lib\Resolve-SkillLocalPath.ps1

function Resolve-RepoRelativePath {
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][hashtable]$Index,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$RepoRelativeSet,
        [Parameter(Mandatory)][string]$Sha
    )
    # Exact repo-relative match (git ls-tree form).
    $canonical = ($Key -replace '\\', '/').TrimStart('/')
    if ($RepoRelativeSet.Contains($canonical)) { return $canonical }
    # Suffix match against a stale/live absolute worktree path.
    # Collect every candidate whose repo-relative form is a suffix of the
    # worktree-rooted key. A single input can end with multiple repository paths
    # (for example a shorter nested path can be a suffix of a longer one), so we
    # require an unambiguous longest match and reject on ties. Returning the
    # first hashtable-key match would silently resolve to whichever entry
    # happened to be enumerated first, which is a wrong-source bug the caller
    # cannot detect.
    $winKey = '\' + ($Key -replace '/', '\')
    $suffixMatches = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Index.Keys) {
        if ($winKey.EndsWith($k, [System.StringComparison]::OrdinalIgnoreCase)) {
            $suffixMatches.Add($k)
        }
    }
    if ($suffixMatches.Count -eq 0) { return $null }
    $maxLen = 0
    foreach ($m in $suffixMatches) { if ($m.Length -gt $maxLen) { $maxLen = $m.Length } }
    $longest = @($suffixMatches | Where-Object { $_.Length -eq $maxLen })
    if ($longest.Count -gt 1) {
        Write-Warning "Ambiguous suffix match for '$Key' at $Sha (candidates: $($longest -join ', ')); dropping to avoid wrong-source resolution."
        return $null
    }
    return $Index[$longest[0]]
}

# --- Repository anchoring + allowlist -------------------------------------
# This script runs `.build/Build.ps1` from the pinned baseline, so the enclosing
# repository must be one whose code is already trusted. Read the origin URL
# WITHOUT any pager or prompt; a mismatch means we are running from a clone that
# has not been vetted.
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $currentDirectory = Resolve-SkillLocalPath -Path (Get-Location).Path
    if ($null -eq $currentDirectory) {
        throw "Get-BaselineDependencyGraph refuses repository discovery: the current directory failed local-path validation."
    }
    $repoRootRaw = git --no-pager -C $currentDirectory rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repoRootRaw)) {
        throw "Get-BaselineDependencyGraph must run inside the microsoft/CSS-Exchange git repository."
    }
    $repoRoot = $repoRootRaw.Trim()
} else {
    $repoRoot = $RepositoryRoot.Trim()
}

# Gate 0 (mirrors `Assert-BaselineTrusted.ps1`): the working tree we are about
# to read AND materialize a worktree from must itself be a real local directory.
# `$repoRoot` feeds `git -C` for the origin check, the tag gate, `worktree add`,
# `ls-tree`, and `show` -- a UNC, SUBST-aliased, device-namespace, or
# reparse-redirected root means `.build/Build.ps1` is executed from an object
# store the operator never chose. Validating this only in the sibling gate would
# be exactly the "convention, not a control" mistake called out below; worse,
# the two scripts default `RepositoryRoot` differently (Assert uses the CWD,
# this script uses `git rev-parse --show-toplevel`), so Assert's check does not
# even transitively cover this path.
$resolvedRepositoryRoot = Resolve-SkillLocalPath -Path $repoRoot
if ($null -eq $resolvedRepositoryRoot) {
    throw ("Get-BaselineDependencyGraph refuses to operate on repository root '$repoRoot' — " +
        "it failed local-path validation. The path is UNC, on a non-local drive, on a " +
        "SUBST/DefineDosDevice alias, or has a junction/symlink ancestor.")
}
$repoRoot = $resolvedRepositoryRoot

$remoteUrl = git -C $repoRoot config --get remote.origin.url 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($remoteUrl) -or
    $remoteUrl -notmatch '(?i)\A(?:https://github\.com/microsoft/CSS-Exchange(?:\.git)?/?|git@github\.com:microsoft/CSS-Exchange(?:\.git)?/?|ssh://git@github\.com/microsoft/CSS-Exchange(?:\.git)?/?)\z') {
    throw "Get-BaselineDependencyGraph requires a microsoft/CSS-Exchange checkout; resolved repo '$repoRoot' has remote '$remoteUrl'."
}

# --- Self-enforcing baseline gate -----------------------------------------
# `Assert-BaselineTrusted.ps1` is the documented Step 4 gate, but nothing can
# PROVE to this script that it ran. A caller that skips it, reorders the steps,
# or passes hand-assembled arguments would reach the `.build/Build.ps1`
# invocation below against an arbitrary commit. The bar is low: ANY commit
# object already in the clone can be materialized by `git worktree add --detach`,
# and `gh pr checkout`, `git fetch origin pull/N/head`, or a stale review branch
# all leave untrusted commits reachable.
#
# So re-verify here the one binding that makes `$CommitSha` a *release*
# baseline rather than an arbitrary commit: the tag must resolve locally to
# EXACTLY the commit we are about to execute. This deliberately duplicates
# gate 7 of `Assert-BaselineTrusted.ps1` -- a security control that exists only
# in a sibling script is a convention, not a control, and conventions do not
# survive refactors.
#
# `^{commit}` peels annotated tags; a lightweight tag pointing straight at the
# commit resolves identically, so only a genuine disagreement is rejected.
# `--end-of-options` prevents a ref name from being parsed as an option.
# stderr is discarded rather than merged so a git warning cannot be
# concatenated into the SHA comparison below.
$tagPeeled = @(git --no-pager -C $repoRoot rev-parse --verify --end-of-options "refs/tags/$Tag^{commit}" 2>$null)
if ($LASTEXITCODE -ne 0 -or $tagPeeled.Count -eq 0 -or [string]::IsNullOrWhiteSpace($tagPeeled[0])) {
    throw ("Get-BaselineDependencyGraph refuses to execute .build/Build.ps1: tag '$Tag' does not " +
        "resolve to a commit in '$repoRoot'. Run 'git fetch --tags' and retry.")
}
$tagSha = ([string]$tagPeeled[0]).Trim().ToLowerInvariant()
if ($tagSha -ne $sha) {
    throw ("Get-BaselineDependencyGraph refuses to execute .build/Build.ps1: tag '$Tag' resolves " +
        "locally to $tagSha but CommitSha is $sha. Refusing to build from an unverified " +
        "tag/commit pairing.")
}

$cacheRoot = Join-Path $env:LOCALAPPDATA 'CSS-Exchange\dependency-cache'
# Missing cache paths still require the full locality and reparse checks.
$resolvedCacheRoot = Resolve-SkillLocalPath -Path $cacheRoot -AllowMissing
if ($null -eq $resolvedCacheRoot) {
    throw ("Get-BaselineDependencyGraph refuses to use dependency-cache root '$cacheRoot' — " +
        "it failed local-path validation. `$env:LOCALAPPDATA` is UNC, " +
        "on a non-local drive, on a SUBST/DefineDosDevice alias, or " +
        "has a junction/symlink ancestor.")
}
$cacheRoot = $resolvedCacheRoot

$cacheDir = Join-Path $cacheRoot $sha
$dependencyCacheXml = Join-Path $cacheDir 'dependencyHashtable.xml'
$dependentCacheXml = Join-Path $cacheDir 'dependentHashtable.xml'
$metaCache = Join-Path $cacheDir 'metadata.json'
$marker = Join-Path $cacheDir '.last-accessed'

$dependencyHashtable = $null
$materializationSource = $null
$worktreeRoot = $null
# Cleanup-gate flag. Only becomes $true AFTER post-add locality validation
# succeeds. The outer `finally` MUST NOT touch `$worktreeRoot` via `Test-Path`
# or `git worktree remove` unless this flag is $true -- if post-add validation
# rejected the path (e.g. a racer materialized a junction between our
# parent-check and `git worktree add`), running cleanup against the rejected
# path would traverse the redirected destination and, worse, hand
# `git worktree remove --force` a rooted-elsewhere target. On rejection, we
# leave the (small, GUID-named, no-secrets) scratch directory for manual
# inspection and surface the failure.
$worktreeValidated = $false

$cacheValid = $false
# An existing child can itself be a reparse point even when its parent is not.
foreach ($cachePath in @($dependencyCacheXml, $dependentCacheXml, $metaCache, $marker)) {
    if (-not (Resolve-SkillLocalPath -Path $cachePath -AllowMissing)) {
        throw "Get-BaselineDependencyGraph refuses to use cache path '$cachePath' — it failed local-path validation."
    }
}
$cacheEntryValidated = Test-Path -LiteralPath $cacheDir -PathType Container
if ((Test-Path -LiteralPath $dependencyCacheXml -PathType Leaf) -and
    (Test-Path -LiteralPath $dependentCacheXml -PathType Leaf) -and
    (Test-Path -LiteralPath $metaCache -PathType Leaf)) {
    try {
        $metaText = Get-Content -LiteralPath $metaCache -Raw -ErrorAction Stop
        $meta = $metaText | ConvertFrom-Json -ErrorAction Stop
        if ($meta.SchemaVersion -eq 1 -and
            $meta.BaselineSha -is [string] -and
            $meta.BaselineSha.ToLowerInvariant() -eq $sha) {
            $cacheValid = $true
        }
    } catch {
        Write-Warning "Cache metadata at $metaCache is unreadable; falling through to build."
    }
}

try {
    if ($cacheValid) {
        # === Cache hit ===
        # All existing entry paths were validated at intake.
        # Import may still throw if a per-SHA XML on disk is truncated or
        # corrupt (interrupted writer, disk error, tampering). The existence +
        # metadata check above does NOT prove the XML parses. Recover by
        # quarantining the entire cache entry and falling into the build branch
        # on this run so one bad entry cannot permanently abort analysis of a
        # good baseline.
        try {
            $dependencyHashtable = Import-Clixml -LiteralPath $dependencyCacheXml
            $null = Import-Clixml -LiteralPath $dependentCacheXml
        } catch {
            $quarantineName = "$sha.corrupt.$PID-$(([guid]::NewGuid().ToString('N')).Substring(0,8))"
            $quarantineDir = Join-Path $cacheRoot $quarantineName
            Write-Warning "Cache entry at $cacheDir failed to import ($_); quarantining as $quarantineName and rebuilding."
            try {
                [System.IO.Directory]::Move($cacheDir, $quarantineDir)
                $cacheEntryValidated = $false
            } catch {
                Write-Warning "Could not quarantine ${cacheDir}: $_. Proceeding to build; a future run will retry."
            }
            $cacheValid = $false
            $dependencyHashtable = $null
        }
    }

    if ($cacheValid) {
        $materializationSource = 'Cache'
        # Touch a marker file so external cache-maintenance tooling can sort by
        # recency without parsing metadata.json.
        try {
            [System.IO.File]::WriteAllText($marker, (Get-Date).ToUniversalTime().ToString('o'))
        } catch {
            Write-Warning "Could not update .last-accessed marker under ${cacheDir}: $_"
        }
        # On the hit path the caller reads source with `git show $sha:<path>`
        # against the current clone. $worktreeRoot stays $null; no worktree
        # cleanup runs.
    } else {
        # === Cache miss: build in a scratch worktree ===
        # The scratch-worktree parent comes from `[System.IO.Path]::GetTempPath()`,
        # which reads `TMP` / `TEMP` / `UserProfile`. A tampered TEMP (or a
        # junction/symlink along its resolved path) can redirect `git worktree add`
        # and the subsequent Build.ps1 subprocess to a UNC share or a
        # reparse-point-backed slot, silently bypassing the local-only trust
        # model. Validate the parent before `git worktree add`; `$worktreeRoot`
        # itself is a fresh GUID sibling under the validated parent and inherits
        # its guarantees.
        $tempParent = [System.IO.Path]::GetTempPath()
        $resolvedTempParent = Resolve-SkillLocalPath -Path $tempParent
        if ($null -eq $resolvedTempParent) {
            throw ("Get-BaselineDependencyGraph refuses to create a scratch worktree under " +
                "'$tempParent' — it failed local-path validation. " +
                "`TEMP` / `TMP` is UNC, on a non-local drive, on a SUBST/" +
                "DefineDosDevice alias, or has a junction/symlink ancestor.")
        }
        $tempParent = $resolvedTempParent
        $worktreeRoot = Join-Path $tempParent ("css-exchange-analyze-" + [guid]::NewGuid().ToString('N'))
        # Capture native output instead of letting it fall through to the
        # pipeline. This script's return value is a single result object; an
        # unassigned native call would emit every progress line as a pipeline
        # string and corrupt that contract for the caller.
        $addOutput = git --no-pager -C $repoRoot worktree add --detach $worktreeRoot $sha 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "git worktree add failed (exit $LASTEXITCODE): $(($addOutput | ForEach-Object { [string]$_ }) -join '; ')"
        }
        $addOutput | ForEach-Object { Write-Verbose ([string]$_) }
        # Boundary check on a newly-materialized path -- one-time validation
        # applies to paths that did not exist at intake, and the git worktree
        # root falls into that category.
        #
        # `git worktree add` follows symlinks on the input path, so an existing
        # symlink somewhere under `%TEMP%` (e.g. installer- or tool-created, NOT
        # a concurrent racer) could land the worktree off the local disk.
        # Deliberately no `Test-Path` before this check:
        # `Resolve-SkillLocalPath` runs a non-following reparse walk FIRST and
        # only then confirms the directory exists, so it proves reparse-freedom
        # and existence in one pass. Do not defend against a same-user racer
        # materializing a junction between `git worktree add` and this check --
        # that is out of the trust boundary.
        $resolvedWorktreeRoot = Resolve-SkillLocalPath -Path $worktreeRoot
        if ($null -eq $resolvedWorktreeRoot) {
            throw ("Get-BaselineDependencyGraph refuses to Push-Location into worktree root " +
                "'$worktreeRoot' — it failed local-path validation after " +
                "`git worktree add`, indicating a symlink-redirected TEMP, " +
                "misconfigured environment, or that the directory does " +
                "not exist.")
        }
        $worktreeRoot = $resolvedWorktreeRoot
        # Post-validation gate: only after this line may the outer `finally`
        # touch `$worktreeRoot` via `Test-Path` or invoke `git worktree remove`
        # against it. See the flag declaration for the reasoning.
        $worktreeValidated = $true
        Push-Location -LiteralPath $worktreeRoot -ErrorAction Stop
        try {
            # Run Build.ps1 in an isolated pwsh process so the caller's error
            # preferences and module state cannot affect the build. A child
            # scope overrides caller-local native error preferences without
            # changing the caller's setting or the global session.
            $buildOutput = & {
                $PSNativeCommandUseErrorActionPreference = $false
                & pwsh -NoProfile -File (Join-Path -Path $worktreeRoot -ChildPath '.build\Build.ps1') 2>&1
            }
            $buildOutput | ForEach-Object { Write-Verbose ([string]$_) }
            # Build.ps1 may exit non-zero on cosmetic Format-Table errors while
            # still producing the XML we need. Assert on the XML files instead.
            $dependencyBuiltXml = Join-Path $worktreeRoot 'dist\dependencyHashtable.xml'
            $dependentBuiltXml = Join-Path $worktreeRoot 'dist\dependentHashtable.xml'
            if (-not (Test-Path -LiteralPath $dependencyBuiltXml -PathType Leaf)) {
                throw "Build.ps1 did not produce dependencyHashtable.xml at $dependencyBuiltXml."
            }
            if (-not (Test-Path -LiteralPath $dependentBuiltXml -PathType Leaf)) {
                throw "Build.ps1 did not produce dependentHashtable.xml at $dependentBuiltXml."
            }
            $dependencyHashtable = Import-Clixml -LiteralPath $dependencyBuiltXml
            # Parse-validate the dependent graph too, even though this script
            # does not traverse it. Build.ps1 can emit a truncated file (disk
            # pressure, interrupted write); importing here keeps a corrupt XML
            # from being copied into the cache below, where every later run
            # would hit it on the cache-hit path. Discarded deliberately -- only
            # the dependency direction is traversed.
            $null = Import-Clixml -LiteralPath $dependentBuiltXml

            # === Cache population ===
            # Build into a per-pid temp sibling directory, then atomic rename.
            # Same-volume rename on LOCALAPPDATA is atomic.
            $materializationSource = 'BuildOnly'
            # Initialize BEFORE the try so a failure inside
            # `New-Item -Path $cacheRoot` (i.e. before $tempDir is assigned)
            # cannot leave $tempDir unbound. Under Set-StrictMode the
            # `if ($tempDir -and ...)` guard in the catch would otherwise throw
            # and mask the original cache error.
            $tempDir = $null
            try {
                if (-not (Test-Path -LiteralPath $cacheRoot -PathType Container)) {
                    New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null
                }
                # Threat model: `$cacheRoot` was validated at intake; `New-Item`
                # above only materializes the same path. No post-create
                # revalidation -- same-user races are out of scope.
                $rand = [guid]::NewGuid().ToString('N').Substring(0, 8)
                $tempDir = Join-Path $cacheRoot ($sha + '.building.' + $PID + '-' + $rand)
                New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
                Copy-Item -LiteralPath $dependencyBuiltXml -Destination (Join-Path $tempDir 'dependencyHashtable.xml') -Force
                Copy-Item -LiteralPath $dependentBuiltXml -Destination (Join-Path $tempDir 'dependentHashtable.xml') -Force
                $meta = [ordered]@{
                    SchemaVersion     = 1
                    BaselineSha       = $sha
                    BaselineTag       = $Tag
                    BuiltAtUtc        = (Get-Date).ToUniversalTime().ToString('o')
                    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                }
                $metaJson = $meta | ConvertTo-Json -Depth 3
                [System.IO.File]::WriteAllText((Join-Path $tempDir 'metadata.json'), $metaJson)
                # Race check: distinguish a valid concurrent winner from a
                # stale/corrupt entry. If $cacheDir already exists but is missing
                # metadata.json or either XML file, or metadata.json is malformed
                # or does not match $sha, the previous winner is not usable and
                # every future run would keep hitting the bad entry -- quarantine
                # it so this run can install a fresh copy. Only accept the
                # existing entry when it validates.
                #
                # Concurrency: `[System.IO.Directory]::Move` is atomic w.r.t. the
                # destination name -- the underlying `MoveFileEx` Win32 call,
                # invoked without the replace-existing flag, throws IOException if
                # the destination already exists. Using PowerShell's `Move-Item`
                # after a `Test-Path` check would open a race: a concurrent writer
                # that created $cacheDir between our check and the move would
                # silently receive $tempDir as a NESTED child, leaving the cache
                # root without XML files but flagged as `BuildAndCached` for later
                # runs. Always attempt the move first and treat IOException as
                # "another process installed a same-SHA entry; validate the winner".
                #
                # Volume constraint: `Directory.Move` (like `MoveFileEx` without
                # the copy-allowed flag) fails with IOException /
                # ERROR_NOT_SAME_DEVICE when source and destination are on
                # different volumes. The pattern above guarantees same-volume
                # placement by construction -- `$tempDir` is created under
                # `$cacheRoot` via `Join-Path $cacheRoot ...` -- so this failure
                # mode cannot occur here. Do NOT relocate `$tempDir` to a system
                # temp path (`$env:TEMP`, custom scratch drive) without also
                # switching to a copy-and-delete strategy or you will silently
                # misclassify every install as "lost race".
                $installed = $false
                try {
                    [System.IO.Directory]::Move($tempDir, $cacheDir)
                    $installed = $true
                } catch [System.IO.IOException] {
                    # Destination already exists -- lost the race.
                    $installed = $false
                }
                if (-not $installed) {
                    $existingIsValid = $false
                    # A winner created after intake is a new entry boundary,
                    # not a reason to repeat checks on already-trusted paths.
                    if (-not $cacheEntryValidated) {
                        foreach ($cachePath in @($dependencyCacheXml, $dependentCacheXml, $metaCache, $marker)) {
                            if (-not (Resolve-SkillLocalPath -Path $cachePath -AllowMissing)) {
                                throw "Cache winner path '$cachePath' failed local-path validation; refusing to inspect it."
                            }
                        }
                        $cacheEntryValidated = $true
                    }
                    try {
                        $existingMetaPath = Join-Path $cacheDir 'metadata.json'
                        $existingDepPath = Join-Path $cacheDir 'dependencyHashtable.xml'
                        $existingDeptPath = Join-Path $cacheDir 'dependentHashtable.xml'
                        if ((Test-Path -LiteralPath $existingMetaPath -PathType Leaf) -and
                            (Test-Path -LiteralPath $existingDepPath -PathType Leaf) -and
                            (Test-Path -LiteralPath $existingDeptPath -PathType Leaf)) {
                            $existingMeta = Get-Content -LiteralPath $existingMetaPath -Raw -ErrorAction Stop |
                                ConvertFrom-Json -ErrorAction Stop
                            if ($existingMeta.SchemaVersion -eq 1 -and
                                $existingMeta.BaselineSha -eq $sha) {
                                # File existence + metadata match is necessary but
                                # NOT sufficient. A truncated or corrupt XML
                                # (interrupted writer, disk error, tampering) will
                                # pass the file-existence check yet fail to import.
                                # If we accept such an entry here, this runner
                                # discards its freshly-built good XML, and every
                                # future run repeats the cache-hit branch's
                                # Import-Clixml failure -> quarantine -> rebuild
                                # loop, wasting build time each run until an
                                # operator manually intervenes. Import both XMLs to
                                # actually prove the entry is usable before
                                # honoring it.
                                $null = Import-Clixml -LiteralPath $existingDepPath -ErrorAction Stop
                                $null = Import-Clixml -LiteralPath $existingDeptPath -ErrorAction Stop
                                $existingIsValid = $true
                            }
                        }
                    } catch {
                        Write-Verbose "Existing cache entry at $cacheDir failed validation: $_"
                        $existingIsValid = $false
                    }
                    if ($existingIsValid) {
                        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                        $materializationSource = 'BuildAndCached'
                    } else {
                        $quarantineName = "$sha.corrupt.$PID-$(([guid]::NewGuid().ToString('N')).Substring(0,8))"
                        $quarantinePath = Join-Path $cacheRoot $quarantineName
                        Write-Warning "Quarantining invalid cache entry at $cacheDir -> $quarantinePath (missing files, malformed metadata, or SHA/schema mismatch)."
                        Move-Item -LiteralPath $cacheDir -Destination $quarantinePath -ErrorAction Stop
                        # Retry the atomic install now that the destination name is
                        # free again. If a third concurrent writer slipped in
                        # between the quarantine rename and this retry, treat the
                        # second failure as a lost race too and skip caching for
                        # this run.
                        try {
                            [System.IO.Directory]::Move($tempDir, $cacheDir)
                            $materializationSource = 'BuildAndCached'
                        } catch [System.IO.IOException] {
                            Write-Warning "Cache slot reoccupied after quarantine at $cacheDir; continuing without a cache write."
                            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                            # $materializationSource remains 'BuildOnly'.
                        }
                    }
                } else {
                    $materializationSource = 'BuildAndCached'
                }
            } catch {
                Write-Warning "Cache population failed under $cacheRoot; continuing without a cache write: $_"
                # $materializationSource remains 'BuildOnly'.
                # Clean up the partially-populated temp directory so repeated
                # failures cannot orphan `*.building.*` siblings under $cacheRoot
                # and eventually consume the user's local disk. Only $tempDir is
                # removed here -- the final $cacheDir slot is intentionally left
                # alone in case a concurrent runner successfully populated it
                # while this runner was mid-catch, or the failure happened AFTER
                # the atomic Move (unlikely but possible under exotic exception
                # paths).
                if ($tempDir -and (Test-Path -LiteralPath $tempDir -PathType Container)) {
                    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        } finally {
            Pop-Location
        }
    }

    # === Entry-file discovery + transitive dependency traversal ===
    # Runs on BOTH branches. On cache hit, XML keys are opaque graph identifiers
    # (they were rooted in a worktree that no longer exists). On cache miss, XML
    # keys are absolute paths under $worktreeRoot. Both shapes are normalized to
    # repo-relative form below.
    $status = 'Ok'
    $statusDetail = $null

    # Resolve the entry candidates FIRST. An ambiguous graph (two keys with
    # the same leaf name) is a more fundamental problem than anything
    # `ls-tree` could tell us, so reject it before spending a subprocess --
    # and so the operator sees "Multiple graph keys match" rather than an
    # incidental `git ls-tree failed` when both are wrong at once.
    $entryCandidates = @(
        $dependencyHashtable.Keys | Where-Object {
            [System.IO.Path]::GetFileName($_) -ceq $ScriptLeafName
        }
    )
    if ($entryCandidates.Count -gt 1) {
        throw "Multiple graph keys match $ScriptLeafName; disambiguate before proceeding: $($entryCandidates -join ', ')"
    }

    # `git ls-tree` at the pinned SHA is the authoritative file list for the
    # commit. BOTH the PartialGraph fallback (leaf-name discovery) and the
    # path-normalization pass below need it, so read it ONCE here rather than
    # spawning the same subprocess twice on the fallback path.
    $treeLines = git --no-pager -C $repoRoot ls-tree -r --name-only $sha
    if ($LASTEXITCODE -ne 0) {
        throw "git ls-tree failed for $sha (exit $LASTEXITCODE)."
    }

    if ($entryCandidates.Count -eq 0) {
        # Fallback: no usable dependency graph entry -> discover the file
        # directly from the pinned tree by leaf-name match. Runs the same way on
        # cache hit and cache miss because `git show`/`git ls-tree` read from the
        # current clone.
        $treeMatch = @($treeLines | Where-Object {
                [System.IO.Path]::GetFileName($_) -ceq $ScriptLeafName
            })
        if ($treeMatch.Count -ne 1) {
            throw "No dependency-graph key and no unique tree entry match $ScriptLeafName at $sha."
        }
        $entry = $treeMatch[0]
        $allDeps = [System.Collections.Generic.HashSet[string]]::new()
        [void]$allDeps.Add($entry)
        $status = 'PartialGraph'
        $statusDetail = ("No dependency-graph key matched '$ScriptLeafName' at $sha; " +
            "the entry file was discovered directly from the pinned tree and AllDeps " +
            "contains only that file. Downstream correlation has reduced coverage.")
        Write-Warning "Proceeding without full dependency graph — downstream correlation has reduced coverage."
    } else {
        # Ambiguity (Count -gt 1) was already rejected above, before any
        # subprocess ran, so exactly one candidate remains here.
        $entry = $entryCandidates[0]
        $allDeps = [System.Collections.Generic.HashSet[string]]::new()
        $queue = [System.Collections.Generic.Queue[string]]::new()
        $queue.Enqueue($entry)
        while ($queue.Count -gt 0) {
            $current = $queue.Dequeue()
            if (-not $allDeps.Add($current)) { continue }
            if ($dependencyHashtable.ContainsKey($current)) {
                foreach ($dep in $dependencyHashtable[$current]) {
                    $queue.Enqueue($dep)
                }
            }
        }
    }

    # === Normalize $entry and $allDeps to repo-relative paths ===
    # Build.ps1 records absolute paths in the XML rooted in whatever worktree
    # produced the build. On cache miss those roots point at the live
    # $worktreeRoot; on cache hit they point at a worktree that no longer exists.
    # Either way, callers use `git show <sha>:<path>` which requires a
    # repo-relative path (forward slashes). Resolve every key to its canonical
    # form against the `$treeLines` snapshot read above -- that is the
    # authoritative list of files in the commit. Runs on BOTH branches so
    # callers get one consistent path shape.
    # Index keyed on `\<windows form>` so an EndsWith test against a stale
    # absolute path resolves to a unique tree entry.
    $treeIndex = @{}
    foreach ($t in $treeLines) {
        $winSuffix = '\' + ($t -replace '/', '\')
        $treeIndex[$winSuffix] = $t
    }
    $treePathSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$treeLines,
        [System.StringComparer]::OrdinalIgnoreCase)

    $normalizedEntry = Resolve-RepoRelativePath -Key $entry -Index $treeIndex -RepoRelativeSet $treePathSet -Sha $sha
    if (-not $normalizedEntry) {
        throw "Could not resolve entry path '$entry' to a repo-relative path at $sha."
    }
    $entry = $normalizedEntry

    $normalizedAllDeps = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($d in $allDeps) {
        $r = Resolve-RepoRelativePath -Key $d -Index $treeIndex -RepoRelativeSet $treePathSet -Sha $sha
        if ($r) {
            [void]$normalizedAllDeps.Add($r)
        } else {
            # A build artifact or generated file recorded by Build.ps1 that isn't
            # tracked in git at this SHA. Skip it; it can't be read via
            # `git show` and isn't a source dependency for downstream correlation.
            Write-Warning "Dropping allDeps entry with no tree match at ${sha}: $d"
        }
    }
    $allDeps = $normalizedAllDeps

    [PSCustomObject]@{
        Entry                 = $entry
        AllDeps               = @($allDeps | Sort-Object -CaseSensitive)
        HasErrorHelper        = @($allDeps | Where-Object {
                [System.IO.Path]::GetFileName($_) -ceq 'Get-ErrorsThatOccurred.ps1'
            }).Count -gt 0
        MaterializationSource = $materializationSource
        BaselineSha           = $sha
        BaselineTag           = $Tag
        Status                = $status
        StatusDetail          = $statusDetail
    }
} finally {
    # Only clean up the worktree if post-add locality validation succeeded. If it
    # did not, `$worktreeRoot` is a rejected path (possibly a racer-installed
    # junction pointing elsewhere) and neither `Test-Path` nor
    # `git worktree remove --force` may be aimed at it -- both would traverse
    # and, in the case of worktree remove, potentially delete content on the
    # redirected target. Leave the small GUID-named scratch directory for
    # inspection and surface the failure via the throw that just bubbled up.
    # `git worktree prune` at any later time will reclaim the metadata slot
    # without touching the on-disk directory.
    if ($worktreeValidated -and $worktreeRoot -and (Test-Path -LiteralPath $worktreeRoot -PathType Container)) {
        $cleanupFailure = $null
        try {
            $cleanupOutput = & {
                $PSNativeCommandUseErrorActionPreference = $false
                git --no-pager -C $repoRoot worktree remove --force $worktreeRoot 2>&1
            }
            if ($LASTEXITCODE -ne 0) {
                $cleanupDetail = ($cleanupOutput | ForEach-Object { [string]$_ }) -join '; '
                $cleanupFailure = "exit ${LASTEXITCODE}: $cleanupDetail"
            }
        } catch {
            $cleanupFailure = [string]$_
        }
        if ($null -ne $cleanupFailure) {
            # Cleanup must not replace an earlier failure, even with -WarningAction Stop.
            Write-Warning -Message "Failed to remove scratch worktree '$worktreeRoot': $cleanupFailure. Remove it manually when it is no longer in use." -WarningAction Continue
        }
    }
}
