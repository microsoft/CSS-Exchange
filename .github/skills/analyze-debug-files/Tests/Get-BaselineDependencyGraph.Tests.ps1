# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore healthchecker toplevel

# Tests for `.github/skills/analyze-debug-files/Get-BaselineDependencyGraph.ps1`.
#
# This helper materializes the dependency graph for a CSS-Exchange script at a
# pinned release baseline. It is security-sensitive: on a cache miss it runs
# `.build/Build.ps1` FROM THE BASELINE COMMIT, so its refusal gates (repository
# allowlist, 40-hex SHA, local-path validation of the cache root and the
# scratch-worktree parent) must stay hard failures rather than degrade into a
# recoverable status a caller might ignore.
#
# `git` is mocked throughout. Worktree creation normally fails; build-path
# cases create only controlled XML fixtures and a child script that exits.
# No test runs the repository build.

[CmdletBinding()]
param()

Describe "Get-BaselineDependencyGraph" {

    BeforeAll {
        $Script:originalGitFunction = $null
        $gitFunction = Get-Command -Name git -CommandType Function -ErrorAction SilentlyContinue
        if ($null -ne $gitFunction) {
            $Script:originalGitFunction = $gitFunction.ScriptBlock
        }
        $Script:repoRoot = (Get-Item "$PSScriptRoot\..\..\..\..").FullName
        $Script:scriptPath = Join-Path $Script:repoRoot '.github\skills\analyze-debug-files\Get-BaselineDependencyGraph.ps1'
        $Script:sha = '1111111111111111111111111111111111111111'
        $Script:tag = 'v26.10.02.1939'

        # Fixture root under %TEMP% rather than Pester's TestDrive PSDrive: the
        # helper validates the drive via DriveInfo + QueryDosDevice, which only
        # speaks about real OS drive letters, not PowerShell provider drives.
        $Script:fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("BaselineGraphTests-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $Script:fixtureRoot -Force | Out-Null

        $Script:realLocalAppData = $env:LOCALAPPDATA
        $Script:realTemp = $env:TEMP
        $Script:realTmp = $env:TMP
        $env:TEMP = $Script:fixtureRoot
        $env:TMP = $Script:fixtureRoot

        # Mock git. Behavior is driven by environment variables rather than
        # global variables: the mock must be reachable from the child scope the
        # helper runs in, and `$global:` variables trip PSAvoidGlobalVars.
        # `& cmd /c exit N` is used to drive $LASTEXITCODE, which the helper
        # checks after every native call and which a plain function return
        # cannot set.
        function global:git {
            $line = ($args | ForEach-Object { [string]$_ }) -join ' '
            $env:MockGitCalls += "$line`n"
            # ORDER MATTERS: the tag-resolution form is also a `rev-parse`, so
            # it must be matched BEFORE the generic repository-root branch or
            # the helper's self-enforcing tag/commit gate would receive a
            # repository path where it expects a SHA.
            if ($line -match 'rev-parse.*refs/tags/') {
                & cmd /c exit ([int]$env:MockGitTagExit)
                return $env:MockGitTagSha
            }
            if ($line -match 'rev-parse') {
                & cmd /c exit 0
                return $env:MockGitRepositoryRoot
            }
            if ($line -match 'config\s+--get\s+remote\.origin\.url') {
                & cmd /c exit ([int]$env:MockGitRemoteExit)
                return $env:MockGitRemote
            }
            if ($line -match 'ls-tree') {
                & cmd /c exit ([int]$env:MockGitTreeExit)
                return ($env:MockGitTree -split "`n" | Where-Object { $_ -ne '' })
            }
            if ($line -match 'worktree\s+add') {
                $env:MockGitWorktreeAddCalled = '1'
                if ($env:MockGitWorktreeAddExit -ne '0') {
                    & cmd /c exit 1
                    return 'mock: worktree add deliberately refused'
                }
                $worktreeRoot = [string]$args[$args.Count - 2]
                $env:MockGitWorktreeRoot = $worktreeRoot
                $dist = Join-Path -Path $worktreeRoot -ChildPath 'dist'
                $buildDirectory = Join-Path -Path $worktreeRoot -ChildPath '.build'
                New-Item -ItemType Directory -Path $dist, $buildDirectory -Force | Out-Null
                if ($env:MockGitBuildXmlMissing -ne '1') {
                    @{
                        "$worktreeRoot\Diagnostics\HealthChecker\HealthChecker.ps1" = @()
                    } | Export-Clixml -LiteralPath (Join-Path -Path $dist -ChildPath 'dependencyHashtable.xml')
                    @{} | Export-Clixml -LiteralPath (Join-Path -Path $dist -ChildPath 'dependentHashtable.xml')
                }
                [System.IO.File]::WriteAllText(
                    (Join-Path -Path $buildDirectory -ChildPath 'Build.ps1'),
                    'exit 1',
                    [System.Text.UTF8Encoding]::new($true))
                if ($env:MockGitNewCacheWinner -eq '1') {
                    $cacheRoot = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'CSS-Exchange\dependency-cache'
                    $target = Join-Path -Path $env:TEMP -ChildPath ([guid]::NewGuid().ToString('N'))
                    New-Item -Path $cacheRoot, $target -ItemType Directory -Force | Out-Null
                    New-Item -Path (Join-Path -Path $cacheRoot -ChildPath $env:MockGitTagSha) -ItemType Junction -Target $target | Out-Null
                }
                & cmd /c exit 0
                return 'mock: controlled build fixture created'
            }
            if ($line -match 'worktree\s+remove') {
                if ($env:MockGitWorktreeRemoveExit -ne '0') {
                    & cmd /c exit 1
                    return 'mock: file locked'
                }
                [System.IO.Directory]::Delete([string]$args[$args.Count - 1], $true)
                & cmd /c exit 0
                return
            }
            & cmd /c exit 0
            return $null
        }

        function Script:Reset-MockGit {
            $env:MockGitRepositoryRoot = $Script:repoRoot
            $env:MockGitCalls = ''
            $env:MockGitCurrentPath = ''
            $env:MockGitRemote = 'https://github.com/microsoft/CSS-Exchange.git'
            $env:MockGitRemoteExit = '0'
            $env:MockGitTreeExit = '0'
            # By default the tag resolves to the SHA under test, so the
            # self-enforcing baseline gate passes and the rest of the suite
            # exercises the behavior it is actually about.
            $env:MockGitTagSha = $Script:sha
            $env:MockGitTagExit = '0'
            $env:MockGitTree = @(
                'Diagnostics/HealthChecker/HealthChecker.ps1',
                'Diagnostics/HealthChecker/Helpers/Get-ErrorsThatOccurred.ps1',
                'Shared/ErrorMonitorFunctions.ps1',
                'Shared/LoggerFunctions.ps1'
            ) -join "`n"
            $env:MockGitWorktreeAddCalled = '0'
            $env:MockGitWorktreeAddExit = '1'
            $env:MockGitWorktreeRemoveExit = '0'
            $env:MockGitWorktreeRoot = ''
            $env:MockGitBuildXmlMissing = '0'
            $env:MockGitNewCacheWinner = '0'
        }

        # Build a cache entry the helper will accept: both XML files plus a
        # metadata.json whose SchemaVersion is 1 and BaselineSha matches.
        function Script:New-CacheEntry {
            param(
                [Parameter(Mandatory)][string]$LocalAppData,
                [Parameter(Mandatory)][string]$Sha,
                [Parameter(Mandatory)][hashtable]$DependencyGraph,
                [hashtable]$DependentGraph = @{},
                [switch]$CorruptXml,
                [int]$SchemaVersion = 1,
                [string]$MetaSha
            )
            $dir = Join-Path $LocalAppData "CSS-Exchange\dependency-cache\$Sha"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $depPath = Join-Path $dir 'dependencyHashtable.xml'
            $deptPath = Join-Path $dir 'dependentHashtable.xml'
            if ($CorruptXml) {
                Set-Content -LiteralPath $depPath -Value 'not valid CliXml at all' -Encoding utf8
                Set-Content -LiteralPath $deptPath -Value 'not valid CliXml at all' -Encoding utf8
            } else {
                $DependencyGraph | Export-Clixml -LiteralPath $depPath
                $DependentGraph | Export-Clixml -LiteralPath $deptPath
            }
            $meta = [ordered]@{
                SchemaVersion     = $SchemaVersion
                BaselineSha       = if ($MetaSha) { $MetaSha } else { $Sha }
                BaselineTag       = 'v26.10.02.1939'
                BuiltAtUtc        = (Get-Date).ToUniversalTime().ToString('o')
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            }
            [System.IO.File]::WriteAllText((Join-Path $dir 'metadata.json'), ($meta | ConvertTo-Json -Depth 3))
            return $dir
        }

        # Fresh, isolated LOCALAPPDATA per test so cache state never leaks.
        function Script:New-IsolatedLocalAppData {
            $p = Join-Path $Script:fixtureRoot ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $p -Force | Out-Null
            $env:LOCALAPPDATA = $p
            return $p
        }

        function Script:Invoke-Target {
            param([hashtable]$Params)
            $splat = @{
                CommitSha      = $Script:sha
                Tag            = $Script:tag
                ScriptLeafName = 'HealthChecker.ps1'
                RepositoryRoot = $Script:repoRoot
            }
            if ($Params) { foreach ($k in $Params.Keys) { $splat[$k] = $Params[$k] } }
            return & $Script:scriptPath @splat
        }
    }

    AfterAll {
        $env:LOCALAPPDATA = $Script:realLocalAppData
        $env:TEMP = $Script:realTemp
        $env:TMP = $Script:realTmp
        Remove-Item -LiteralPath $Script:fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'Function:\git' -ErrorAction SilentlyContinue
        if ($null -ne $Script:originalGitFunction) {
            ${function:global:git} = $Script:originalGitFunction
        }
        foreach ($n in @('MockGitRepositoryRoot', 'MockGitCalls', 'MockGitCurrentPath', 'MockGitRemote', 'MockGitRemoteExit',
                'MockGitTreeExit', 'MockGitTree', 'MockGitWorktreeAddCalled',
                'MockGitTagSha', 'MockGitTagExit', 'MockGitWorktreeAddExit',
                'MockGitWorktreeRemoveExit', 'MockGitWorktreeRoot', 'MockGitBuildXmlMissing',
                'MockGitNewCacheWinner')) {
            Remove-Item -LiteralPath "env:\$n" -ErrorAction SilentlyContinue
        }
        $gitFunction = Get-Command -Name git -CommandType Function -ErrorAction SilentlyContinue
        if ($null -eq $Script:originalGitFunction) {
            $gitFunction | Should -BeNullOrEmpty
        } else {
            $gitFunction.ScriptBlock | Should -Be $Script:originalGitFunction
        }
    }

    BeforeEach {
        Script:Reset-MockGit
        $null = Script:New-IsolatedLocalAppData
    }

    Context "Parameter validation" {

        It "rejects a CommitSha that is not 40 characters" {
            { Script:Invoke-Target -Params @{ CommitSha = 'abc123' } } | Should -Throw
        }
        It "rejects a CommitSha containing non-hex characters" {
            { Script:Invoke-Target -Params @{ CommitSha = ('z' * 40) } } | Should -Throw
        }

        It "rejects a ScriptLeafName carrying a path separator" {
            { Script:Invoke-Target -Params @{ ScriptLeafName = 'Diagnostics/HealthChecker.ps1' } } | Should -Throw
        }

        It "rejects a ScriptLeafName with a traversal component" {
            { Script:Invoke-Target -Params @{ ScriptLeafName = '..\HealthChecker.ps1' } } | Should -Throw
        }

        It "rejects a ScriptLeafName that is not a .ps1 file" {
            { Script:Invoke-Target -Params @{ ScriptLeafName = 'HealthChecker.txt' } } | Should -Throw
        }

        It "rejects a Tag containing shell metacharacters" {
            { Script:Invoke-Target -Params @{ Tag = 'v1.0; rm -rf /' } } | Should -Throw
        }

        It "accepts a Tag containing a slash, matching Assert-BaselineTrusted's ref-name charset" {
            # The two scripts previously disagreed: a `/`-bearing tag passed the
            # Step 4 gate and then failed ValidatePattern here.
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
            }
            $r = Script:Invoke-Target -Params @{ Tag = 'release/v26.10.02.1939' }
            $r.BaselineTag | Should -Be 'release/v26.10.02.1939'
        }
    }

    Context "Repository root local-path validation (hard refusal)" {

        # Gate 0. `$repoRoot` feeds `git -C` for the origin check, the tag gate,
        # `worktree add`, `ls-tree` and `show`. A redirected root means
        # `.build/Build.ps1` runs from an object store the operator never chose.
        # Assert-BaselineTrusted's equivalent gate does NOT cover this path --
        # the two scripts default `RepositoryRoot` differently.

        It "rejects an unsafe default current directory before invoking Git: <CurrentPath>" -ForEach @(
            @{ CurrentPath = '\\attacker.example\share\repo' }
            @{ CurrentPath = 'FileSystem::C:\repo' }
            @{ CurrentPath = 'HKLM:\SOFTWARE' }
        ) {
            $env:MockGitCurrentPath = $CurrentPath
            Mock -CommandName Get-Location -MockWith { [PSCustomObject]@{ Path = $env:MockGitCurrentPath } }

            { Script:Invoke-Target -Params @{ RepositoryRoot = '' } } |
                Should -Throw '*current directory failed local-path validation*'

            $env:MockGitCalls | Should -BeNullOrEmpty
        }

        It "anchors default repository discovery to the validated current directory" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
            }
            $env:MockGitCurrentPath = $Script:repoRoot
            Mock -CommandName Get-Location -MockWith { [PSCustomObject]@{ Path = $env:MockGitCurrentPath } }

            $result = Script:Invoke-Target -Params @{ RepositoryRoot = '' }

            $result.Status | Should -Be 'Ok'
            ($env:MockGitCalls -split "`n")[0] |
                Should -Be "--no-pager -C $Script:repoRoot rev-parse --show-toplevel"
        }

        It "rejects a junction-backed default current directory before invoking Git" {
            $junction = Join-Path -Path $Script:fixtureRoot -ChildPath 'current-location-link'
            New-Item -Path $junction -ItemType Junction -Target $Script:repoRoot | Out-Null
            $env:MockGitCurrentPath = $junction
            Mock -CommandName Get-Location -MockWith { [PSCustomObject]@{ Path = $env:MockGitCurrentPath } }
            try {
                { Script:Invoke-Target -Params @{ RepositoryRoot = '' } } |
                    Should -Throw '*current directory failed local-path validation*'

                $env:MockGitCalls | Should -BeNullOrEmpty
            } finally {
                Remove-Item -LiteralPath $junction -Force
            }
        }

        It "refuses a UNC repository root" {
            { Script:Invoke-Target -Params @{ RepositoryRoot = '\\attacker.example\share\repo' } } |
                Should -Throw '*failed local-path validation*'
        }

        It "refuses a device-namespace repository root" {
            { Script:Invoke-Target -Params @{ RepositoryRoot = '\\?\C:\repo' } } |
                Should -Throw '*failed local-path validation*'
        }

        It "refuses a provider-qualified repository root" {
            { Script:Invoke-Target -Params @{ RepositoryRoot = 'FileSystem::C:\repo' } } |
                Should -Throw '*failed local-path validation*'
        }

        It "refuses a repository root that does not exist" {
            { Script:Invoke-Target -Params @{ RepositoryRoot = (Join-Path $Script:repoRoot 'does-not-exist-4b71') } } |
                Should -Throw '*failed local-path validation*'
        }

        It "never materializes a worktree when the repository root is rejected" {
            { Script:Invoke-Target -Params @{ RepositoryRoot = '\\attacker.example\share\repo' } } | Should -Throw
            $env:MockGitWorktreeAddCalled | Should -Be '0' -Because "gate 0 must refuse before any git invocation that could materialize baseline code"
        }
    }

    Context "Self-enforcing baseline gate (tag must resolve to CommitSha)" {
        # Assert-BaselineTrusted.ps1 is the documented Step 4 gate, but nothing
        # proves to this script that it ran. Without an independent check here,
        # ANY 40-hex commit object already in the clone -- a `gh pr checkout`
        # commit, a fetched pull/N/head, a stale review branch -- would be
        # materialized and have `.build/Build.ps1` executed from it.

        It "refuses to build when the tag resolves to a different commit" {
            $env:MockGitTagSha = '2222222222222222222222222222222222222222'
            { Script:Invoke-Target } | Should -Throw '*unverified tag/commit pairing*'
        }

        It "refuses to build when the tag does not resolve at all" {
            $env:MockGitTagExit = '1'
            $env:MockGitTagSha = ''
            { Script:Invoke-Target } | Should -Throw '*does not resolve to a commit*'
        }

        It "never materializes a worktree when the tag/commit pairing is rejected" {
            $env:MockGitTagSha = '2222222222222222222222222222222222222222'
            { Script:Invoke-Target } | Should -Throw
            $env:MockGitWorktreeAddCalled | Should -Be '0' -Because "the gate must refuse BEFORE git worktree add, or baseline code is already on disk"
        }

        It "does not consult the cache before the gate has passed" {
            # A cache hit must not be able to short-circuit the gate: the cached
            # XML was produced by a build, so honoring it for an unverified
            # pairing would still return baseline-derived data.
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
            }
            $env:MockGitTagSha = '2222222222222222222222222222222222222222'
            { Script:Invoke-Target } | Should -Throw '*unverified tag/commit pairing*'
        }

        It "compares the tag SHA case-insensitively" {
            $env:MockGitTagSha = $Script:sha.ToUpperInvariant()
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
            }
            $r = Script:Invoke-Target
            $r.Status | Should -Be 'Ok' -Because "git may echo a SHA in either case; only a genuine mismatch is a refusal"
        }
    }

    Context "Repository allowlist (hard refusal)" {

        It "refuses when origin points at a repository other than microsoft/CSS-Exchange" {
            $env:MockGitRemote = 'https://github.com/attacker/CSS-Exchange.git'
            { Script:Invoke-Target } | Should -Throw '*requires a microsoft/CSS-Exchange checkout*'
        }

        It "refuses when origin is a look-alike host" {
            $env:MockGitRemote = 'https://github.com.evil.test/microsoft/CSS-Exchange.git'
            { Script:Invoke-Target } | Should -Throw '*requires a microsoft/CSS-Exchange checkout*'
        }

        It "refuses when the origin lookup itself fails" {
            $env:MockGitRemoteExit = '1'
            $env:MockGitRemote = ''
            { Script:Invoke-Target } | Should -Throw '*requires a microsoft/CSS-Exchange checkout*'
        }

        It "accepts the ssh and git@ remote forms" {
            foreach ($remote in @(
                    'git@github.com:microsoft/CSS-Exchange.git',
                    'ssh://git@github.com/microsoft/CSS-Exchange.git',
                    'https://github.com/microsoft/CSS-Exchange')) {
                $null = Script:New-IsolatedLocalAppData
                $env:MockGitRemote = $remote
                $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                    'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
                }
                $r = Script:Invoke-Target
                $r.Status | Should -Be 'Ok' -Because "remote form '$remote' is allowlisted"
            }
        }
    }

    Context "Cache root local-path validation (hard refusal)" {

        It "refuses a UNC LOCALAPPDATA before touching the filesystem" {
            $env:LOCALAPPDATA = '\\attacker.example\share\AppData\Local'
            { Script:Invoke-Target } | Should -Throw '*failed local-path validation*'
        }

        It "refuses an NT device-namespace LOCALAPPDATA" {
            $env:LOCALAPPDATA = '\\?\C:\Users\someone\AppData\Local'
            { Script:Invoke-Target } | Should -Throw '*failed local-path validation*'
        }

        It "refuses a provider-qualified LOCALAPPDATA" {
            $env:LOCALAPPDATA = 'FileSystem::C:\Users\someone\AppData\Local'
            { Script:Invoke-Target } | Should -Throw '*failed local-path validation*'
        }

        It "refuses a pre-existing junction on the <Label>" -ForEach @(
            @{ Label = 'SHA directory'; RelativePath = '' }
            @{ Label = 'dependency XML'; RelativePath = 'dependencyHashtable.xml' }
            @{ Label = 'access marker'; RelativePath = '.last-accessed' }
        ) {
            $cacheDir = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
            }
            $link = if ([string]::IsNullOrEmpty($RelativePath)) {
                $cacheDir
            } else {
                Join-Path -Path $cacheDir -ChildPath $RelativePath
            }
            $target = Join-Path -Path $Script:fixtureRoot -ChildPath ([guid]::NewGuid().ToString('N'))
            if (Test-Path -LiteralPath $link -PathType Container) {
                [System.IO.Directory]::Move($link, $target)
            } else {
                New-Item -Path $target -ItemType Directory | Out-Null
                if (Test-Path -LiteralPath $link -PathType Leaf) {
                    Remove-Item -LiteralPath $link -Force
                }
            }
            try {
                New-Item -Path $link -ItemType Junction -Target $target | Out-Null
                { Script:Invoke-Target } | Should -Throw '*cache path*failed local-path validation*'
                Test-Path -LiteralPath (Join-Path -Path $target -ChildPath '.last-accessed') | Should -BeFalse
                $env:MockGitWorktreeAddCalled | Should -Be '0'
            } finally {
                if (Test-Path -LiteralPath $link) {
                    [System.IO.Directory]::Delete($link)
                }
            }
        }
    }

    Context "Cache-hit path" {

        It "returns MaterializationSource 'Cache' and Status 'Ok' without building" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @('Shared/ErrorMonitorFunctions.ps1')
                'Shared/ErrorMonitorFunctions.ps1'            = @()
            }
            $r = Script:Invoke-Target
            $r.MaterializationSource | Should -Be 'Cache'
            $r.Status | Should -Be 'Ok'
            $env:MockGitWorktreeAddCalled | Should -Be '0' -Because "a cache hit must not materialize a worktree"
        }

        It "returns exactly one object" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
            }
            $r = @(Script:Invoke-Target)
            $r.Count | Should -Be 1 -Because "native command output must never leak into the return value"
        }

        It "echoes the normalized SHA and the supplied Tag" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
            }
            $r = Script:Invoke-Target -Params @{ CommitSha = $Script:sha.ToUpperInvariant() }
            $r.BaselineSha | Should -BeExactly $Script:sha
            $r.BaselineTag | Should -BeExactly $Script:tag
        }

        It "writes a .last-accessed marker on a cache hit" {
            $dir = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
            }
            $null = Script:Invoke-Target
            Test-Path -LiteralPath (Join-Path $dir '.last-accessed') | Should -BeTrue
        }

        It "ignores a cache entry whose metadata SHA does not match" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -MetaSha ('2' * 40) -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
            }
            # Falls through to the build branch, where the mocked worktree add fails.
            { Script:Invoke-Target } | Should -Throw '*git worktree add failed*'
            $env:MockGitWorktreeAddCalled | Should -Be '1'
        }

        It "ignores a cache entry whose metadata SchemaVersion is not 1" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -SchemaVersion 2 -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
            }
            { Script:Invoke-Target } | Should -Throw '*git worktree add failed*'
        }
    }

    Context "Transitive dependency traversal" {

        It "reports the completion-helper dependency for <Label>" -ForEach @(
            @{ Label = 'the exact helper leaf'; Dependency = 'Diagnostics/HealthChecker/Helpers/Get-ErrorsThatOccurred.ps1'; Expected = $true }
            @{ Label = 'a different helper'; Dependency = 'Shared/ErrorMonitorFunctions.ps1'; Expected = $false }
            @{ Label = 'a directory with the helper name'; Dependency = 'Other/Get-ErrorsThatOccurred.ps1/Helper.ps1'; Expected = $false }
        ) {
            $env:MockGitTree += "`n$Dependency"
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @($Dependency)
                $Dependency                                   = @()
            }
            $r = Script:Invoke-Target

            $r.HasErrorHelper | Should -Be $Expected
        }

        It "walks the graph transitively, not just direct dependencies" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1'                  = @('Diagnostics/HealthChecker/Helpers/Get-ErrorsThatOccurred.ps1')
                'Diagnostics/HealthChecker/Helpers/Get-ErrorsThatOccurred.ps1' = @('Shared/ErrorMonitorFunctions.ps1')
                'Shared/ErrorMonitorFunctions.ps1'                             = @('Shared/LoggerFunctions.ps1')
                'Shared/LoggerFunctions.ps1'                                   = @()
            }
            $r = Script:Invoke-Target
            $r.AllDeps | Should -Contain 'Shared/LoggerFunctions.ps1' -Because "level-3 transitive dependencies must be included"
            $r.AllDeps.Count | Should -Be 4
            $r.HasErrorHelper | Should -BeTrue
        }

        It "includes the entry file itself in AllDeps" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @('Shared/LoggerFunctions.ps1')
                'Shared/LoggerFunctions.ps1'                  = @()
            }
            $r = Script:Invoke-Target
            $r.AllDeps | Should -Contain 'Diagnostics/HealthChecker/HealthChecker.ps1'
        }

        It "terminates on a cyclic dependency graph" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @('Shared/LoggerFunctions.ps1')
                'Shared/LoggerFunctions.ps1'                  = @('Diagnostics/HealthChecker/HealthChecker.ps1')
            }
            $r = Script:Invoke-Target
            $r.AllDeps.Count | Should -Be 2
        }
    }

    Context "Path normalization" {

        It "normalizes absolute worktree-rooted graph keys to repo-relative forward-slash paths" {
            $wt = 'C:\Users\someone\AppData\Local\Temp\css-exchange-analyze-deadbeef'
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                "$wt\Diagnostics\HealthChecker\HealthChecker.ps1" = @("$wt\Shared\ErrorMonitorFunctions.ps1")
                "$wt\Shared\ErrorMonitorFunctions.ps1"            = @()
            }
            $r = Script:Invoke-Target
            $r.Entry | Should -BeExactly 'Diagnostics/HealthChecker/HealthChecker.ps1'
            $r.AllDeps | Should -Contain 'Shared/ErrorMonitorFunctions.ps1'
            ($r.AllDeps | Where-Object { $_ -match '\\' }) | Should -BeNullOrEmpty -Because "every returned path must use forward slashes"
        }

        It "drops graph entries that have no match in the pinned tree" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @('dist/GeneratedArtifact.ps1')
                'dist/GeneratedArtifact.ps1'                  = @()
            }
            $r = Script:Invoke-Target 3>$null
            $r.AllDeps | Should -Not -Contain 'dist/GeneratedArtifact.ps1'
            $r.AllDeps.Count | Should -Be 1
            $r.HasErrorHelper | Should -BeFalse
        }

        It "throws when git ls-tree fails" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
            }
            $env:MockGitTreeExit = '1'
            { Script:Invoke-Target } | Should -Throw '*git ls-tree failed*'
        }
    }

    Context "PartialGraph fallback" {

        It "falls back to tree discovery and reports PartialGraph when no graph key matches" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Shared/ErrorMonitorFunctions.ps1' = @()
            }
            $r = Script:Invoke-Target 3>$null
            $r.Status | Should -Be 'PartialGraph'
            $r.StatusDetail | Should -Not -BeNullOrEmpty
            $r.Entry | Should -BeExactly 'Diagnostics/HealthChecker/HealthChecker.ps1'
            $r.AllDeps.Count | Should -Be 1
        }

        It "throws when the leaf name matches no graph key and no unique tree entry" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Shared/ErrorMonitorFunctions.ps1' = @()
            }
            $env:MockGitTree = 'Shared/ErrorMonitorFunctions.ps1'
            { Script:Invoke-Target } | Should -Throw '*no unique tree entry*'
        }

        It "throws when more than one graph key matches the leaf name" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
                'Other/Copy/HealthChecker.ps1'                = @()
            }
            { Script:Invoke-Target } | Should -Throw '*Multiple graph keys match*'
        }

        It "reports graph ambiguity before consulting git ls-tree" {
            # Ambiguity is the more fundamental problem, and resolving it does
            # not need the tree listing at all. If the ordering regresses, a
            # simultaneously-failing `ls-tree` masks the real cause behind an
            # incidental 'git ls-tree failed' message.
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/HealthChecker.ps1' = @()
                'Other/Copy/HealthChecker.ps1'                = @()
            }
            $env:MockGitTreeExit = '1'
            { Script:Invoke-Target } | Should -Throw '*Multiple graph keys match*'
        }

        It "matches the leaf name case-sensitively" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -DependencyGraph @{
                'Diagnostics/HealthChecker/healthchecker.ps1' = @()
            }
            $env:MockGitTree = 'Diagnostics/HealthChecker/healthchecker.ps1'
            # Neither the graph key nor the tree entry matches 'HealthChecker.ps1' exactly.
            { Script:Invoke-Target } | Should -Throw '*no unique tree entry*'
        }
    }

    Context "Corrupt cache recovery" {

        It "quarantines a cache entry whose XML cannot be imported" {
            $null = Script:New-CacheEntry -LocalAppData $env:LOCALAPPDATA -Sha $Script:sha -CorruptXml -DependencyGraph @{}
            $cacheRoot = Join-Path $env:LOCALAPPDATA 'CSS-Exchange\dependency-cache'
            # Import fails -> quarantine -> fall through to build -> mocked add fails.
            { Script:Invoke-Target } | Should -Throw '*git worktree add failed*'
            $quarantined = @(Get-ChildItem -LiteralPath $cacheRoot -Directory | Where-Object { $_.Name -like "$Script:sha.corrupt.*" })
            $quarantined.Count | Should -Be 1 -Because "a corrupt entry must be moved aside so later runs do not keep hitting it"
            Test-Path -LiteralPath (Join-Path $cacheRoot $Script:sha) | Should -BeFalse
        }
    }

    Context "Build-path safety in tests" {

        It "never runs a real build because worktree add is mocked to fail" {
            # No cache entry at all -> straight to the build branch.
            { Script:Invoke-Target } | Should -Throw '*git worktree add failed*'
            $env:MockGitWorktreeAddCalled | Should -Be '1'
        }

        It "accepts valid XML after a nonzero build exit with caller-local native preference <NativePreference>" -ForEach @(
            @{ NativePreference = $true }
            @{ NativePreference = $false }
        ) {
            $env:MockGitWorktreeAddExit = '0'
            $result = & {
                param([bool]$Preference)
                $PSNativeCommandUseErrorActionPreference = $Preference
                $ErrorActionPreference = 'Stop'
                $splat = @{
                    CommitSha      = $Script:sha
                    Tag            = $Script:tag
                    ScriptLeafName = 'HealthChecker.ps1'
                    RepositoryRoot = $Script:repoRoot
                }
                $value = & $Script:scriptPath @splat
                $PSNativeCommandUseErrorActionPreference | Should -Be $Preference
                return $value
            } -Preference $NativePreference
            $result.Status | Should -Be 'Ok'
            $result.MaterializationSource | Should -Be 'BuildAndCached'
            Test-Path -LiteralPath $env:MockGitWorktreeRoot | Should -BeFalse
        }

        It "warns with the retained worktree path when cleanup fails" {
            $env:MockGitWorktreeAddExit = '0'
            $env:MockGitWorktreeRemoveExit = '1'
            $cleanupWarnings = @()
            $splat = @{
                CommitSha       = $Script:sha
                Tag             = $Script:tag
                ScriptLeafName  = 'HealthChecker.ps1'
                RepositoryRoot  = $Script:repoRoot
                WarningVariable = 'cleanupWarnings'
                WarningAction   = 'SilentlyContinue'
            }
            $result = & $Script:scriptPath @splat
            $result.Status | Should -Be 'Ok'
            ($cleanupWarnings -join "`n") | Should -Match 'Failed to remove scratch worktree'
            ($cleanupWarnings -join "`n") | Should -Match ([regex]::Escape($env:MockGitWorktreeRoot))
            Test-Path -LiteralPath $env:MockGitWorktreeRoot | Should -BeTrue
        }

        It "does not inspect a redirected cache winner that first appears during the build" {
            $env:MockGitWorktreeAddExit = '0'
            $env:MockGitNewCacheWinner = '1'
            $cacheRoot = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'CSS-Exchange\dependency-cache'
            $cacheWarnings = @()
            $splat = @{
                CommitSha       = $Script:sha
                Tag             = $Script:tag
                ScriptLeafName  = 'HealthChecker.ps1'
                RepositoryRoot  = $Script:repoRoot
                WarningVariable = 'cacheWarnings'
                WarningAction   = 'SilentlyContinue'
            }
            try {
                $result = & $Script:scriptPath @splat
                $result.Status | Should -Be 'Ok'
                $result.MaterializationSource | Should -Be 'BuildOnly'
                ($cacheWarnings -join "`n") | Should -Match 'Cache winner path.*failed local-path validation'
            } finally {
                Get-ChildItem -LiteralPath $cacheRoot -Directory -Attributes ReparsePoint |
                    ForEach-Object { [System.IO.Directory]::Delete($_.FullName) }
            }
        }

        It "preserves the build failure when cleanup fails with warning action <Action>" -ForEach @(
            @{ Action = 'SilentlyContinue' }
            @{ Action = 'Stop' }
        ) {
            $env:MockGitWorktreeAddExit = '0'
            $env:MockGitWorktreeRemoveExit = '1'
            $env:MockGitBuildXmlMissing = '1'
            $cleanupWarnings = @()
            $message = $null
            $splat = @{
                CommitSha       = $Script:sha
                Tag             = $Script:tag
                ScriptLeafName  = 'HealthChecker.ps1'
                RepositoryRoot  = $Script:repoRoot
                WarningVariable = 'cleanupWarnings'
                WarningAction   = $Action
            }
            try {
                $null = & $Script:scriptPath @splat
            } catch {
                $message = $_.Exception.Message
            }
            $message | Should -Match 'did not produce dependencyHashtable.xml'
            ($cleanupWarnings -join "`n") | Should -Match 'Failed to remove scratch worktree'
        }
    }
}
