# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Tests for `.github/skills/analyze-debug-files/Assert-BaselineTrusted.ps1`.
#
# This helper is the gate that stands between an untrusted release-tag lookup
# result and `Get-BaselineDependencyGraph.ps1`, which executes `.build/Build.ps1`
# FROM THE BASELINE COMMIT. Every gate must stay a hard refusal; a regression
# that downgrades one into a warning would let unverified code execute.

[CmdletBinding()]
param()

Describe "Assert-BaselineTrusted" {

    BeforeAll {
        $Script:repoRoot = (Get-Item "$PSScriptRoot\..\..\..\..").FullName
        $Script:scriptPath = Join-Path $Script:repoRoot '.github\skills\analyze-debug-files\Assert-BaselineTrusted.ps1'
        $Script:goodSha = '1e55f00d9ae4578f15f5250811a552dd34a55f69'
        $Script:goodTag = 'v26.10.02.1939'

        # Mock git, driven by environment variables so no $global: variables are
        # needed (PSAvoidGlobalVars). `& cmd /c exit N` drives $LASTEXITCODE,
        # which the helper checks after every native call.
        function global:git {
            $line = ($args | ForEach-Object { [string]$_ }) -join ' '
            if ($line -match 'config\s+--get\s+remote\.origin\.url') {
                & cmd /c exit ([int]$env:MockGitOriginExit)
                return $env:MockGitOrigin
            }
            if ($line -match 'cat-file\s+-e') {
                & cmd /c exit ([int]$env:MockGitCommitExistsExit)
                return $null
            }
            if ($line -match 'rev-parse\s+--verify') {
                & cmd /c exit ([int]$env:MockGitTagPeelExit)
                return $env:MockGitTagPeel
            }
            & cmd /c exit 0
            return $null
        }

        function Script:Reset-MockGit {
            $env:MockGitOrigin = 'https://github.com/microsoft/CSS-Exchange.git'
            $env:MockGitOriginExit = '0'
            $env:MockGitCommitExistsExit = '0'
            $env:MockGitTagPeel = $Script:goodSha
            $env:MockGitTagPeelExit = '0'
        }

        function Script:New-Baseline {
            param([hashtable]$Override)
            $b = [PSCustomObject]@{
                Script             = 'HealthChecker.ps1'
                Version            = '26.10.02.1907'
                Repository         = 'microsoft/CSS-Exchange'
                ConfirmedTag       = $Script:goodTag
                ConfirmedCommitSha = $Script:goodSha
                SHA256Hash         = ('A' * 64)
                Status             = 'match-earliest'
            }
            if ($Override) { foreach ($k in $Override.Keys) { $b.$k = $Override[$k] } }
            return $b
        }

        function Script:Invoke-Target {
            param([hashtable]$Override, [string]$RepositoryRoot = $Script:repoRoot)
            return & $Script:scriptPath -Baseline (Script:New-Baseline -Override $Override) -RepositoryRoot $RepositoryRoot
        }
    }

    AfterAll {
        Remove-Item -LiteralPath 'function:\global:git' -ErrorAction SilentlyContinue
        foreach ($n in @('MockGitOrigin', 'MockGitOriginExit', 'MockGitCommitExistsExit',
                'MockGitTagPeel', 'MockGitTagPeelExit')) {
            Remove-Item -LiteralPath "env:\$n" -ErrorAction SilentlyContinue
        }
    }

    BeforeEach {
        Script:Reset-MockGit
    }

    Context "Gate 0 - RepositoryRoot local-path validation" {

        # Gates 5-7 read repository state through `git -C $RepositoryRoot`. If
        # that path is UNC, SUBST-aliased, device-namespace, or
        # reparse-redirected, those gates vet a repository the operator never
        # chose -- and this script's whole purpose is to decide whether baseline
        # code may be executed.

        It "refuses a UNC repository root" {
            { Script:Invoke-Target -RepositoryRoot '\\attacker.example\share\repo' } |
                Should -Throw '*failed local-path validation*'
        }

        It "refuses a device-namespace repository root" {
            { Script:Invoke-Target -RepositoryRoot '\\?\C:\repo' } |
                Should -Throw '*failed local-path validation*'
        }

        It "refuses a provider-qualified repository root" {
            { Script:Invoke-Target -RepositoryRoot 'FileSystem::C:\repo' } |
                Should -Throw '*failed local-path validation*'
        }

        It "refuses a repository root that does not exist" {
            { Script:Invoke-Target -RepositoryRoot (Join-Path $Script:repoRoot 'does-not-exist-9e3f') } |
                Should -Throw '*failed local-path validation*'
        }

        It "refuses an empty repository root" {
            { Script:Invoke-Target -RepositoryRoot '' } | Should -Throw
        }

        It "accepts the real repository root" {
            { Script:Invoke-Target } | Should -Not -Throw
        }
    }

    Context "Gate 1 - Status" {

        It "accepts match-earliest" {
            { Script:Invoke-Target -Override @{ Status = 'match-earliest' } } | Should -Not -Throw
        }

        It "accepts match-possibly-not-earliest" {
            { Script:Invoke-Target -Override @{ Status = 'match-possibly-not-earliest' } } | Should -Not -Throw
        }

        It "refuses a not-found status" {
            { Script:Invoke-Target -Override @{ Status = 'not-found-complete' } } |
                Should -Throw '*did not return a matched release*'
        }

        It "refuses an inconclusive status" {
            { Script:Invoke-Target -Override @{ Status = 'not-found-inconclusive' } } |
                Should -Throw '*did not return a matched release*'
        }

        It "refuses a null status" {
            { Script:Invoke-Target -Override @{ Status = $null } } |
                Should -Throw '*did not return a matched release*'
        }
    }

    Context "Gate 2 - ConfirmedTag presence" {

        It "refuses a null tag" {
            { Script:Invoke-Target -Override @{ ConfirmedTag = $null } } | Should -Throw '*missing ConfirmedTag*'
        }

        It "refuses a whitespace-only tag" {
            { Script:Invoke-Target -Override @{ ConfirmedTag = '   ' } } | Should -Throw '*missing ConfirmedTag*'
        }
    }

    Context "Gate 3 - ConfirmedCommitSha shape" {

        It "refuses a short SHA" {
            { Script:Invoke-Target -Override @{ ConfirmedCommitSha = '1e55f00' } } |
                Should -Throw '*not a 40-char hex SHA*'
        }

        It "refuses a non-hex SHA" {
            { Script:Invoke-Target -Override @{ ConfirmedCommitSha = ('z' * 40) } } |
                Should -Throw '*not a 40-char hex SHA*'
        }

        It "refuses a null SHA" {
            { Script:Invoke-Target -Override @{ ConfirmedCommitSha = $null } } |
                Should -Throw '*not a 40-char hex SHA*'
        }
    }

    Context "Gate 4 - Repository allowlist" {

        It "refuses a fork" {
            { Script:Invoke-Target -Override @{ Repository = 'attacker/CSS-Exchange' } } |
                Should -Throw '*restricted to microsoft/CSS-Exchange*'
        }

        It "accepts a case-variant of the allowlisted repository" {
            # GitHub owner/repo names are case-insensitive for routing, so
            # 'Microsoft/css-exchange' IS the allowlisted repository. PowerShell's
            # -ne is case-insensitive by default, which is the intended behavior
            # here; rejecting the variant would be a false negative.
            { Script:Invoke-Target -Override @{ Repository = 'Microsoft/css-exchange' } } | Should -Not -Throw
        }

        It "refuses a repository whose name merely contains the allowlisted one" {
            { Script:Invoke-Target -Override @{ Repository = 'attacker/microsoft-CSS-Exchange' } } |
                Should -Throw '*restricted to microsoft/CSS-Exchange*'
        }
    }

    Context "Gate 5 - local origin URL" {

        It "refuses when the local origin points elsewhere" {
            $env:MockGitOrigin = 'https://github.com/attacker/CSS-Exchange.git'
            { Script:Invoke-Target } | Should -Throw '*Local origin does not point to*'
        }

        It "refuses a look-alike host" {
            $env:MockGitOrigin = 'https://github.com.evil.test/microsoft/CSS-Exchange.git'
            { Script:Invoke-Target } | Should -Throw '*Local origin does not point to*'
        }

        It "refuses when the origin lookup fails" {
            $env:MockGitOriginExit = '1'
            $env:MockGitOrigin = ''
            { Script:Invoke-Target } | Should -Throw '*Could not read local git origin URL*'
        }

        It "accepts the git@ and ssh:// forms" {
            foreach ($o in @('git@github.com:microsoft/CSS-Exchange.git',
                    'ssh://git@github.com/microsoft/CSS-Exchange.git',
                    'https://github.com/microsoft/CSS-Exchange')) {
                $env:MockGitOrigin = $o
                { Script:Invoke-Target } | Should -Not -Throw -Because "'$o' is an allowlisted remote form"
            }
        }
    }

    Context "Gate 6 - commit present locally" {

        It "refuses when the commit object is missing" {
            $env:MockGitCommitExistsExit = '1'
            { Script:Invoke-Target } | Should -Throw '*is not present locally*'
        }
    }

    Context "Gate 7 - tag resolves to the claimed commit" {

        It "refuses a tag containing characters illegal in a git ref" {
            { Script:Invoke-Target -Override @{ ConfirmedTag = 'v1.0;rm -rf' } } |
                Should -Throw '*not permitted in a git ref*'
        }

        It "refuses when the tag does not resolve locally" {
            $env:MockGitTagPeelExit = '1'
            $env:MockGitTagPeel = ''
            { Script:Invoke-Target } | Should -Throw '*does not resolve to a commit locally*'
        }

        It "refuses when the tag peels to a different commit" {
            $env:MockGitTagPeel = '2222222222222222222222222222222222222222'
            { Script:Invoke-Target } | Should -Throw '*refusing to proceed against an unverified pairing*'
        }

        It "accepts a case-differing but equal peel result" {
            $env:MockGitTagPeel = $Script:goodSha.ToUpperInvariant()
            { Script:Invoke-Target } | Should -Not -Throw
        }
    }

    Context "Happy path" {

        It "returns nothing when every gate passes" {
            $result = Script:Invoke-Target
            $result | Should -BeNullOrEmpty -Because "the helper asserts; it must not emit to the pipeline"
        }
    }
}
