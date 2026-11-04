# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Describe 'Find-ReleaseTagForScriptVersion' {
    BeforeAll {
        $Script:helperPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Find-ReleaseTagForScriptVersion.ps1'
        $Script:hash = 'A' * 64
        $Script:commitSha = '1' * 40

        function gh {
            throw 'Unexpected gh invocation without a mock.'
        }

        function Get-TestRelease {
            param(
                [string]$Tag,
                [bool]$Draft = $false,
                [bool]$Prerelease = $false
            )

            [PSCustomObject]@{
                tagName      = $Tag
                publishedAt  = '2026-03-20T00:00:00Z'
                isDraft      = $Draft
                isPrerelease = $Prerelease
            }
        }

        function Invoke-Resolver {
            param(
                [switch]$DefaultWorkFolder,
                [int]$MaxCandidates = 30,
                [string]$Repository = 'microsoft/CSS-Exchange'
            )

            $resolverArguments = @{
                ScriptName    = 'HealthChecker'
                Version       = '26.03.12.1424'
                MaxCandidates = $MaxCandidates
                Repository    = $Repository
            }
            if (-not $DefaultWorkFolder) {
                $resolverArguments.WorkFolder = $Script:workFolder
            }
            & $Script:helperPath @resolverArguments
        }
    }

    BeforeEach {
        $Script:originalTemp = $env:TEMP
        $Script:originalHost = $env:GH_HOST
        $Script:caseRoot = (New-Item -ItemType Directory -Path (Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N')))).FullName
        $Script:workFolder = (New-Item -ItemType Directory -Path (Join-Path -Path $Script:caseRoot -ChildPath 'caller')).FullName
        $env:TEMP = $Script:caseRoot
        $env:GH_HOST = 'enterprise.example.invalid'
        $Script:matchingCsv = "File,Version,SHA256Hash`nHealthChecker.ps1,26.03.12.1424,$Script:hash"
        $Script:mockState = @{
            Calls         = [System.Collections.Generic.List[object]]::new()
            Downloads     = [System.Collections.Generic.List[string]]::new()
            Paths         = [System.Collections.Generic.List[string]]::new()
            Releases      = @(
                Get-TestRelease -Tag 'v26.03.12.1500'
                Get-TestRelease -Tag 'v26.03.13.1500'
                Get-TestRelease -Tag 'v26.03.14.1500'
            )
            ReleaseJson   = $null
            ListExit      = 0
            ListFailure   = 'Release enumeration failed'
            CsvByTag      = @{}
            DownloadExits = @{}
            MissingTags   = @()
            ApiExit       = 0
            ApiOutput     = $Script:commitSha
            DefaultCsv    = $Script:matchingCsv
        }
        $state = $Script:mockState

        Mock -CommandName gh -MockWith ({
                $state.Calls.Add(@($args))
                if ($args[0] -eq 'release' -and $args[1] -eq 'list') {
                    & $env:ComSpec /c exit $state.ListExit
                    if ($state.ListExit -ne 0) { return $state.ListFailure }
                    if ($null -ne $state.ReleaseJson) { return $state.ReleaseJson }
                    return ConvertTo-Json -InputObject @($state.Releases) -Depth 4 -Compress
                }
                if ($args[0] -eq 'release' -and $args[1] -eq 'download') {
                    $tag = $args[2]
                    $path = $args[[array]::IndexOf($args, '-O') + 1]
                    $state.Downloads.Add($tag)
                    $state.Paths.Add($path)
                    if ($state.MissingTags -notcontains $tag) {
                        $csv = if ($state.CsvByTag.ContainsKey($tag)) { $state.CsvByTag[$tag] } else { $state.DefaultCsv }
                        Set-Content -LiteralPath $path -Value $csv -Encoding utf8
                    }
                    $exitCode = if ($state.DownloadExits.ContainsKey($tag)) { $state.DownloadExits[$tag] } else { 0 }
                    & $env:ComSpec /c exit $exitCode
                    if ($exitCode -ne 0) { return 'Asset unavailable' }
                    return
                }
                if ($args[0] -eq 'api') {
                    & $env:ComSpec /c exit $state.ApiExit
                    return $state.ApiOutput
                }
                throw "Unexpected gh arguments: $($args -join ' ')"
            }.GetNewClosure())
    }

    AfterEach {
        $env:TEMP = $Script:originalTemp
        $env:GH_HOST = $Script:originalHost
        Remove-Item -LiteralPath $Script:caseRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'walks stable date tags in ascending order and stops at the earliest exact match' {
        $Script:mockState.Releases = @(
            Get-TestRelease -Tag 'v26.03.14.1500'
            Get-TestRelease -Tag 'v26.03.12.1500'
            Get-TestRelease -Tag 'v26.03.13.1500'
            Get-TestRelease -Tag 'v26.03.12.1400'
            Get-TestRelease -Tag 'v26.02.30.1500'
            Get-TestRelease -Tag 'other-tag'
            Get-TestRelease -Tag 'v26.03.12.1430' -Draft $true
            Get-TestRelease -Tag 'v26.03.12.1440' -Prerelease $true
        )
        $Script:mockState.CsvByTag['v26.03.12.1500'] = "File,Version,SHA256Hash`nHealthChecker.ps1,26.03.12.1400,$Script:hash"

        $result = Invoke-Resolver

        $result.Status | Should -Be 'match-earliest'
        $result.Script | Should -Be 'HealthChecker.ps1'
        $result.Version | Should -Be '26.03.12.1424'
        $result.Repository | Should -Be 'microsoft/CSS-Exchange'
        $result.ConfirmedTag | Should -Be 'v26.03.13.1500'
        $result.ConfirmedCommitSha | Should -Be $Script:commitSha
        $result.SHA256Hash | Should -Be $Script:hash
        $result.EarlierGaps | Should -Be 0
        $result.WindowExhausted | Should -BeFalse
        $result.Tried.Status | Should -Be @('version-mismatch', 'match')
        $Script:mockState.Downloads.ToArray() | Should -Be @('v26.03.12.1500', 'v26.03.13.1500')
    }

    It 'treats a clean missing file as evidence rather than a gap' {
        $Script:mockState.CsvByTag['v26.03.12.1500'] = "File,Version,SHA256Hash`nOther.ps1,26.03.12.1424,$Script:hash"

        $result = Invoke-Resolver

        $result.Status | Should -Be 'match-earliest'
        $result.Tried.Status | Should -Be @('file-not-listed', 'match')
        $result.EarlierGaps | Should -Be 0
    }

    It 'does not claim earliest after an earlier download failure' {
        $PSNativeCommandUseErrorActionPreference = $true
        $Script:mockState.DownloadExits['v26.03.12.1500'] = 1

        $result = Invoke-Resolver

        $result.Status | Should -Be 'match-possibly-not-earliest'
        $result.ConfirmedTag | Should -Be 'v26.03.13.1500'
        $result.EarlierGaps | Should -Be 1
        $result.Tried.Status | Should -Be @('download-failed', 'match')
        $result.Tried[0].Detail | Should -Be 'Asset unavailable'
        $PSNativeCommandUseErrorActionPreference | Should -BeTrue
        foreach ($path in $Script:mockState.Paths) {
            Test-Path -LiteralPath $path | Should -BeFalse
        }
    }

    It 'rejects <Kind> CSV evidence and marks the later match uncertain' -TestCases @(
        @{ Kind = 'a wrong header'; Csv = "file,Version,SHA256Hash`nHealthChecker.ps1,26.03.12.1424,{hash}"; Status = 'csv-malformed'; Detail = 'header mismatch' },
        @{ Kind = 'an extra field'; Csv = "File,Version,SHA256Hash`nHealthChecker.ps1,26.03.12.1424,{hash},extra"; Status = 'csv-malformed'; Detail = 'row structure mismatch' },
        @{ Kind = 'unbalanced quotes'; Csv = "File,Version,SHA256Hash`n`"HealthChecker.ps1,26.03.12.1424,{hash}"; Status = 'csv-malformed'; Detail = 'row structure mismatch' },
        @{ Kind = 'leading field whitespace'; Csv = "File,Version,SHA256Hash`n HealthChecker.ps1,26.03.12.1424,{hash}"; Status = 'csv-malformed'; Detail = 'row structure mismatch' },
        @{ Kind = 'an empty record'; Csv = "File,Version,SHA256Hash`n,,"; Status = 'csv-malformed'; Detail = 'empty row' },
        @{ Kind = 'a header without rows'; Csv = 'File,Version,SHA256Hash'; Status = 'csv-malformed'; Detail = 'no rows' },
        @{ Kind = 'duplicate matching rows'; Csv = "File,Version,SHA256Hash`nHealthChecker.ps1,26.03.12.1424,{hash}`nHealthChecker.ps1,26.03.12.1424,{hash}"; Status = 'csv-malformed'; Detail = 'duplicate file rows' },
        @{ Kind = 'duplicate file rows with different versions'; Csv = "File,Version,SHA256Hash`nHealthChecker.ps1,26.03.12.1400,{hash}`nHealthChecker.ps1,26.03.12.1424,{hash}"; Status = 'csv-malformed'; Detail = 'duplicate file rows' },
        @{ Kind = 'an invalid calendar date'; Csv = "File,Version,SHA256Hash`nHealthChecker.ps1,26.02.30.1424,{hash}"; Status = 'csv-malformed-row'; Detail = '26.02.30.1424|' },
        @{ Kind = 'an invalid version format'; Csv = "File,Version,SHA256Hash`nHealthChecker.ps1,26.3.12.1424,{hash}"; Status = 'csv-malformed-row'; Detail = '26.3.12.1424|' },
        @{ Kind = 'an invalid hash'; Csv = "File,Version,SHA256Hash`nHealthChecker.ps1,26.03.12.1424,invalid"; Status = 'csv-malformed-row'; Detail = '26.03.12.1424|invalid' }
    ) {
        param($Csv, $Status, $Detail)

        $Script:mockState.CsvByTag['v26.03.12.1500'] = $Csv.Replace('{hash}', $Script:hash)

        $result = Invoke-Resolver

        $result.Status | Should -Be 'match-possibly-not-earliest'
        $result.ConfirmedTag | Should -Be 'v26.03.13.1500'
        $result.EarlierGaps | Should -Be 1
        $result.Tried[0].Status | Should -Be $Status
        $result.Tried[0].Detail | Should -BeLike "$Detail*"
        $result.Tried[1].Status | Should -Be 'match'
    }

    It 'accepts quoted columns and blank physical lines' {
        $Script:mockState.DefaultCsv = "`"File`",`"Version`",`"SHA256Hash`"`n`n`"HealthChecker.ps1`",`"26.03.12.1424`",`"$Script:hash`"`n"

        $result = Invoke-Resolver

        $result.Status | Should -Be 'match-earliest'
        $result.SHA256Hash | Should -Be $Script:hash
    }

    It 'does not normalize <Kind> filenames into an exact match' -TestCases @(
        @{ Kind = 'case differences'; FileName = 'HealthChecker.ps1'.ToLowerInvariant() },
        @{ Kind = 'invisible prefixes'; FileName = "$([char]0x200D)HealthChecker.ps1" }
    ) {
        param($FileName)

        $Script:mockState.Releases = @($Script:mockState.Releases[0])
        $Script:mockState.DefaultCsv = "File,Version,SHA256Hash`n$FileName,26.03.12.1424,$Script:hash"

        $result = Invoke-Resolver

        $result.Status | Should -Be 'not-found-complete'
        $result.Tried[0].Status | Should -Be 'file-not-listed'
        $result.ConfirmedTag | Should -BeNullOrEmpty
    }

    It 'records a gap when a successful download leaves no file' {
        $Script:mockState.MissingTags = @('v26.03.12.1500')

        $result = Invoke-Resolver

        $result.Status | Should -Be 'match-possibly-not-earliest'
        $result.Tried[0].Status | Should -Be 'csv-oversize-or-missing'
        $result.EarlierGaps | Should -Be 1
    }

    It 'distinguishes a complete search from candidate window exhaustion' -TestCases @(
        @{ Limit = 3; ExpectedStatus = 'not-found-complete'; Exhausted = $false },
        @{ Limit = 2; ExpectedStatus = 'not-found-inconclusive'; Exhausted = $true }
    ) {
        param($Limit, $ExpectedStatus, $Exhausted)

        $Script:mockState.DefaultCsv = "File,Version,SHA256Hash`nHealthChecker.ps1,26.03.12.1400,$Script:hash"

        $result = Invoke-Resolver -MaxCandidates $Limit

        $result.Status | Should -Be $ExpectedStatus
        $result.WindowExhausted | Should -Be $Exhausted
        $result.Tried.Count | Should -Be $Limit
        $result.EarlierGaps | Should -Be 0
        $result.ConfirmedTag | Should -BeNullOrEmpty
        $result.ConfirmedCommitSha | Should -BeNullOrEmpty
        $result.SHA256Hash | Should -BeNullOrEmpty
    }

    It 'does not mark a match exhausted just because later candidates remain' {
        $result = Invoke-Resolver -MaxCandidates 1

        $result.Status | Should -Be 'match-earliest'
        $result.WindowExhausted | Should -BeFalse
        $result.Tried.Count | Should -Be 1
    }

    It 'does not claim a complete search with only download gaps' {
        foreach ($release in $Script:mockState.Releases) {
            $Script:mockState.DownloadExits[$release.tagName] = 1
        }

        $result = Invoke-Resolver

        $result.Status | Should -Be 'not-found-inconclusive'
        $result.WindowExhausted | Should -BeFalse
        $result.EarlierGaps | Should -Be 3
        $result.Tried.Count | Should -Be 3
    }

    It 'treats the release enumeration cap as uncertainty for <Kind>' -TestCases @(
        @{ Kind = 'a match'; Match = $true; Candidates = $true; ExpectedStatus = 'match-possibly-not-earliest' },
        @{ Kind = 'clean different files'; Match = $false; Candidates = $true; ExpectedStatus = 'not-found-inconclusive' },
        @{ Kind = 'no candidates'; Match = $false; Candidates = $false; ExpectedStatus = 'not-found-inconclusive' }
    ) {
        param($Match, $Candidates, $ExpectedStatus)

        $Script:mockState.Releases = @(
            for ($i = 0; $i -lt 999; $i++) {
                Get-TestRelease -Tag "other-$i"
            }
            if ($Candidates) {
                Get-TestRelease -Tag 'v26.03.12.1500'
            } else {
                Get-TestRelease -Tag 'v26.03.11.1500'
            }
        )
        if (-not $Match) {
            $Script:mockState.DefaultCsv = "File,Version,SHA256Hash`nOther.ps1,26.03.12.1424,$Script:hash"
        }

        $result = Invoke-Resolver

        $result.Status | Should -Be $ExpectedStatus
        $result.WindowExhausted | Should -BeFalse
        $result.EarlierGaps | Should -Be 0
        $result.Tried.Count | Should -Be ([int]$Candidates)
        $listArguments = $Script:mockState.Calls[0]
        $listArguments[[array]::IndexOf($listArguments, '--limit') + 1] | Should -Be 1000
    }

    It 'returns no candidates for <Kind> without any download or API calls' -TestCases @(
        @{ Kind = 'an empty release list'; Json = '[]' },
        @{ Kind = 'only older releases'; Json = '[{"tagName":"v26.03.11.1500","isDraft":false,"isPrerelease":false}]' }
    ) {
        param($Json)

        $Script:mockState.ReleaseJson = $Json

        $result = Invoke-Resolver

        $result.Status | Should -Be 'not-found-no-candidates'
        $result.Tried.Count | Should -Be 0
        $result.ConfirmedTag | Should -BeNullOrEmpty
        $result.WindowExhausted | Should -BeFalse
        $Script:mockState.Calls.Count | Should -Be 1
    }

    It 'preserves caller contents and removes only invocation downloads after <Kind>' -TestCases @(
        @{ Kind = 'success'; Fail = $false },
        @{ Kind = 'a failed download'; Fail = $true }
    ) {
        param($Fail)

        $sentinel = Join-Path -Path $Script:workFolder -ChildPath 'existing.ScriptVersions.csv'
        Set-Content -LiteralPath $sentinel -Value 'caller data'
        if ($Fail) {
            foreach ($release in $Script:mockState.Releases) {
                $Script:mockState.DownloadExits[$release.tagName] = 1
            }
        }

        $null = Invoke-Resolver

        Test-Path -LiteralPath $Script:workFolder -PathType Container | Should -BeTrue
        Get-Content -LiteralPath $sentinel | Should -Be 'caller data'
        @(Get-ChildItem -LiteralPath $Script:workFolder).Count | Should -Be 1
        foreach ($path in $Script:mockState.Paths) {
            Test-Path -LiteralPath $path | Should -BeFalse
        }
    }

    It 'removes its default work folder after <Kind>' -TestCases @(
        @{ Kind = 'a match'; Fail = $false },
        @{ Kind = 'a terminating enumeration failure'; Fail = $true }
    ) {
        param($Fail)

        if ($Fail) {
            $Script:mockState.ListExit = 1
            { Invoke-Resolver -DefaultWorkFolder } | Should -Throw -ExpectedMessage '*Failed to list releases*'
        } else {
            $result = Invoke-Resolver -DefaultWorkFolder
            $result.Status | Should -Be 'match-earliest'
            $downloadFolder = Split-Path -Path $Script:mockState.Paths[0] -Parent
            Split-Path -Path $downloadFolder -Leaf | Should -BeLike 'find-release-tag-*'
            Split-Path -Path $downloadFolder -Parent | Should -Be $Script:caseRoot
            Test-Path -LiteralPath $downloadFolder | Should -BeFalse
        }
        @(Get-ChildItem -LiteralPath $Script:caseRoot -Directory).Name | Should -Be @('caller')
    }

    It 'pins release and commit requests to github.com despite an inherited host' {
        $result = Invoke-Resolver -Repository 'sample/project'

        $result.Status | Should -Be 'match-earliest'
        $result.Repository | Should -Be 'sample/project'
        $Script:mockState.Calls.Count | Should -Be 3
        foreach ($callArguments in $Script:mockState.Calls) {
            if ($callArguments[0] -eq 'release') {
                $callArguments[[array]::IndexOf($callArguments, '--repo') + 1] | Should -Be 'github.com/sample/project'
            } else {
                $callArguments[0] | Should -Be 'api'
                $callArguments[[array]::IndexOf($callArguments, '--hostname') + 1] | Should -Be 'github.com'
                $callArguments | Should -Contain 'repos/sample/project/commits/v26.03.12.1500'
                $callArguments[[array]::IndexOf($callArguments, '--jq') + 1] | Should -Be '.sha'
            }
        }
        $env:GH_HOST | Should -Be 'enterprise.example.invalid'
    }

    It 'rejects a host-qualified repository before invoking gh' {
        { Invoke-Resolver -Repository 'enterprise.example.invalid/sample/project' } | Should -Throw

        $Script:mockState.Calls.Count | Should -Be 0
        $env:GH_HOST | Should -Be 'enterprise.example.invalid'
    }

    It 'fails closed without a host fallback when release enumeration fails' {
        $Script:mockState.ListExit = 1

        { Invoke-Resolver } | Should -Throw -ExpectedMessage '*Failed to list releases*'

        $Script:mockState.Calls.Count | Should -Be 1
        $callArguments = $Script:mockState.Calls[0]
        $callArguments[[array]::IndexOf($callArguments, '--repo') + 1] | Should -Be 'github.com/microsoft/CSS-Exchange'
        $Script:mockState.Downloads.Count | Should -Be 0
        $env:GH_HOST | Should -Be 'enterprise.example.invalid'
    }

    It 'rejects malformed release enumeration <Kind> before downloading' -TestCases @(
        @{ Kind = 'object shape'; Json = '{}' },
        @{ Kind = 'invalid JSON'; Json = '[invalid' },
        @{ Kind = 'string flags'; Json = '[{"tagName":"v26.03.12.1500","isDraft":"false","isPrerelease":false}]' },
        @{ Kind = 'missing flags'; Json = '[{"tagName":"v26.03.12.1500"}]' }
    ) {
        param($Json)

        $Script:mockState.ReleaseJson = $Json

        { Invoke-Resolver } | Should -Throw

        $Script:mockState.Calls.Count | Should -Be 1
        $Script:mockState.Downloads.Count | Should -Be 0
    }

    It 'retains the CSV match but never retries another host for <Kind> commit lookup' -TestCases @(
        @{ Kind = 'a failed'; ExitCode = 1; Output = 'API unavailable' },
        @{ Kind = 'an invalid'; ExitCode = 0; Output = 'not-a-commit' }
    ) {
        param($ExitCode, $Output)

        $Script:mockState.ApiExit = $ExitCode
        $Script:mockState.ApiOutput = $Output

        $result = Invoke-Resolver

        $result.Status | Should -Be 'match-earliest'
        $result.ConfirmedTag | Should -Be 'v26.03.12.1500'
        $result.ConfirmedCommitSha | Should -BeNullOrEmpty
        $Script:mockState.Calls.Count | Should -Be 3
        $callArguments = $Script:mockState.Calls[2]
        $callArguments[[array]::IndexOf($callArguments, '--hostname') + 1] | Should -Be 'github.com'
    }
}
