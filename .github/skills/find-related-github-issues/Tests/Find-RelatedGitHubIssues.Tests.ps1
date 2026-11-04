# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Describe 'Find-RelatedGitHubIssues' {
    BeforeAll {
        $Script:helperPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Find-RelatedGitHubIssues.ps1'

        function gh {
            throw 'Unexpected gh invocation without a mock.'
        }
    }

    BeforeEach {
        $Script:mockState = @{
            SearchCalls     = [System.Collections.Generic.List[object]]::new()
            SearchHosts     = [System.Collections.Generic.List[string]]::new()
            SearchResponses = @()
            MatchingQuery   = ''
            Issues          = @(
                [PSCustomObject]@{
                    number = 1038
                    state  = 'closed'
                    title  = 'Unrelated failure'
                    body   = ''
                    url    = 'https://github.com/microsoft/CSS-Exchange/issues/1038'
                }
            )
        }
        $state = $Script:mockState

        Mock -CommandName gh -MockWith ({
                & $env:ComSpec /c exit 0
                if ($args[0] -eq 'auth') {
                    return 'Authenticated'
                }
                if ($args[0] -eq 'search') {
                    $state.SearchCalls.Add(@($args))
                    $state.SearchHosts.Add($env:GH_HOST)
                    if ($state.SearchResponses.Count -gt 0) {
                        $response = $state.SearchResponses[$state.SearchCalls.Count - 1]
                        & $env:ComSpec /c exit $response.Exit
                        return $response.Output
                    }
                    if ($state.MatchingQuery -and $args[-1] -ne $state.MatchingQuery) {
                        return '[]'
                    }
                    return ConvertTo-Json -InputObject @($state.Issues) -Depth 4 -Compress
                }
                throw "Unexpected gh arguments: $($args -join ' ')"
            }.GetNewClosure())
    }

    It 'includes pull requests in the native search arguments' {
        $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException 'Cannot parse configuration'

        $result.Status | Should -Be 'Ok'
        $Script:mockState.SearchCalls.Count | Should -Be 1
        $callArguments = $Script:mockState.SearchCalls[0]
        $callArguments[0] | Should -Be 'search'
        $callArguments[1] | Should -Be 'issues'
        $callArguments | Should -Contain '--include-prs'
        $callArguments[[array]::IndexOf($callArguments, '--repo') + 1] | Should -Be 'microsoft/CSS-Exchange'
        $callArguments[-1] | Should -Be '"Cannot parse configuration" in:title,body'
    }

    It 'pins search to GitHub and restores <Label>' -ForEach @(
        @{ Label = 'an inherited host after success'; HostName = 'enterprise.example.invalid'; ExitCode = 0; ExpectedStatus = 'Ok' },
        @{ Label = 'an unset host after success'; HostName = $null; ExitCode = 0; ExpectedStatus = 'Ok' },
        @{ Label = 'an inherited host after failure'; HostName = 'enterprise.example.invalid'; ExitCode = 1; ExpectedStatus = 'Error' }
    ) {
        $originalGhHost = $env:GH_HOST
        try {
            $env:GH_HOST = $HostName
            $Script:mockState.SearchResponses = @(
                @{ Exit = $ExitCode; Output = '[]' }
            )
            $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException 'Cannot parse configuration'

            $result.Status | Should -Be $ExpectedStatus
            $Script:mockState.SearchHosts.Count | Should -Be 1
            $Script:mockState.SearchHosts[0] | Should -Be 'github.com'
            $env:GH_HOST | Should -Be $HostName
        } finally {
            $env:GH_HOST = $originalGhHost
        }
    }

    It 'searches a contiguous exception span around <Kind>' -TestCases @(
        @{
            Kind        = 'a concrete path'
            Exception   = "Cannot find path 'C:\Install A\file.xml' because it does not exist"
            IssueText   = "Cannot find path 'D:\Install B\file.xml' because it does not exist"
            SearchQuery = '"Cannot find path" in:title,body'
        },
        @{
            Kind        = 'a caller path placeholder'
            Exception   = "Cannot find path '<path>' because it does not exist"
            IssueText   = "Cannot find path 'D:\Install B\file.xml' because it does not exist"
            SearchQuery = '"Cannot find path" in:title,body'
        },
        @{
            Kind        = 'a caller user placeholder'
            Exception   = "Cannot find mailbox '<user>' while resolving identity"
            IssueText   = "Cannot find mailbox 'SampleUser' while resolving identity"
            SearchQuery = '"Cannot find mailbox" in:title,body'
        },
        @{
            Kind        = 'a concrete GUID'
            Exception   = 'Cannot resolve mailbox 11111111-1111-1111-1111-111111111111 because it is missing'
            IssueText   = 'Cannot resolve mailbox 22222222-2222-2222-2222-222222222222 because it is missing'
            SearchQuery = '"Cannot resolve mailbox" in:title,body'
        },
        @{
            Kind        = 'a caller GUID placeholder'
            Exception   = 'Cannot resolve mailbox <guid> because it is missing'
            IssueText   = 'Cannot resolve mailbox 22222222-2222-2222-2222-222222222222 because it is missing'
            SearchQuery = '"Cannot resolve mailbox" in:title,body'
        },
        @{
            Kind        = 'a leading timestamp'
            Exception   = '[10/28/2026 06:51:00.123] Failed to parse configuration'
            IssueText   = '[10/27/2026 03:01:00.456] Failed to parse configuration'
            SearchQuery = '"Failed to parse configuration" in:title,body'
        },
        @{
            Kind        = 'a randomized module name'
            Exception   = 'Failure in tmpEXO_123456.123 while reading mailbox'
            IssueText   = 'Failure in tmpEXO_654321.456 while reading mailbox'
            SearchQuery = '"Failure in" in:title,body'
        }
    ) {
        param($Exception, $IssueText, $SearchQuery)

        $Script:mockState.Issues[0].title = $IssueText
        $Script:mockState.MatchingQuery = $SearchQuery
        $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException $Exception

        $result.Status | Should -Be 'Ok'
        $result.QueriesRun.Count | Should -Be 1
        $result.QueriesRun[0] | Should -Be $SearchQuery
        $result.TotalResultsExamined | Should -Be 1
        $result.Similar.Count | Should -Be 1
        $result.Similar[0].Number | Should -Be 1038
        $result.Duplicates.Count | Should -Be 0
    }

    It 'matches the reported quoted path with spaces through the whole helper' {
        $Script:mockState.Issues[0].title = "Cannot read 'D:\Install B\file.xml' while loading"
        $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException "Cannot read 'C:\Install A\file.xml' while loading"

        $result.Status | Should -Be 'Ok'
        $result.TotalResultsExamined | Should -Be 1
        $result.Similar.Count | Should -Be 1
    }

    It 'strips whole <Kind> paths with spaces before selecting a stable span' -TestCases @(
        @{ Kind = 'single-quoted drive'; OpeningQuote = "'"; ClosingQuote = "'"; InputPath = 'C:\Install A\file.xml'; IssuePath = 'D:\Install B\file.xml' },
        @{ Kind = 'double-quoted drive'; OpeningQuote = '"'; ClosingQuote = '"'; InputPath = 'C:\Install A\file.xml'; IssuePath = 'D:\Install B\file.xml' },
        @{ Kind = 'smart single-quoted drive'; OpeningQuote = [string][char]0x2018; ClosingQuote = [string][char]0x2019; InputPath = 'C:\Install A\file.xml'; IssuePath = 'D:\Install B\file.xml' },
        @{ Kind = 'smart double-quoted drive'; OpeningQuote = [string][char]0x201c; ClosingQuote = [string][char]0x201d; InputPath = 'C:\Install A\file.xml'; IssuePath = 'D:\Install B\file.xml' },
        @{ Kind = 'single-quoted UNC'; OpeningQuote = "'"; ClosingQuote = "'"; InputPath = '\\serverA\Install A\file.xml'; IssuePath = '\\serverB\Install B\file.xml' },
        @{ Kind = 'double-quoted UNC'; OpeningQuote = '"'; ClosingQuote = '"'; InputPath = '\\serverA\Install A\file.xml'; IssuePath = '\\serverB\Install B\file.xml' }
    ) {
        param($OpeningQuote, $ClosingQuote, $InputPath, $IssuePath)

        $Script:mockState.Issues[0].title = "$OpeningQuote$IssuePath$ClosingQuote cannot be read while loading"
        $Script:mockState.MatchingQuery = '"cannot be read while loading" in:title,body'
        $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException "$OpeningQuote$InputPath$ClosingQuote cannot be read while loading"

        $result.Status | Should -Be 'Ok'
        $result.QueriesRun[0] | Should -Be $Script:mockState.MatchingQuery
        $result.Similar.Count | Should -Be 1
        $result.Similar[0].Number | Should -Be 1038
    }

    It 'does not reconstruct a local exception phrase across a removed token' {
        $Script:mockState.Issues[0].title = 'Cannot find <path> path'
        $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException 'Cannot find path'

        $result.TotalResultsExamined | Should -Be 1
        $result.Similar.Count | Should -Be 0
        $result.Duplicates.Count | Should -Be 0
    }

    It 'rejects a broad-query candidate that <Kind>' -TestCases @(
        @{ Kind = 'shares only the stable prefix'; IssueText = "Cannot find path 'D:\Other Folder\file.xml' because access is denied" },
        @{ Kind = 'shares only the common suffix'; IssueText = "Cannot remove item 'D:\Other Folder\file.xml' because it does not exist" },
        @{ Kind = 'reverses the stable excerpts'; IssueText = "because it does not exist. Cannot find path 'D:\Other Folder\file.xml'" }
    ) {
        param($IssueText)

        $Script:mockState.Issues[0].title = $IssueText
        $Script:mockState.Issues[0].body = 'Get-MailboxValue'
        $findArguments = @{
            Repository            = 'microsoft/CSS-Exchange'
            TopLevelException     = 'Cannot find path <path> because it does not exist'
            DiscriminatorFunction = 'Get-MailboxValue'
        }
        $result = & $Script:helperPath @findArguments

        $result.Status | Should -Be 'Ok'
        $result.QueriesRun | Should -Contain '"Cannot find path" in:title,body'
        $result.TotalResultsExamined | Should -Be 1
        $result.Similar.Count | Should -Be 0
        $result.Duplicates.Count | Should -Be 0
        $result.DiscardedFunctionOnly | Should -Be 1
    }

    It 'does not promote a partial inner-exception match to a duplicate' {
        $Script:mockState.Issues[0].title = 'Cannot read configuration'
        $Script:mockState.Issues[0].body = 'Cannot find path <path> because access is denied'
        $findArguments = @{
            Repository        = 'microsoft/CSS-Exchange'
            TopLevelException = 'Cannot read configuration'
            InnerException    = 'Cannot find path <path> because it does not exist'
        }
        $result = & $Script:helperPath @findArguments

        $result.Status | Should -Be 'Ok'
        $result.TotalResultsExamined | Should -Be 1
        $result.Duplicates.Count | Should -Be 0
        $result.Similar.Count | Should -Be 1
        $result.Similar[0].Reason | Should -Be 'top-level exception phrase'
    }

    It 'does not treat a truncated search excerpt as the full local signature' {
        $prefix = 'Cannot load configuration while processing mailbox settings for the requested organization'
        $Script:mockState.Issues[0].title = "$prefix because the file was missing"
        $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException "$prefix because the connection was closed"

        $result.Status | Should -Be 'Ok'
        $result.TotalResultsExamined | Should -Be 1
        $result.Similar.Count | Should -Be 0
        $result.Duplicates.Count | Should -Be 0
    }

    It 'retains duplicate and similar classification without accepting function-only matches' {
        $Script:mockState.Issues[0].title = "Cannot find path 'D:\Other Folder\file.xml' because it does not exist"
        $Script:mockState.Issues[0].body = 'Cannot resolve mailbox 22222222-2222-2222-2222-222222222222 because it is missing. Get-MailboxValue'
        $Script:mockState.Issues += [PSCustomObject]@{
            number = 2000
            state  = 'open'
            title  = 'Cannot find path <path> because it does not exist'
            body   = ''
            url    = 'https://github.com/microsoft/CSS-Exchange/issues/2000'
        }
        $Script:mockState.Issues += [PSCustomObject]@{
            number = 2001
            state  = 'open'
            title  = 'Get-MailboxValue failed for a different reason'
            body   = 'Unrelated failure'
            url    = 'https://github.com/microsoft/CSS-Exchange/issues/2001'
        }
        $findArguments = @{
            Repository            = 'microsoft/CSS-Exchange'
            TopLevelException     = 'Cannot find path <path> because it does not exist'
            InnerException        = 'Cannot resolve mailbox <guid> because it is missing'
            ScriptName            = 'HealthChecker.ps1'
            DiscriminatorFunction = 'Get-MailboxValue'
        }
        $result = & $Script:helperPath @findArguments

        $result.Status | Should -Be 'Ok'
        $result.StatusDetail | Should -BeNullOrEmpty
        $result.QueriesRun.Count | Should -BeLessOrEqual 4
        $result.TotalResultsExamined | Should -Be 3
        $result.Duplicates.Count | Should -Be 1
        $result.Duplicates[0].Number | Should -Be 1038
        $result.Duplicates[0].Reason | Should -Match 'Get-MailboxValue \(additional context\)'
        $result.Similar.Count | Should -Be 1
        $result.Similar[0].Number | Should -Be 2000
        $result.DiscardedFunctionOnly | Should -Be 1
    }

    It 'does not search placeholder-only content: <Exception>' -TestCases @(
        @{ Exception = '<user> <email> <guid> <path> <tenant>' },
        @{ Exception = "'C:\Install A\file.xml'" },
        @{ Exception = '11111111-1111-1111-1111-111111111111' },
        @{ Exception = 'tmpEXO_123456.123' }
    ) {
        param($Exception)

        $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException $Exception -ScriptName 'HealthChecker.ps1'

        $result.Status | Should -Be 'NoSearchablePhrase'
        $result.StatusDetail | Should -Not -BeNullOrEmpty
        $result.QueriesRun.Count | Should -Be 0
        $Script:mockState.SearchCalls.Count | Should -Be 0
        Should -Invoke -CommandName gh -Times 0 -Exactly
    }

    It 'does not attempt a function-only fallback without a usable exception signature' {
        $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException '<path>' -DiscriminatorFunction 'Get-Configuration'

        $result.Status | Should -Be 'NoSearchablePhrase'
        $result.StatusDetail | Should -Match 'exception content'
        $result.QueriesRun.Count | Should -Be 0
        Should -Invoke -CommandName gh -Times 0 -Exactly
    }

    It 'still searches a usable inner exception when the top-level message is placeholders-only' {
        $Script:mockState.Issues[0].title = 'Cannot parse configuration'
        $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException '<path>' -InnerException 'Cannot parse configuration'

        $result.Status | Should -Be 'Ok'
        $result.Similar.Count | Should -Be 1
        $result.QueriesRun[0] | Should -Be '"Cannot parse configuration" in:title,body'
    }

    It 'retains a successful search with <Label> before a later rate limit' -ForEach @(
        @{ Label = 'a matching issue'; HasMatch = $true }
        @{ Label = 'no matching issues'; HasMatch = $false }
    ) {
        $Script:mockState.Issues[0].title = 'Cannot load configuration'
        $Script:mockState.Issues[0].body = 'Cannot parse setting'
        $firstOutput = if ($HasMatch) {
            ConvertTo-Json -InputObject @($Script:mockState.Issues) -Depth 4 -Compress
        } else {
            '[]'
        }
        $Script:mockState.SearchResponses = @(
            @{ Exit = 0; Output = $firstOutput }
            @{ Exit = 1; Output = 'API rate limit exceeded' }
        )
        $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException 'Cannot load configuration' -InnerException 'Cannot parse setting' -DiscriminatorFunction 'Get-Configuration'

        $result.Status | Should -Be 'PartialLookup'
        $result.StatusDetail | Should -Match '1 of 2 attempted queries failed'
        $result.StatusDetail | Should -Match 'rate limit'
        $result.Duplicates.Count | Should -Be ([int]$HasMatch)
        $result.TotalResultsExamined | Should -Be ([int]$HasMatch)
        $result.QueriesRun.Count | Should -Be 2
        $Script:mockState.SearchCalls.Count | Should -Be 2
        if ($HasMatch) {
            $result.Duplicates[0].Number | Should -Be 1038
        }
    }

    It 'stops on an initial rate limit without claiming a completed lookup' {
        $Script:mockState.SearchResponses = @(
            @{ Exit = 1; Output = 'API rate limit exceeded' }
        )
        $result = & $Script:helperPath -Repository 'microsoft/CSS-Exchange' -TopLevelException 'Cannot load configuration' -InnerException 'Cannot parse setting'

        $result.Status | Should -Be 'RateLimited'
        $result.TotalResultsExamined | Should -Be 0
        $result.Duplicates.Count | Should -Be 0
        $result.QueriesRun.Count | Should -Be 1
        $Script:mockState.SearchCalls.Count | Should -Be 1
    }
}
