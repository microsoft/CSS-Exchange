# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Describe 'Trace-CodeIntroduction' {
    BeforeAll {
        $Script:helperPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Trace-CodeIntroduction.ps1'
        $Script:introducingSha = '1111111111111111111111111111111111111111'
        $Script:fixtureRoot = (New-Item -ItemType Directory -Path (Join-Path -Path $TestDrive -ChildPath 'repository')).FullName

        function git {
            throw 'Unexpected git invocation without a mock.'
        }

        function gh {
            throw 'Unexpected gh invocation without a mock.'
        }

        function Invoke-Trace {
            param(
                [switch]$WithoutRepository,
                [int]$StartLine = 1,
                [int]$EndLine = 1
            )

            $traceArguments = @{
                Path           = 'Sample.ps1'
                StartLine      = $StartLine
                EndLine        = $EndLine
                BaselineSha    = '2222222222222222222222222222222222222222'
                RepositoryRoot = $Script:fixtureRoot
            }
            if (-not $WithoutRepository) {
                $traceArguments.Repository = 'microsoft/CSS-Exchange'
            }
            & $Script:helperPath @traceArguments
        }
    }

    BeforeEach {
        $Script:mockState = @{
            IntroducingSha = $Script:introducingSha
            GhCalls        = [System.Collections.Generic.List[object]]::new()
            ApiExit        = 0
            ApiOutput      = '[{"number":2584,"merged_at":"2026-10-01T10:00:00Z"}]'
            PrExit         = 0
            PrOutput       = '{"number":2584,"title":"Fix sample","url":"https://github.com/microsoft/CSS-Exchange/pull/2584","body":"Sample change","mergedAt":"2026-10-01T10:00:00Z","author":{"login":"SampleAuthor"}}'
            BeforeSource   = 'if ($null -eq $item) { return }'
            AfterSource    = 'Write-Output -InputObject $item'
            SourceExit     = 0
            ShallowOutput  = 'false'
            ShallowExit    = 0
            ParentOutput   = $null
            ParentExit     = 0
            BlameOutput    = $null
            RawCommitExit  = 0
            RawCommit      = @(
                'tree 4444444444444444444444444444444444444444'
                'parent 3333333333333333333333333333333333333333'
                ''
                'Sample commit body'
            )
            DiffOutput     = @(
                'diff --git a/Sample.ps1 b/Sample.ps1'
                '--- a/Sample.ps1'
                '+++ b/Sample.ps1'
                '@@ -1 +1 @@'
                '-if ($null -eq $item) { return }'
                '+Write-Output -InputObject $item'
            )
        }
        $state = $Script:mockState

        Mock -CommandName git -MockWith ({
                & $env:ComSpec /c exit 0
                if ($args -contains 'cat-file') {
                    if ($args -contains 'commit') {
                        & $env:ComSpec /c exit $state.RawCommitExit
                        return $state.RawCommit
                    }
                    return
                }
                if ($args -contains '--is-shallow-repository') {
                    & $env:ComSpec /c exit $state.ShallowExit
                    return $state.ShallowOutput
                }
                if ($args -contains 'rev-list' -and $args -contains '--no-walk') {
                    & $env:ComSpec /c exit $state.ParentExit
                    if ($null -ne $state.ParentOutput) { return $state.ParentOutput }
                    return "$($state.IntroducingSha) 3333333333333333333333333333333333333333"
                }
                if ($args -contains 'blame') {
                    if ($null -ne $state.BlameOutput) { return $state.BlameOutput }
                    return "$($state.IntroducingSha) 1 1 1"
                }
                if ($args -contains 'log' -and $args -contains '--format=%H') { return $state.IntroducingSha }
                if ($args -contains 'log' -and $args -contains '--format=') {
                    return $state.DiffOutput
                }
                if ($args -contains 'show') {
                    if ($args -contains "$($state.IntroducingSha)^:Sample.ps1") {
                        & $env:ComSpec /c exit $state.SourceExit
                        return $state.BeforeSource
                    }
                    if ($args -contains "$($state.IntroducingSha):Sample.ps1") {
                        & $env:ComSpec /c exit $state.SourceExit
                        return $state.AfterSource
                    }
                    $format = @($args | Where-Object { $_ -like '--format=*' })[0]
                    switch ($format) {
                        '--format=%h' { return $state.IntroducingSha.Substring(0, 7) }
                        '--format=%an' { return 'Sample Author' }
                        '--format=%ae' { return 'sample@example.com' }
                        '--format=%aI' { return '2026-10-01T10:00:00Z' }
                        '--format=%s' { return 'Sample change' }
                        '--format=%b' { return 'Sample commit body' }
                    }
                }
                throw "Unexpected git arguments: $($args -join ' ')"
            }.GetNewClosure())

        Mock -CommandName gh -MockWith ({
                $state.GhCalls.Add(@($args))
                if ($args[0] -eq 'api') {
                    & $env:ComSpec /c exit $state.ApiExit
                    return $state.ApiOutput
                }
                if ($args[0] -eq 'pr' -and $args[1] -eq 'view') {
                    & $env:ComSpec /c exit $state.PrExit
                    return $state.PrOutput
                }
                throw "Unexpected gh arguments: $($args -join ' ')"
            }.GetNewClosure())
    }

    It 'retains local evidence and reports <Kind> from the PR API' -TestCases @(
        @{ Kind = 'an API failure'; Failure = 'Connection failed'; ExitCode = 1 },
        @{ Kind = 'an authentication failure'; Failure = 'HTTP 401: Requires authentication'; ExitCode = 4 },
        @{ Kind = 'a rate limit'; Failure = 'API rate limit exceeded'; ExitCode = 1 }
    ) {
        param($Failure, $ExitCode)

        $PSNativeCommandUseErrorActionPreference = $true
        $ErrorActionPreference = 'Stop'
        $Script:mockState.ApiExit = $ExitCode
        $Script:mockState.ApiOutput = $Failure
        $result = Invoke-Trace

        $result.Status | Should -Be 'PartialLookup'
        $result.StatusDetail | Should -Match 'gh api'
        $result.StatusDetail | Should -Match ([regex]::Escape($Failure))
        $result.PullRequest | Should -BeNullOrEmpty
        $result.IntroducingCommit.Sha | Should -Be $Script:introducingSha
        $result.DiffSummary.AddedLines | Should -Be 1
        $result.DiffSummary.RemovedLines | Should -Be 1
        $result.RegressionAssessment.Verdict | Should -Be 'PossibleRegression'
        $result.Provenance.Availability | Should -Be 'SingleMatching'
        $Script:mockState.GhCalls.Count | Should -Be 1
        $PSNativeCommandUseErrorActionPreference | Should -BeTrue
    }

    It 'retains local evidence and reports malformed API JSON' {
        $Script:mockState.ApiOutput = '{not JSON'
        $result = Invoke-Trace

        $result.Status | Should -Be 'PartialLookup'
        $result.StatusDetail | Should -Match 'gh api'
        $result.StatusDetail | Should -Not -BeNullOrEmpty
        $result.PullRequest | Should -BeNullOrEmpty
        $result.IntroducingCommit.Sha | Should -Be $Script:introducingSha
        $result.DiffSummary.AddedLines | Should -Be 1
        $result.RegressionAssessment.Verdict | Should -Be 'PossibleRegression'
        $result.Provenance.Availability | Should -Be 'SingleMatching'
        $Script:mockState.GhCalls.Count | Should -Be 1
    }

    It 'retains local evidence and reports a failed PR view' {
        $PSNativeCommandUseErrorActionPreference = $true
        $ErrorActionPreference = 'Stop'
        $Script:mockState.PrExit = 1
        $Script:mockState.PrOutput = 'PR details unavailable'
        $result = Invoke-Trace

        $result.Status | Should -Be 'PartialLookup'
        $result.StatusDetail | Should -Match 'gh pr view'
        $result.StatusDetail | Should -Match 'PR details unavailable'
        $result.PullRequest | Should -BeNullOrEmpty
        $result.IntroducingCommit.Sha | Should -Be $Script:introducingSha
        $result.DiffSummary.AddedLines | Should -Be 1
        $result.RegressionAssessment.Verdict | Should -Be 'PossibleRegression'
        $result.Provenance.Availability | Should -Be 'SingleMatching'
        $Script:mockState.GhCalls.Count | Should -Be 2
    }

    It 'retains local evidence and reports malformed PR-view JSON' {
        $Script:mockState.PrOutput = '{not JSON'
        $result = Invoke-Trace

        $result.Status | Should -Be 'PartialLookup'
        $result.StatusDetail | Should -Match 'gh pr view'
        $result.StatusDetail | Should -Not -BeNullOrEmpty
        $result.PullRequest | Should -BeNullOrEmpty
        $result.IntroducingCommit.Sha | Should -Be $Script:introducingSha
        $result.DiffSummary.AddedLines | Should -Be 1
        $result.RegressionAssessment.Verdict | Should -Be 'PossibleRegression'
        $result.Provenance.Availability | Should -Be 'SingleMatching'
    }

    It 'reports unavailable gh without discarding local evidence' {
        Mock -CommandName Get-Command -ParameterFilter { $Name -eq 'gh' } -MockWith { return $null }
        $result = Invoke-Trace

        $result.Status | Should -Be 'PartialLookup'
        $result.StatusDetail | Should -Match 'gh.*not found'
        $result.PullRequest | Should -BeNullOrEmpty
        $result.IntroducingCommit.Sha | Should -Be $Script:introducingSha
        $result.DiffSummary.AddedLines | Should -Be 1
        $result.RegressionAssessment.Verdict | Should -Be 'PossibleRegression'
        $Script:mockState.GhCalls.Count | Should -Be 0
    }

    It 'distinguishes a successful lookup with no associated PR from a failure' {
        $Script:mockState.ApiOutput = '[]'
        $result = Invoke-Trace

        $result.Status | Should -Be 'Ok'
        $result.StatusDetail | Should -BeNullOrEmpty
        $result.PullRequest | Should -BeNullOrEmpty
        $result.IntroducingCommit.Sha | Should -Be $Script:introducingSha
        $result.DiffSummary.AddedLines | Should -Be 1
        $result.RegressionAssessment.Verdict | Should -Be 'PossibleRegression'
        $Script:mockState.GhCalls.Count | Should -Be 1
    }

    It 'leaves a successful unmerged-only lookup as Ok without claiming a merged PR' {
        $Script:mockState.ApiOutput = '[{"number":2584,"merged_at":null}]'
        $result = Invoke-Trace

        $result.Status | Should -Be 'Ok'
        $result.StatusDetail | Should -BeNullOrEmpty
        $result.PullRequest | Should -BeNullOrEmpty
        $Script:mockState.GhCalls.Count | Should -Be 1
    }

    It 'retains the enriched PR on success' {
        $result = Invoke-Trace

        $result.Status | Should -Be 'Ok'
        $result.StatusDetail | Should -BeNullOrEmpty
        $result.PullRequest.Number | Should -Be 2584
        $result.PullRequest.Author | Should -Be 'SampleAuthor'
        $result.IntroducingCommit.Sha | Should -Be $Script:introducingSha
        $Script:mockState.GhCalls.Count | Should -Be 2
    }

    It 'does not require GitHub enrichment when Repository is omitted' {
        $result = Invoke-Trace -WithoutRepository

        $result.Status | Should -Be 'Ok'
        $result.StatusDetail | Should -BeNullOrEmpty
        $result.PullRequest | Should -BeNullOrEmpty
        $result.IntroducingCommit.Sha | Should -Be $Script:introducingSha
        $Script:mockState.GhCalls.Count | Should -Be 0
    }

    It 'ignores <Label> when assessing guard changes' -ForEach @(
        @{
            Label       = 'multiline comment prose'
            Before      = @('<#', 'if an operation fails, return to its caller', '#>')
            After       = @('<#', 'The operation is described here', '#>')
            ChangedLine = 2
        }
        @{
            Label       = 'literal here-string prose'
            Before      = @('$message = @''', 'if an operation fails, return to its caller', '''@')
            After       = @('$message = @''', 'The operation is described here', '''@')
            ChangedLine = 2
        }
        @{
            Label       = 'expandable here-string prose'
            Before      = @('$message = @"', 'if an operation fails, return to its caller', '"@')
            After       = @('$message = @"', 'The operation is described here', '"@')
            ChangedLine = 2
        }
        @{
            Label       = 'a verbose message change'
            Before      = @('Write-Verbose ''Old description''')
            After       = @('Write-Verbose ''Updated description''')
            ChangedLine = 1
        }
        @{
            Label       = 'interpolated diagnostic prose with unchanged executable content'
            Before      = @('Write-Verbose "if $item return"')
            After       = @('Write-Verbose "Updated description: $item"')
            ChangedLine = 1
        }
        @{
            Label       = 'formatting-only changes'
            Before      = @('Write-Output -InputObject $item')
            After       = @('  Write-Output    -InputObject $item  ')
            ChangedLine = 1
        }
    ) {
        $Script:mockState.BeforeSource = $Before -join "`n"
        $Script:mockState.AfterSource = $After -join "`n"
        $Script:mockState.DiffOutput = @(
            'diff --git a/Sample.ps1 b/Sample.ps1'
            '--- a/Sample.ps1'
            '+++ b/Sample.ps1'
            "@@ -$ChangedLine +$ChangedLine @@"
            "-$($Before[$ChangedLine - 1])"
            "+$($After[$ChangedLine - 1])"
        )
        $result = Invoke-Trace -WithoutRepository -StartLine $ChangedLine -EndLine $ChangedLine

        $result.Status | Should -Be 'Ok'
        $result.RegressionAssessment.Verdict | Should -Be 'Indeterminate'
        $result.DiffSummary.KeywordsAdded | Should -BeNullOrEmpty
        $result.DiffSummary.KeywordsRemoved | Should -BeNullOrEmpty
    }

    It 'detects a removed guard inside <Label>' -ForEach @(
        @{
            Label       = 'an expandable string'
            Before      = @('$message = "$(if ($null -ne $item) { $item.Name })"')
            After       = @('$message = "$($item.Name)"')
            ChangedLine = 1
        }
        @{
            Label       = 'an expandable here-string'
            Before      = @('$message = @"', '$(if ($null -ne $item) { $item.Name })', '"@')
            After       = @('$message = @"', '$($item.Name)', '"@')
            ChangedLine = 2
        }
        @{
            Label       = 'a nested expandable string'
            Before      = @('$message = "$("$(if ($null -ne $item) { $item.Name })")"')
            After       = @('$message = "$("$($item.Name)")"')
            ChangedLine = 1
        }
    ) {
        $Script:mockState.BeforeSource = $Before -join "`n"
        $Script:mockState.AfterSource = $After -join "`n"
        $Script:mockState.DiffOutput = @(
            'diff --git a/Sample.ps1 b/Sample.ps1'
            '--- a/Sample.ps1'
            '+++ b/Sample.ps1'
            "@@ -$ChangedLine +$ChangedLine @@"
            "-$($Before[$ChangedLine - 1])"
            "+$($After[$ChangedLine - 1])"
        )
        $result = Invoke-Trace -WithoutRepository -StartLine $ChangedLine -EndLine $ChangedLine

        $result.Status | Should -Be 'Ok'
        $result.RegressionAssessment.Verdict | Should -Be 'PossibleRegression'
        $result.DiffSummary.KeywordsRemoved | Should -Contain 'if'
        $result.DiffSummary.KeywordsRemoved | Should -Contain '-ne'
        $result.DiffSummary.KeywordsAdded | Should -BeNullOrEmpty
    }

    It 'retains <Label> as source rather than file metadata' -ForEach @(
        @{ Label = 'an added path header'; BeforeText = 'old'; AfterText = '++ b/placeholder.ps1' }
        @{ Label = 'a removed path header'; BeforeText = '-- a/placeholder.ps1'; AfterText = 'new' }
        @{ Label = 'an added null header'; BeforeText = 'old'; AfterText = '++ /dev/null' }
        @{ Label = 'a removed null header'; BeforeText = '-- /dev/null'; AfterText = 'new' }
    ) {
        $before = @('$notes = @''', $BeforeText, '''@', 'if ($null -eq $item) { return }')
        $after = @('$notes = @''', $AfterText, '''@', 'Write-Output -InputObject $item')
        $Script:mockState.BeforeSource = $before -join "`n"
        $Script:mockState.AfterSource = $after -join "`n"
        $Script:mockState.DiffOutput = @(
            'diff --git a/Sample.ps1 b/Sample.ps1'
            '--- a/Sample.ps1'
            '+++ b/Sample.ps1'
            '@@ -1,4 +1,4 @@'
            " $($before[0])"
            "-$($before[1])"
            "+$($after[1])"
            " $($before[2])"
            "-$($before[3])"
            "+$($after[3])"
        )
        $result = Invoke-Trace -WithoutRepository -EndLine 4

        $result.Status | Should -Be 'Ok'
        $result.DiffSummary.AddedLines | Should -Be 2
        $result.DiffSummary.RemovedLines | Should -Be 2
        $result.RegressionAssessment.Verdict | Should -Be 'PossibleRegression'
        $result.DiffSummary.KeywordsRemoved | Should -Contain 'if'
        $result.DiffSummary.KeywordsRemoved | Should -Contain '-eq'
    }

    It 'does not interpret parameter prefixes as conditional operators' {
        $Script:mockState.BeforeSource = 'Rename-Item -LiteralPath ''old'' -NewName ''new'''
        $Script:mockState.AfterSource = 'Move-Item -LiteralPath ''old'' -Destination ''new'''
        $Script:mockState.DiffOutput = @(
            'diff --git a/Sample.ps1 b/Sample.ps1'
            '--- a/Sample.ps1'
            '+++ b/Sample.ps1'
            '@@ -1 +1 @@'
            "-$($Script:mockState.BeforeSource)"
            "+$($Script:mockState.AfterSource)"
        )
        $result = Invoke-Trace -WithoutRepository

        $result.DiffSummary.KeywordsRemoved | Should -BeNullOrEmpty
        $result.RegressionAssessment.Verdict | Should -Be 'LikelyOversight'
    }

    It 'recognizes a genuine new guard in an added file without reading a nonexistent parent file' {
        $Script:mockState.AfterSource = 'if ($null -eq $item) { return }'
        $Script:mockState.DiffOutput = @(
            'diff --git a/Sample.ps1 b/Sample.ps1'
            '--- /dev/null'
            '+++ b/Sample.ps1'
            '@@ -0,0 +1 @@'
            "+$($Script:mockState.AfterSource)"
        )
        $result = Invoke-Trace -WithoutRepository

        $result.RegressionAssessment.Verdict | Should -Be 'Intentional'
        $result.DiffSummary.KeywordsAdded | Should -Contain 'if'
        $result.DiffSummary.KeywordsAdded | Should -Contain '-eq'
    }

    It 'leaves assessment indeterminate when complete historical source is unavailable' {
        $Script:mockState.SourceExit = 1
        $result = Invoke-Trace -WithoutRepository

        $result.IntroducingCommit.Sha | Should -Be $Script:introducingSha
        $result.DiffSummary.AddedLines | Should -Be 1
        $result.RegressionAssessment.Verdict | Should -Be 'Indeterminate'
        $result.RegressionAssessment.Reasoning | Should -Match 'lexical context is unavailable'
    }

    It 'reads the UTF-8 preamble as encoding metadata rather than executable source' {
        $Script:mockState.BeforeSource = [string][char]0xFEFF + $Script:mockState.BeforeSource
        $Script:mockState.AfterSource = [string][char]0xFEFF + $Script:mockState.AfterSource
        $result = Invoke-Trace -WithoutRepository

        $result.RegressionAssessment.Verdict | Should -Be 'PossibleRegression'
        $result.DiffSummary.KeywordsRemoved | Should -Contain '-eq'
    }

    It 'does not attribute code or look up a PR from an artificial shallow root' {
        $Script:mockState.ShallowOutput = 'true'
        $Script:mockState.ParentOutput = $Script:introducingSha
        $PSNativeCommandUseErrorActionPreference = $true
        $result = Invoke-Trace

        $result.Status | Should -Be 'RangeUnavailable'
        $result.StatusDetail | Should -Match 'shallow boundary'
        $result.IntroducingCommit | Should -BeNullOrEmpty
        $result.PullRequest | Should -BeNullOrEmpty
        $result.DiffSummary | Should -BeNullOrEmpty
        $result.RegressionAssessment.Verdict | Should -Be 'Indeterminate'
        $result.Provenance.Availability | Should -Be 'Unavailable'
        $result.Provenance.CandidateShas | Should -Contain $Script:introducingSha
        $Script:mockState.GhCalls.Count | Should -Be 0
        $PSNativeCommandUseErrorActionPreference | Should -BeTrue
    }

    It 'detects a shallow blame origin even when the newest touch is not itself a boundary' {
        $boundarySha = '3333333333333333333333333333333333333333'
        $Script:mockState.ShallowOutput = 'true'
        $Script:mockState.BlameOutput = @(
            "$($Script:introducingSha) 1 1 1"
            "$boundarySha 2 2 1"
            'boundary'
        )
        $Script:mockState.ParentOutput = @(
            "$($Script:introducingSha) $boundarySha"
            $boundarySha
        )
        $result = Invoke-Trace

        $result.Status | Should -Be 'RangeUnavailable'
        $result.Provenance.Availability | Should -Be 'Unavailable'
        $result.Provenance.CandidateShas | Should -Contain $boundarySha
        $result.RegressionAssessment.Verdict | Should -Be 'Indeterminate'
        $Script:mockState.GhCalls.Count | Should -Be 0
    }

    It 'preserves a trace whose entire selected history is available inside a shallow repository' {
        $Script:mockState.ShallowOutput = 'true'
        $result = Invoke-Trace

        $result.Status | Should -Be 'Ok'
        $result.Provenance.Availability | Should -Be 'SingleMatching'
        $result.IntroducingCommit.Sha | Should -Be $Script:introducingSha
        $result.RegressionAssessment.Verdict | Should -Be 'PossibleRegression'
        $result.PullRequest.Number | Should -Be 2584
    }

    It 'accepts a genuine root commit and ignores parent-looking text in its message' {
        $Script:mockState.ShallowOutput = 'true'
        $Script:mockState.ParentOutput = $Script:introducingSha
        $Script:mockState.RawCommit = @(
            'tree 4444444444444444444444444444444444444444'
            ''
            'parent 3333333333333333333333333333333333333333'
        )
        $Script:mockState.AfterSource = 'if ($null -eq $item) { return }'
        $Script:mockState.DiffOutput = @(
            'diff --git a/Sample.ps1 b/Sample.ps1'
            '--- /dev/null'
            '+++ b/Sample.ps1'
            '@@ -0,0 +1 @@'
            "+$($Script:mockState.AfterSource)"
        )
        $result = Invoke-Trace

        $result.Status | Should -Be 'Ok'
        $result.Provenance.Availability | Should -Be 'SingleMatching'
        $result.RegressionAssessment.Verdict | Should -Be 'Intentional'
    }

    It 'does not confirm attribution when the <Phase> query fails' -ForEach @(
        @{ Phase = 'shallow-state'; FailShallow = 1; FailParent = 0; FailRaw = 0 }
        @{ Phase = 'visible-parent'; FailShallow = 0; FailParent = 1; FailRaw = 0 }
        @{ Phase = 'raw-parent'; FailShallow = 0; FailParent = 0; FailRaw = 1 }
    ) {
        $Script:mockState.ShallowOutput = 'true'
        $Script:mockState.ShallowExit = $FailShallow
        $Script:mockState.ParentExit = $FailParent
        $Script:mockState.RawCommitExit = $FailRaw
        $Script:mockState.ParentOutput = $Script:introducingSha
        $result = Invoke-Trace

        $result.Status | Should -Be 'RangeUnavailable'
        $result.StatusDetail | Should -Not -BeNullOrEmpty
        $result.Provenance.Availability | Should -Be 'Unavailable'
        $result.RegressionAssessment.Verdict | Should -Be 'Indeterminate'
        $result.IntroducingCommit | Should -BeNullOrEmpty
        $Script:mockState.GhCalls.Count | Should -Be 0
    }
}
