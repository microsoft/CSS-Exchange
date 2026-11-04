# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

Describe "Get-DebugFileMetadata completion signals" {

    BeforeAll {
        $Script:metadataPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Get-DebugFileMetadata.ps1'
        $Script:fixtureRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("DebugMetadataTests-" + [guid]::NewGuid().ToString('N'))
        New-Item -Path $Script:fixtureRoot -ItemType Directory | Out-Null

        function Script:Invoke-MetadataFixture {
            param(
                [Parameter(Mandatory)][AllowEmptyString()][string[]]$Lines,
                [int]$MaxInlineEvents = 20,
                [switch]$WithoutLoggerStart
            )
            $directory = Join-Path -Path $Script:fixtureRoot -ChildPath ([guid]::NewGuid().ToString('N'))
            New-Item -Path $directory -ItemType Directory | Out-Null
            $path = Join-Path -Path $directory -ChildPath 'HealthChecker-Debug_20261028064600.txt'
            $prefix = @('[10/28/2026 06:46:00] : Script Version: 26.09.14.1957')
            if (-not $WithoutLoggerStart) {
                $prefix = @('[10/28/2026 06:46:00] : Starting Logger Instance') + $prefix
            }
            [System.IO.File]::WriteAllLines($path, [string[]]($prefix + $Lines), [System.Text.UTF8Encoding]::new($true))
            $inventory = & $Script:metadataPath -DebugDirectory $directory -MaxInlineEventsPerFile $MaxInlineEvents
            $inventory.Files[0].Status | Should -Be 'Parsed'
            return $inventory.Files[0]
        }
    }

    AfterAll {
        Remove-Item -LiteralPath $Script:fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "retains terminal no-errors evidence with <Label>" -ForEach @(
        @{ Label = 'no trailer'; Tail = @() }
        @{ Label = 'blank lines'; Tail = @('', '   ') }
        @{ Label = 'the canonical runtime trailer'; Tail = @('[10/28/2026 06:46:01] : The total script time took 1.25 seconds') }
        @{ Label = 'a short scientific-notation runtime'; Tail = @('[10/28/2026 06:46:01] : The total script time took 1.25E-05 seconds', '') }
    ) {
        $lines = @('[10/28/2026 06:46:01] : No errors occurred in the script.') + $Tail
        $file = Script:Invoke-MetadataFixture -Lines $lines
        $hits = @($file.CompletionSignals | Where-Object -Property Name -EQ -Value 'NoErrorsMessage')
        $hits.Count | Should -Be 1
        $hits[0].LineNumber | Should -Be 3
    }

    It "discards stale no-errors evidence before <Label>" -ForEach @(
        @{ Label = 'a new invocation'; Tail = @('[10/28/2026 06:47:00] : Starting Logger Instance', '[10/28/2026 06:47:01] : Unhandled exception: System.InvalidOperationException') }
        @{ Label = 'later work'; Tail = @('[10/28/2026 06:46:02] : Trying to inspect another server') }
        @{ Label = 'a failure without a timestamp'; Tail = @('System.InvalidOperationException: later failure') }
        @{ Label = 'an invalid runtime timestamp'; Tail = @('[99/99/2026 25:99:99] : The total script time took 1.25 seconds') }
        @{ Label = 'work after the runtime trailer'; Tail = @('[10/28/2026 06:46:02] : The total script time took 1.25 seconds', '[10/28/2026 06:46:03] : Failed to finish another operation') }
    ) {
        $lines = @('[10/28/2026 06:46:01] : No errors occurred in the script.') + $Tail
        $file = Script:Invoke-MetadataFixture -Lines $lines
        @($file.CompletionSignals | Where-Object -Property Name -EQ -Value 'NoErrorsMessage').Count | Should -Be 0
    }

    It "accepts a later terminal no-errors message after an earlier one was invalidated" {
        $file = Script:Invoke-MetadataFixture -Lines @(
            '[10/28/2026 06:46:01] : No errors occurred in the script.'
            '[10/28/2026 06:47:00] : Starting Logger Instance'
            '[10/28/2026 06:47:01] : Trying to inspect another server'
            '[10/28/2026 06:47:02] : No errors occurred in the script.'
            '[10/28/2026 06:47:02] : The total script time took 2.5 seconds'
        )
        $hits = @($file.CompletionSignals | Where-Object -Property Name -EQ -Value 'NoErrorsMessage')
        $hits.Count | Should -Be 1
        $hits[0].LineNumber | Should -Be 6
        $file.MultipleRunsDetected | Should -BeTrue
    }

    It "retains terminal summary completion with the canonical runtime trailer" {
        $file = Script:Invoke-MetadataFixture -Lines @(
            '-----Errors that were handled-----'
            '[10/28/2026 06:46:01] : ----------------------------------'
            "----Errors that occurred that wasn't handled----"
            '[10/28/2026 06:46:01] : ----------------------------------'
            '[10/28/2026 06:46:01] : The total script time took 1.25 seconds'
            ''
        )
        $file.Summary.SummaryComplete | Should -BeTrue
        $file.MultipleRunsDetected | Should -BeFalse
    }

    It "invalidates a completed summary followed by <Label>" -ForEach @(
        @{ Label = 'timestamped work'; Tail = '[10/28/2026 06:46:02] : Trying to inspect another server' }
        @{ Label = 'a failure without a timestamp'; Tail = 'System.InvalidOperationException: later failure' }
    ) {
        $file = Script:Invoke-MetadataFixture -Lines @(
            '-----Errors that were handled-----'
            '[10/28/2026 06:46:01] : ----------------------------------'
            "----Errors that occurred that wasn't handled----"
            '[10/28/2026 06:46:01] : ----------------------------------'
            '[10/28/2026 06:46:01] : The total script time took 1.25 seconds'
            $Tail
        )
        $file.Summary.HandledFooterLine | Should -BeGreaterThan 0
        $file.Summary.UnhandledFooterLine | Should -BeGreaterThan 0
        $file.Summary.SummaryComplete | Should -BeFalse
        $file.MultipleRunsDetected | Should -BeFalse
    }

    It "detects a later failed invocation when the earlier logger start is <Label>" -ForEach @(
        @{ Label = 'present'; OmitStart = $false }
        @{ Label = 'missing'; OmitStart = $true }
    ) {
        $file = Script:Invoke-MetadataFixture -WithoutLoggerStart:$OmitStart -Lines @(
            '-----Errors that were handled-----'
            '[10/28/2026 06:46:01] : ----------------------------------'
            "----Errors that occurred that wasn't handled----"
            '[10/28/2026 06:46:01] : ----------------------------------'
            '[10/28/2026 06:47:00] : Starting Logger Instance'
            '[10/28/2026 06:47:01] : Unhandled exception: System.InvalidOperationException: later failure'
        )
        $file.Summary.SummaryComplete | Should -BeFalse
        $file.MultipleSummaryBlocksDetected | Should -BeFalse
        $file.MultipleRunsDetected | Should -BeTrue
        @($file.InlineEvents | Where-Object { -not $_.IsHandled }).Count | Should -Be 1
    }

    It "retains a late fatal event instead of earlier handled events and discloses the loss" {
        $file = Script:Invoke-MetadataFixture -MaxInlineEvents 2 -Lines @(
            '[10/28/2026 06:46:01] : Failed to inspect optional setting one. Inner Exception: System.Exception'
            '[10/28/2026 06:46:01] : Calling: Invoke-CatchActions'
            '[10/28/2026 06:46:02] : Failed to inspect optional setting two. Inner Exception: System.Exception'
            '[10/28/2026 06:46:02] : Calling: Invoke-CatchActions'
            '[10/28/2026 06:46:03] : Unhandled exception: System.InvalidOperationException: fatal failure'
        )
        $file.InlineEvents.Count | Should -Be 2
        $file.InlineEvents[0].HeadLine | Should -Match 'setting two'
        $file.InlineEvents[1].HeadLine | Should -Match 'fatal failure'
        $file.InlineEvents[1].IsHandled | Should -BeFalse
        $file.InlineEventsTruncated | Should -BeTrue
    }

    It "does not report inline truncation when the retained count equals the cap" {
        $file = Script:Invoke-MetadataFixture -MaxInlineEvents 2 -Lines @(
            '[10/28/2026 06:46:01] : Unhandled exception: first failure'
            '[10/28/2026 06:46:02] : Unhandled exception: second failure'
        )
        $file.InlineEvents.Count | Should -Be 2
        $file.InlineEventsTruncated | Should -BeFalse
    }
}
