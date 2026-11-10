# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    . $PSScriptRoot\..\LogCopyTaskActionFunctions.ps1

    function Get-IISLogDirectory {
        param([datetime]$LogStartDate, [datetime]$LogEndDate, [switch]$IncludeAdditionalLocations)
    }

    $tokens = $null
    $parseErrors = $null
    $source = [System.Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\..\Invoke-RemoteMain.ps1", [ref]$tokens, [ref]$parseErrors)
    $iisBlock = $source.Find({
            param($node)
            $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$PassedInfo.IISLogs'
        }, $true)
    $script:callerBlock = [ScriptBlock]::Create($iisBlock.Extent.Text)
}

Describe 'IIS copy task destinations and collection window' {
    BeforeEach {
        $script:RootCopyToDirectory = $TestDrive
        $script:taskActionList = New-Object 'System.Collections.Generic.List[object]'
        $script:now = [datetime]'2026-09-16T12:00:00'
        $script:PassedInfo = [PSCustomObject]@{ IISLogs = $true; TimeSpan = [TimeSpan]::FromHours(2); EndTimeSpan = [TimeSpan]::FromHours(1) }
        $script:paths = @('C:\IIS\W3SVC1', 'C:\IIS\W3SVC2')
        Mock -CommandName Get-Date -MockWith { $script:now }
        Mock -CommandName Get-IISLogDirectory -MockWith { $script:paths }
    }

    It 'preserves existing per-site destination names' {
        . $script:callerBlock
        $destinations = @($script:taskActionList | ForEach-Object { $_.Parameters.CopyToThisLocation })
        $destinations | Should -Contain "$TestDrive\IIS_W3SVC1_Logs"
        $destinations | Should -Contain "$TestDrive\IIS_W3SVC2_Logs"
        $destinations | Should -Contain "$TestDrive\HTTPERR_Logs"
    }

    It 'passes both collection boundaries and enables additional locations' {
        . $script:callerBlock
        Should -Invoke -CommandName Get-IISLogDirectory -Times 1 -Exactly -ParameterFilter {
            $LogStartDate -eq $script:now.AddHours(-2) -and $LogEndDate -eq $script:now.AddHours(-1) -and $IncludeAdditionalLocations
        }
    }

    It 'separates roots with the same leaf name using the later source identity' {
        $script:paths = @('E:\Current\Logs', 'F:\Retained\Logs')
        . $script:callerBlock
        $tasks = @($script:taskActionList | Where-Object { $_.Parameters.LogPath -notlike '*HTTPERR*' })
        $tasks | Should -HaveCount 2
        $tasks[0].Parameters.CopyToThisLocation | Should -Be "$TestDrive\IIS_Logs_Logs"
        $tasks[1].Parameters.CopyToThisLocation | Should -Match 'IIS_Logs_Logs__F_RETAINED_LOGS_[a-f0-9]{12}$'
    }

    It 'does not schedule the same source twice through case or separator differences' {
        $script:paths = @('C:\IIS\W3SVC1', 'c:\iis\W3SVC1\')
        . $script:callerBlock
        @($script:taskActionList | Where-Object { $_.Parameters.LogPath -notlike '*HTTPERR*' }) | Should -HaveCount 1
    }

    It 'uses a filesystem-safe name for an absolute drive root' {
        $script:paths = @('E:\')
        . $script:callerBlock
        $script:taskActionList[0].Parameters.CopyToThisLocation | Should -Be "$TestDrive\IIS_Root_Logs"
        $script:taskActionList[0].Parameters.LogPath | Should -Be 'E:\'
    }
}
