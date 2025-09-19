# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-Progress {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Warning from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Activity = "",

        [switch]$Completed,

        [string]$CurrentOperation,

        [Parameter(Position = 2)]
        [int]$Id,

        [int]$ParentId = -1,

        [int]$PercentComplete = -1,

        [int]$SecondsRemaining = -1,

        [int]$SourceId,

        [Parameter(Position = 1)]
        [string]$Status
    )
    begin {
        if ($null -eq $Script:WriteProgressGUIStopWatch) {
            $Script:WriteProgressGUIStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $isFirstRun = $true
        }
        $writeProgressStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    }
    process {
        $params = @{
            Activity         = $Activity
            Completed        = $Completed
            CurrentOperation = $CurrentOperation
            Id               = $Id
            ParentId         = $ParentId
            PercentComplete  = $PercentComplete
            SecondsRemaining = $SecondsRemaining
            SourceId         = $SourceId
        }

        if (-not([string]::IsNullOrEmpty($Status))) {
            $params.Add("Status", $Status)
        }

        # This is to help improve the overall performance if Write-Progress is used in a tight loop.
        if ($isFirstRun -or $Completed -or $Script:WriteProgressGUIStopWatch.Elapsed.TotalMilliseconds -gt 500) {
            Microsoft.PowerShell.Utility\Write-Progress @params
            $Script:WriteProgressGUIStopWatch.Restart()
        }

        $message = "Write-Progress Activity: '$Activity' Completed: $Completed CurrentOperation: '$CurrentOperation' Id: $Id" +
        " ParentId: $ParentId PercentComplete: $PercentComplete SecondsRemaining: $SecondsRemaining SourceId: $SourceId Status: '$Status'"

        if ($null -ne $Script:WriteProgressDebugAction) {
            & $Script:WriteProgressDebugAction $message
        }

        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteProgressDebugAction) {
            & $Script:WriteRemoteProgressDebugAction $message
        }

        if ($writeProgressStopWatch.Elapsed.TotalSeconds -ge 2) {
            Write-Verbose "End $($MyInvocation.MyCommand) and took $($writeProgressStopWatch.Elapsed.TotalSeconds) seconds"
        }
    }
}

function SetWriteProgressAction ($DebugAction) {
    $Script:WriteProgressDebugAction = $DebugAction
}

function SetWriteRemoteProgressAction ($DebugAction) {
    $Script:WriteRemoteProgressDebugAction = $DebugAction
}
