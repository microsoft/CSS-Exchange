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

        [int]$PercentComplete,

        [int]$SecondsRemaining = -1,

        [int]$SourceId,

        [Parameter(Position = 1)]
        [string]$Status
    )

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

        Microsoft.PowerShell.Utility\Write-Progress @params

        $message = "Write-Progress Activity: '$Activity' Completed: $Completed CurrentOperation: '$CurrentOperation' Id: $Id" +
        " ParentId: $ParentId PercentComplete: $PercentComplete SecondsRemaining: $SecondsRemaining SourceId: $SourceId Status: '$Status'"

        if ($null -ne $Script:WriteProgressDebugAction) {
            & $Script:WriteProgressDebugAction $message
        }

        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteProgressDebugAction) {
            & $Script:WriteRemoteProgressDebugAction $message
        }
    }
}

function SetWriteProgressAction ($DebugAction) {
    $Script:WriteProgressDebugAction = $DebugAction
}

function SetWriteRemoteProgressAction ($DebugAction) {
    $Script:WriteRemoteProgressDebugAction = $DebugAction
}
