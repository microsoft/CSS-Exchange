# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-HealthCheckerData.ps1
# The main functionality of Exchange Health Checker.
# Collect information and report it to the screen and export out the results.
function Invoke-HealthCheckerMainReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServerNames,

        [Parameter(Mandatory = $true)]
        [bool]$EdgeServer
    )

    $currentErrors = $Error.Count

    if ((-not $SkipVersionCheck) -and
                (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/HC-VersionsUrl")) {
        Write-Yellow "Script was updated. Please rerun the command."
        return
    } else {
        $Script:DisplayedScriptVersionAlready = $true
        Write-Green "Exchange Health Checker version $BuildVersion"
    }

    Invoke-ErrorCatchActionLoopFromIndex $currentErrors
    Get-HealthCheckerData $ServerNames $EdgeServer
}
