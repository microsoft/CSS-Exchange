# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeUpdates.ps1

function Test-LatestSUInstalled {
    param(
        [string]$Server,
        [string]$Version
    )

    $KBsInstalled = Get-ExchangeUpdates -Server $Server -Version $Version

    if (($null -ne $KBsInstalled) -and ($KBsInstalled -like "*KB5014261*")) {
        Write-Verbose ("Latest SU was detected on the system")
        $LatestSUInstalled = $true
    } else {
        Write-Verbose ("Latest SU was not detected on the system")
        $LatestSUInstalled = $false
    }

    return $LatestSUInstalled
}
