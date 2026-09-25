# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Copy-LogsBasedOnTime.ps1
function Copy-FullLogFullPathRecurse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$CopyToThisLocation
    )
    Write-Verbose("Function Enter: Copy-FullLogFullPathRecurse")
    Write-Verbose("Passed: [string]LogPath: {0} | [string]CopyToThisLocation: {1}" -f $LogPath, $CopyToThisLocation)
    Copy-LogsBasedOnTime -LogPath $LogPath -CopyToThisLocation $CopyToThisLocation -IncludeSubDirectory $true -CopyAll
    Write-Verbose("Function Exit: Copy-FullLogFullPathRecurse")
}
