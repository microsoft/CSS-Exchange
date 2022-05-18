# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Save-DataToFile.ps1
. $PSScriptRoot\..\Add-ServerNameToFileName.ps1
function Save-DataInfoToFile {
    param(
        [Parameter(Mandatory = $false)][object]$DataIn,
        [Parameter(Mandatory = $true)][string]$SaveToLocation,
        [Parameter(Mandatory = $false)][bool]$FormatList = $true,
        [Parameter(Mandatory = $false)][bool]$SaveTextFile = $true,
        [Parameter(Mandatory = $false)][bool]$SaveXMLFile = $true,
        [Parameter(Mandatory = $false)][bool]$AddServerName = $true
    )
    [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "Function Enter: Save-DataInfoToFile"

    if ($AddServerName) {
        $SaveToLocation = Add-ServerNameToFileName $SaveToLocation
    }

    Save-DataToFile -DataIn $DataIn -SaveToLocation $SaveToLocation -FormatList $FormatList -SaveTextFile $SaveTextFile -SaveXMLFile $SaveXMLFile
    $timer.Stop()
    Write-Verbose("Took {0} seconds to save out the data." -f $timer.Elapsed.TotalSeconds)
}
