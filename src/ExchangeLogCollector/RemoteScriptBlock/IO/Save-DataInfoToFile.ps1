Function Save-DataInfoToFile {
    param(
        [Parameter(Mandatory = $false)][object]$DataIn,
        [Parameter(Mandatory = $true)][string]$SaveToLocation,
        [Parameter(Mandatory = $false)][bool]$FormatList = $true,
        [Parameter(Mandatory = $false)][bool]$SaveTextFile = $true,
        [Parameter(Mandatory = $false)][bool]$SaveXMLFile = $true
    )
    [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-ScriptDebug "Function Enter: Save-DataInfoToFile"
    Save-DataToFile -DataIn $DataIn -SaveToLocation (Add-ServerNameToFileName $SaveToLocation) -FormatList $FormatList -SaveTextFile $SaveTextFile -SaveXMLFile $SaveXMLFile
    $timer.Stop()
    Write-ScriptDebug("Took {0} seconds to save out the data." -f $timer.Elapsed.TotalSeconds)
}