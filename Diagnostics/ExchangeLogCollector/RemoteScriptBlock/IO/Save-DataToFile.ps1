# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Save-DataToFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][object]$DataIn,
        [Parameter(Mandatory = $true)][string]$SaveToLocation,
        [Parameter(Mandatory = $false)][bool]$FormatList = $true,
        [Parameter(Mandatory = $false)][bool]$SaveTextFile = $true,
        [Parameter(Mandatory = $false)][bool]$SaveXMLFile = $true
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    Write-Verbose "Passed: [string]SaveToLocation: $SaveToLocation | [bool]FormatList: $FormatList | [bool]SaveTextFile: $SaveTextFile | [bool]SaveXMLFile: $SaveXMLFile"
    $xmlSaveLocation = "{0}.xml" -f $SaveToLocation
    $txtSaveLocation = "{0}.txt" -f $SaveToLocation

    if ($DataIn -ne [string]::Empty -and
        $null -ne $DataIn) {
        if ($SaveXMLFile) {
            $DataIn | Export-Clixml $xmlSaveLocation -Encoding UTF8
        }
        if ($SaveTextFile) {
            if ($FormatList) {
                $DataIn | Format-List * | Out-File $txtSaveLocation
            } else {
                $DataIn | Format-Table -AutoSize | Out-File $txtSaveLocation
            }
        }
    } else {
        Write-Verbose("DataIn was an empty string. Not going to save anything.")
    }
    Write-Verbose ("Returning from Save-DataToFile")
}
