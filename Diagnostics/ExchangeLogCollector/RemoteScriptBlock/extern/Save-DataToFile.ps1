# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Save-DataToFile/Save-DataToFile.ps1
#v21.01.22.2234
Function Save-DataToFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][object]$DataIn,
        [Parameter(Mandatory = $true)][string]$SaveToLocation,
        [Parameter(Mandatory = $false)][bool]$FormatList = $true,
        [Parameter(Mandatory = $false)][bool]$SaveTextFile = $true,
        [Parameter(Mandatory = $false)][bool]$SaveXMLFile = $true
    )
    #Function Version #v21.01.22.2234

    Write-VerboseWriter("Calling: Save-DataToFile")
    Write-VerboseWriter("Passed: [string]SaveToLocation: {0} | [bool]FormatList: {1} | [bool]SaveTextFile: {2} | [bool]SaveXMLFile: {3}" -f $SaveToLocation,
        $FormatList,
        $SaveTextFile,
        $SaveXMLFile)

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
        Write-VerboseWriter("DataIn was an empty string. Not going to save anything.")
    }
    Write-VerboseWriter("Returning from Save-DataToFile")
}
