# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Write-ScriptOutput.ps1
Function Write-DisplayObjectInformation {
    [CmdletBinding()]
    param(
        [object]$DisplayObject,
        [string[]]$PropertyToDisplay
    )
    process {
        $width = 0

        foreach ($property in $PropertyToDisplay) {

            if ($property.Length -gt $width) {
                $width = $property.Length + 1
            }
        }

        foreach ($property in $PropertyToDisplay) {
            Write-ScriptOutput ("{0,-$width} = {1}" -f $property, $DisplayObject.($property))
        }
    }
}
