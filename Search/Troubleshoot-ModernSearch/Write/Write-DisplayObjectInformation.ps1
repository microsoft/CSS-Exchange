# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-DisplayObjectInformation {
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
            Write-Host ("{0,-$width} = {1}" -f $property, $DisplayObject.($property))
        }
    }
}
