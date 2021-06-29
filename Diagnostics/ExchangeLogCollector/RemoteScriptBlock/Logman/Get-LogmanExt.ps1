# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-LogmanExt {
    param(
        [Parameter(Mandatory = $true)]$RawLogmanData
    )
    $strLocation = "Output Location:"
    if (-not($RawLogmanData[15].Contains($strLocation))) {
        $i = 0
        while ((-not($RawLogmanData[$i].Contains($strLocation))) -and ($i -lt ($RawLogmanData.Count - 1))) {
            $i++
        }
    } else {
        $i = 15
    }

    $strLine = $RawLogmanData[$i]
    [int]$index = $strLine.LastIndexOf(".")
    if ($index -ne -1) {
        $strExt = $strLine.SubString($index)
    } else {
        $strExt = $null
    }
    return $strExt
}
