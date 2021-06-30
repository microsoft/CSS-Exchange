# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-LogmanRootPath {
    param(
        [Parameter(Mandatory = $true)]$RawLogmanData
    )
    $rootPath = "Root Path:"
    if (-not($RawLogmanData[3].Contains($rootPath))) {
        $i = 0
        while ((-not($RawLogmanData[$i].Contains($rootPath))) -and ($i -lt ($RawLogmanData.count - 1))) {
            $i++
        }
    } else {
        $i = 3
    }

    $strRootPath = $RawLogmanData[$i]
    $replace = $strRootPath.Replace("Root Path:", "")
    [int]$index = $replace.IndexOf(":") - 1
    $strReturn = $replace.SubString($index)
    return $strReturn
}
