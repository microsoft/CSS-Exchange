# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-LogmanStartDate {
    param(
        [Parameter(Mandatory = $true)]$RawLogmanData
    )
    $strStart_Date = "Start Date:"
    if (-not($RawLogmanData[11].Contains($strStart_Date))) {
        $i = 0
        while ((-not($RawLogmanData[$i].Contains($strStart_Date))) -and ($i -lt ($RawLogmanData.count - 1))) {
            $i++
        }
        #Circular Log collection doesn't contain Start Date
        if (-not($RawLogmanData[$i].Contains($strStart_Date))) {
            $strReturn = (Get-Date).AddDays(-1).ToString()
            return $strReturn
        }
    } else {
        $i = 11
    }
    $strLine = $RawLogmanData[$i]

    [int]$index = $strLine.LastIndexOf(" ") + 1
    $strReturn = $strLine.SubString($index)
    return $strReturn
}
