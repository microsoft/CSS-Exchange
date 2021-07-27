# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-LogmanStatus {
    param(
        [Parameter(Mandatory = $true)]$RawLogmanData
    )
    $status = "Status:"
    $stop = "Stopped"
    $run = "Running"

    if (-not($RawLogmanData[2].Contains($status))) {
        $i = 0
        while ((-not($RawLogmanData[$i].Contains($status))) -and ($i -lt ($RawLogmanData.count - 1))) {
            $i++
        }
    } else {
        $i = 2
    }
    $strLine = $RawLogmanData[$i]

    if ($strLine.Contains($stop)) {
        $currentStatus = $stop
    } elseif ($strLine.Contains($run)) {
        $currentStatus = $run
    } else {
        $currentStatus = "unknown"
    }
    return $currentStatus
}
