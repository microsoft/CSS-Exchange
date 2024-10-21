# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function RunMessageTrackingLogValidation {
    [ref]$errorMessage = $null
    [ref]$writeMessageAlways = $false
    $testResult = $true

    Write-DashLineBoxColor "Running Message Tracking Log Validation" -Color Blue

    $errorMessage = ""
    $testResult = CheckMessageTrackingLogs -errorMessage $errorMessage -writeMessageAlways $writeMessageAlways
    WriteTestResult "Collecting Message tracing logs " -success $testResult -errorMessage $errorMessage -writeMessageAlways $writeMessageAlways
}

function CheckMessageTrackingLogs {
    param([ref]$errorMessage)
    Write-Verbose "Collect Message tracking logs for Booking MB"
    if ($null -eq $script:MessageTrackingLogs) {
        $errorMessage.Value ="Message Tracking Logs are null "
        return $false
    }

    $errorMessage.Value ="Message Tracking Logs contains " + $script:MessageTrackingLogs.Count + " entries"
    $writeMessageAlways.Value = $true
    return $true
}
