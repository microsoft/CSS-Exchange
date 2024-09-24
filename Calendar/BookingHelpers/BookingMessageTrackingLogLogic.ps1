# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function RunMessageTrackingLogValidation {
    [ref]$ErrorMessage = $null
    [ref]$WriteMessageAlways = $false
    $TestResult = $true

    Write-DashLineBoxColor "Running Message Tracking Log Validation" -Color Blue

    $ErrorMessage = ""
    $TestResult = CheckMessageTrackingLogs -errorMessage $ErrorMessage -writeMessageAlways $WriteMessageAlways
    WriteTestResult "Collecting Message tracing logs " -success $TestResult -errorMessage $ErrorMessage -writeMessageAlways $WriteMessageAlways
}

function CheckMessageTrackingLogs {
    param([ref]$ErrorMessage)
    Write-Verbose "Collect Message tracking logs for Booking MB"
    if ($null -eq $script:MessageTrackingLogs) {
        $ErrorMessage.Value ="Message Tracking Logs are null "
        return $false
    }

    $ErrorMessage.Value ="Message Tracking Logs contains " + $script:MessageTrackingLogs.Count + " entries"
    $WriteMessageAlways.Value = $true
    return $true
}
