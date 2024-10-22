# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function GetMessageTrackingLog {
    param($Identity)
    # Get the Message Tracking Log
    $DateNow = Get-Date
    $DateStart = $DateNow.AddDays($script:MessageTrackingDays*-1)
    $DateEnd = Get-Date
    $MessageTrackingLog = Get-MessageTrace -SenderAddress $Identity -StartDate $DateStart.ToString("MM/dd/yyyy HH:mm") -EndDate $DateEnd.ToString("MM/dd/yyyy HH:mm") #-ErrorAction SilentlyContinue
    return $MessageTrackingLog
}
