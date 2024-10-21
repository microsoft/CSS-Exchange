# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function GetMessageTrackingLog {
    param($identity)
    # Get the Message Tracking Log
    $dateNow = Get-Date
    $dateStart = $dateNow.AddDays($script:MessageTrackingDays*-1)
    $dateEnd = Get-Date
    $MessageTrackingLog = Get-MessageTrace -SenderAddress $identity -StartDate $dateStart.ToString("MM/dd/yyyy HH:mm") -EndDate $dateEnd.ToString("MM/dd/yyyy HH:mm") #-ErrorAction SilentlyContinue
    return $MessageTrackingLog
}
