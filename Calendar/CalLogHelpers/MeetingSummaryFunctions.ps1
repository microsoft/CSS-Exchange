# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Build-MeetingSummary.ps1
# This script is used to support the Get-CalendarDiagnosticObjectsSummary.ps1 script.

function Convert-Data {
    param(
        [Parameter(Mandatory = $True)]
        [string[]] $ArrayNames,
        [switch ] $NoWarnings = $False
    )
    $ValidArrays = @()
    $ItemCounts = @()
    $VariableLookup = @{}
    foreach ($Array in $ArrayNames) {
        try {
            $VariableData = Get-Variable -Name $Array -ErrorAction Stop
            $VariableLookup[$Array] = $VariableData.Value
            $ValidArrays += $Array
            $ItemCounts += ($VariableData.Value | Measure-Object).Count
        } catch {
            if (!$NoWarnings) {
                Write-Warning -Message "No variable found for [$Array]"
            }
        }
    }
    $MaxItemCount = ($ItemCounts | Measure-Object -Maximum).Maximum
    $FinalArray = @()
    for ($Inc = 0; $Inc -lt $MaxItemCount; $Inc++) {
        $FinalObj = New-Object PsObject
        foreach ($Item in $ValidArrays) {
            $FinalObj | Add-Member -MemberType NoteProperty -Name $Item -Value $VariableLookup[$Item][$Inc]
        }
        $FinalArray += $FinalObj
    }

    return $FinalArray
    $FinalArray = @()
}

# ===================================================================================================
# Write Out one line of the Meeting Summary (Time + Meeting Changes)
# ===================================================================================================
function MeetingSummary {
    param(
        [array] $Time,
        $MeetingChanges,
        $Entry,
        [switch] $LongVersion,
        [switch] $ShortVersion
    )

    $InitialSubject = "Subject: " + $Entry.NormalizedSubject
    $InitialOrganizer = "Organizer: " + $Entry.SentRepresentingDisplayName
    $InitialSender = "Sender: " + $Entry.SentRepresentingDisplayName
    $InitialToList = "To List: " + $Entry.DisplayAttendeesAll
    $InitialLocation = "Location: " + $Entry.Location

    if ($ShortVersion -or $LongVersion) {
        $InitialStartTime = "StartTime: " + $Entry.StartTime.ToString()
        $InitialEndTime = "EndTime: " + $Entry.EndTime.ToString()
    }

    if ($longVersion -and ($Entry.Timezone -ne "")) {
        $InitialTimeZone = "Time Zone: " + $Entry.Timezone
    } else {
        $InitialTimeZone = "Time Zone: Not Populated"
    }

    if ($Entry.AppointmentRecurring) {
        $InitialRecurring = "Recurring: Yes - Recurring"
    } else {
        $InitialRecurring = "Recurring: No - Single instance"
    }

    if ($longVersion -and $Entry.AppointmentRecurring) {
        $InitialRecurrencePattern = "RecurrencePattern: " + $Entry.RecurrencePattern
        $InitialSeriesStartTime = "Series StartTime: " + $Entry.StartTime.ToString() + "Z"
        $InitialSeriesEndTime = "Series EndTime: " + $Entry.StartTime.ToString() + "Z"
        if (!$Entry.ViewEndTime) {
            $InitialEndDate = "Meeting Series does not have an End Date."
        }
    }

    if (!$Time) {
        $Time = $CalLog.LastModifiedTime.ToString()
    }

    if (!$MeetingChanges) {
        $MeetingChanges = @()
        $MeetingChanges += $InitialSubject, $InitialOrganizer, $InitialSender, $InitialToList, $InitialLocation, $InitialStartTime, $InitialEndTime, $InitialTimeZone, $InitialRecurring, $InitialRecurrencePattern, $InitialSeriesStartTime , $InitialSeriesEndTime , $InitialEndDate
    }

    if ($ShortVersion) {
        $MeetingChanges = @()
        $MeetingChanges += $InitialToList, $InitialLocation, $InitialStartTime, $InitialEndTime, $InitialRecurring
    }

    # Convert-Data -ArrayNames "Time", "MeetingChanges" >> $Script:TimeLineFilename
    $TimeLineOutput = Convert-Data -ArrayNames "Time", "MeetingChanges"

    $TimeLineOutput | Export-Csv -Path $Script:TimeLineFilename -NoTypeInformation -Encoding UTF8 -Append
    $TimeLineOutput
}

