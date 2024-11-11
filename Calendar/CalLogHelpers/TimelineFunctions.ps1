# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ===================================================================================================
# BuildTimeline
# ===================================================================================================

<#
.SYNOPSIS
    Tries to builds a timeline of the history of the meeting based on the diagnostic objects.

.DESCRIPTION
    By using the time sorted diagnostic objects for one user on one meeting, we try to give a high level
    overview of what happened to the meeting. This can be use to get a quick overview of the meeting and
    then you can look into the CalLog in Excel to get more details.

    The timeline will skip a lot of the noise (isIgnorable) in the CalLogs. It skips EBA (Event Based Assistants),
    and other EXO internal processes, which are (99% of the time) not interesting to the end user and just setting
    hidden internal properties (i.e. things like HasBeenIndex, etc.)

    It also skips items from Shared Calendars, which are calendars that have a Modern Sharing relationship setup,
    which creates a replicated copy of another users. If you want to look at the actions this user took on
    another users calendar, you can look at that users Calendar Logs.

.NOTES
    The timeline will never be perfect, but if you see a way to make it more understandable, readable, etc.,
    please let me know or fix it yourself on GitHub.
    I use a iterative approach to building this, so it will get better over time.
#>

function FindOrganizer {
    param (
        $CalLog
    )
    $Script:Organizer = "Unknown"
    if ($null -ne $CalLog.From) {
        if ($null -ne $CalLog.From.SmtpEmailAddress) {
            $Script:Organizer = $($CalLog.From.SmtpEmailAddress)
        } elseif ($null -ne $CalLog.From.DisplayName) {
            $Script:Organizer = $($CalLog.From.DisplayName)
        } else {
            $Script:Organizer = $($CalLog.From)
        }
    }
    Write-Host "Setting Organizer to : [$Script:Organizer]"
}

function FindFirstMeeting {
    [array]$IpmAppointments = $script:GCDO | Where-Object { $_.ItemClass -eq "IPM.Appointment" -and $_.ExternalSharingMasterId -eq "NotFound" }
    if ($IpmAppointments.count -eq 0) {
        Write-Host "All CalLogs are from Shared Calendar, getting values from first IPM.Appointment."
        $IpmAppointments = $script:GCDO | Where-Object { $_.ItemClass -eq "IPM.Appointment" }
    }
    if ($IpmAppointments.count -eq 0) {
        Write-Host -ForegroundColor Red "Warning: Cannot find any IPM.Appointments, if this is the Organizer, check for the Outlook Bifurcation issue."
        Write-Host -ForegroundColor Red "Warning: No IPM.Appointment found. CalLogs start to expire after 31 days."
        return $null
    } else {
        return $IpmAppointments[0]
    }
}

function BuildTimeline {
    $script:TimeLineOutput = @()

    $script:FirstLog = FindFirstMeeting
    FindOrganizer($script:FirstLog)

    # Ignorable and items from Shared Calendars are not included in the TimeLine.
    [array]$InterestingCalLogs = $script:EnhancedCalLogs | Where-Object { $_.LogRowType -eq "Interesting" -and $_.SharedFolderName -eq "Not Shared" }

    if ($InterestingCalLogs.count -eq 0) {
        Write-Host "All CalLogs are Ignorable, nothing to create a timeline with, displaying initial values."
    } else {
        Write-Host "Found $($script:EnhancedCalLogs.count) Log entries, only the $($InterestingCalLogs.count) Non-Ignorable entries will be analyzed in the TimeLine. `n"
    }

    if ($script:CalLogsDisabled) {
        Write-Host -ForegroundColor Red "Warning: CalLogs are disabled for this user, Timeline / CalLogs will be incomplete."
        return
    }

    Write-DashLineBoxColor "  TimeLine for: [$Identity]",
    "CollectionDate: $($(Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))",
    "ScriptVersion: $ScriptVersion",
    "  Subject: $($script:GCDO[0].NormalizedSubject)",
    "  Organizer: $Script:Organizer",
    "  MeetingID: $($script:GCDO[0].CleanGlobalObjectId)"
    [array]$Header = "MeetingID: "+ ($script:GCDO[0].CleanGlobalObjectId)

    CreateMeetingSummary -Time "Calendar Timeline for Meeting" -MeetingChanges $Header
    if ($null -ne $FirstLog) {
        CreateMeetingSummary -Time "Initial Message Values" -Entry $script:FirstLog -LongVersion
    }

    # Look at each CalLog and build the Timeline
    foreach ($CalLog in $InterestingCalLogs) {
        [bool] $script:MeetingSummaryNeeded = $False
        [bool] $script:AddChangedProperties = $False

        $MeetingChanges = CreateTimelineRow
        # Create the Timeline by adding to Time to the generated MeetingChanges
        $Time = "$($($CalLog.LogRow).toString().PadRight(5)) -- $(ConvertDateTime($CalLog.LogTimestamp))"

        if ($MeetingChanges) {
            if ($script:MeetingSummaryNeeded) {
                CreateMeetingSummary -Time $Time -MeetingChanges $MeetingChanges
                CreateMeetingSummary -Time " " -ShortVersion -Entry $CalLog
            } else {
                CreateMeetingSummary -Time $Time -MeetingChanges $MeetingChanges
                if ($script:AddChangedProperties) {
                    FindChangedProperties
                }
            }
        }

        # Setup Previous log (if current logs is an IPM.Appointment)
        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "Ipm.Appointment" -or $CalendarItemTypes.($CalLog.ItemClass) -eq "Exception") {
            $script:PreviousCalLog = $CalLog
        }
    }

    Export-Timeline
}
