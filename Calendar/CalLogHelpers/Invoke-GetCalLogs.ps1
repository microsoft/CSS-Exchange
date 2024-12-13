# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ===================================================================================================
# Constants to support the script
# ===================================================================================================

$script:CustomPropertyNameList =
"AppointmentCounterProposal",
"AppointmentLastSequenceNumber",
"AppointmentRecurring",
"CalendarItemType",
"CalendarLogTriggerAction",
"CalendarProcessed",
"ChangeList",
"ClientIntent",
"CreationTime",
"DisplayAttendeesCc",
"DisplayAttendeesTo",
"EventEmailReminderTimer",
"ExternalSharingMasterId",
"FreeBusyStatus",
"From",
"HasAttachment",
"InternetMessageId",
"IsAllDayEvent",
"IsCancelled",
"IsMeeting",
"IsOrganizerProperty",
"IsSharedInEvent",
"ItemID",
"LogClientInfoString",
"LogRowType",
"LogTimestamp",
"NormalizedSubject",
"OriginalStartDate",
"SendMeetingMessagesDiagnostics",
"Sensitivity",
"SentRepresentingDisplayName",
"SentRepresentingEmailAddress",
"ShortClientInfoString",
"TimeZone"

$LogLimit = 2000

if ($ShortLogs.IsPresent) {
    $LogLimit = 500
}

<#
.SYNOPSIS
Run Get-CalendarDiagnosticObjects for passed in User with Subject or MeetingID.
#>

function GetCalendarDiagnosticObjects {
    param(
        [string]$Identity,
        [string]$Subject,
        [string]$MeetingID
    )

    $params = @{
        Identity           = $Identity
        CustomPropertyName = $script:CustomPropertyNameList
        WarningAction      = "Ignore"
        MaxResults         = $LogLimit
        ResultSize         = $LogLimit
        ShouldBindToItem   = $true
        ShouldDecodeEnums  = $true
    }

    if ($TrackingLogs.IsPresent) {
        Write-Host -ForegroundColor Yellow "Including Tracking Logs in the output."
        $script:CustomPropertyNameList += "AttendeeListDetails", "AttendeeCollection"
        $params.Add("ShouldFetchAttendeeCollection", $true)
        $params.Remove("CustomPropertyName")
        $params.Add("CustomPropertyName", $script:CustomPropertyNameList)
    }

    if ($Identity -and $MeetingID) {
        Write-Verbose "Getting CalLogs for [$Identity] with MeetingID [$MeetingID]."
        $CalLogs = Get-CalendarDiagnosticObjects @params -MeetingID $MeetingID
    } elseif ($Identity -and $Subject ) {
        Write-Verbose "Getting CalLogs for [$Identity] with Subject [$Subject]."
        $CalLogs = Get-CalendarDiagnosticObjects @params -Subject $Subject

        # No Results, do a Deep search with ExactMatch.
        if ($CalLogs.count -lt 1) {
            $CalLogs = Get-CalendarDiagnosticObjects @Params -Subject $Subject -ExactMatch $true
        }
    }

    Write-Host "Found $($CalLogs.count) Calendar Logs for [$Identity]"
    return $CalLogs
}

<#
.SYNOPSIS
This function retrieves calendar logs from the specified source with a subject that matches the provided criteria.
.PARAMETER Identity
The Identity of the mailbox to get calendar logs from.
.PARAMETER Subject
The subject of the calendar logs to retrieve.
#>
function GetCalLogsWithSubject {
    param (
        [string] $Identity,
        [string] $Subject
    )
    Write-Host "Getting CalLogs from [$Identity] with subject [$Subject]]"

    $InitialCDOs = GetCalendarDiagnosticObjects -Identity $Identity -Subject $Subject
    $GlobalObjectIds = @()

    # Find all the unique Global Object IDs
    foreach ($ObjectId in $InitialCDOs.CleanGlobalObjectId) {
        if (![string]::IsNullOrEmpty($ObjectId) -and
            $ObjectId -ne "NotFound" -and
            $ObjectId -ne "InvalidSchemaPropertyName" -and
            $ObjectId.Length -ge 90) {
            $GlobalObjectIds += $ObjectId
        }
    }

    $GlobalObjectIds = $GlobalObjectIds | Select-Object -Unique
    Write-Host "Found $($GlobalObjectIds.count) unique GlobalObjectIds."
    Write-Host "Getting the set of CalLogs for each GlobalObjectID."

    if ($GlobalObjectIds.count -eq 1) {
        $script:GCDO = $InitialCDOs; # use the CalLogs that we already have, since there is only one.
        BuildCSV
        BuildTimeline
    } elseif ($GlobalObjectIds.count -gt 1) {
        Write-Host "Found multiple GlobalObjectIds: $($GlobalObjectIds.Count)."
        foreach ($MID in $GlobalObjectIds) {
            Write-DashLineBoxColor "Processing MeetingID: [$MID]"
            $script:GCDO = GetCalendarDiagnosticObjects -Identity $Identity -MeetingID $MID
            Write-Verbose "Found $($GCDO.count) CalLogs with MeetingID[$MID] ."
            BuildCSV
            BuildTimeline
        }
    } else {
        Write-Warning "No CalLogs were found."
    }
}
