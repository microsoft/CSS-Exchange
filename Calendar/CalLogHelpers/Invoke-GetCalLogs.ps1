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
"ClientBuildVersion",
"ClientIntent",
"ClientProcessName",
"CreationTime",
"RequestChangeMeetingOrganizerMetadataRaw",
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
"IsException",
"IsMeeting",
"IsOrganizerProperty",
"IsSharedInEvent",
"ItemID",
"LogBodyStats",
"LogClientInfoString",
"LogRowType",
"LogTimestamp",
"NormalizedSubject",
"OriginalStartDate",
"ReminderDueByInternal",
"ReminderIsSetInternal",
"ReminderMinutesBeforeStartInternal",
"SendMeetingMessagesDiagnostics",
"Sensitivity",
"SentRepresentingDisplayName",
"ShortClientInfoString",
"TimeZone",
"TransferredDestinationICalUid",
"TransferredDestinationOrganizerId",
"TransferredOriginalICalUid",
"TransferredOriginalOrganizerId"

$LogLimit = 2000

if ($ShortLogs.IsPresent) {
    $LogLimit = 500
}

if ($MaxLogs.IsPresent) {
    $LogLimit = 12000
}

$LimitedItemClasses = @(
    "IPM.Appointment",
    "IPM.Schedule.Meeting.Request",
    "IPM.Schedule.Meeting.Canceled",
    "IPM.Schedule.Meeting.Forwarded"
)

<#
.SYNOPSIS
Run Get-CalendarDiagnosticObjects for passed in User with Subject or MeetingID.
#>
function GetCalendarDiagnosticObjects {
    param(
        [string]$Identity,
        [string]$Subject,
        [string]$MeetingID,
        [datetime]$ExceptionDateOverride
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

    $isExceptionOverrideCall = $PSBoundParameters.ContainsKey('ExceptionDateOverride') -and $null -ne $ExceptionDateOverride

    if ($TrackingLogs -eq $true) {
        if (-not $isExceptionOverrideCall) {
            Write-Host -ForegroundColor Yellow "Including Tracking Logs in the output."
        }
        $script:CustomPropertyNameList += "AttendeeListDetails", "AttendeeCollection"
        $params.Add("ShouldFetchAttendeeCollection", $true)
        $params.Remove("CustomPropertyName")
        $params.Add("CustomPropertyName", $script:CustomPropertyNameList)
    }

    $effectiveExceptionDate = if ($PSBoundParameters.ContainsKey('ExceptionDateOverride') -and $null -ne $ExceptionDateOverride) { $ExceptionDateOverride } else { $ExceptionDate }

    if (-not [string]::IsNullOrEmpty($effectiveExceptionDate)) {
        Write-Host -ForegroundColor Green "---------------------------------------"
        $exceptionDateLabel = if ($effectiveExceptionDate -is [datetime]) { $effectiveExceptionDate.ToString('MM/dd/yyyy') } else { [string]$effectiveExceptionDate }
        Write-Host -ForegroundColor Green "Pulling all the Exceptions for [$exceptionDateLabel] and adding them to the output."
        Write-Host -ForegroundColor Green "---------------------------------------"
        $params.Add("AnalyzeExceptionWithOriginalStartDate", $effectiveExceptionDate)
    }

    if ($MaxLogs.IsPresent) {
        Write-Host -ForegroundColor Yellow "Limiting the number of logs to $LogLimit, and limiting the number of Item Classes retrieved."
        $params.Add("ItemClass", $LimitedItemClasses)
    }

    if ($null -ne $CustomProperty) {
        Write-Host -ForegroundColor Yellow "Adding custom properties to the RAW output."
        $params.Remove("CustomPropertyName")
        $script:CustomPropertyNameList += $CustomProperty
        Write-Host -ForegroundColor Yellow "Adding extra CustomProperty: [$CustomProperty]"
        $params.Add("CustomPropertyName", $script:CustomPropertyNameList)
    }

    # Use 3>$null to suppress "Non-view properties may not be accurate for exception items"
    # warnings from Get-CalendarDiagnosticObjects (remote session warnings bypass WarningAction/Preference).
    if ($Identity -and $MeetingID) {
        Write-Verbose "Getting CalLogs for [$Identity] with MeetingID [$MeetingID]."
        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
            Write-Host -ForegroundColor Yellow ($params.GetEnumerator() | ForEach-Object { "`t$($_.Key) = $($_.Value)`n" })
        }
        $CalLogs = Get-CalendarDiagnosticObjects @params -MeetingID $MeetingID 3>$null
    } elseif ($Identity -and $Subject ) {
        Write-Verbose "Getting CalLogs for [$Identity] with Subject [$Subject]."
        $CalLogs = Get-CalendarDiagnosticObjects @params -Subject $Subject 3>$null

        # No Results, do a Deep search with ExactMatch.
        if ($CalLogs.count -lt 1) {
            $CalLogs = Get-CalendarDiagnosticObjects @Params -Subject $Subject -ExactMatch $true 3>$null
        }
    }

    if (-not $isExceptionOverrideCall) {
        Write-Host "Found $($CalLogs.count) Calendar Logs for [$Identity]"
    }
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
    Write-Host "Getting CalLogs from [$Identity] with subject [$Subject]"
    $script:CurrentIdentityRunStartTime = Get-Date

    $InitialCDOs = GetCalendarDiagnosticObjects -Identity $Identity -Subject $Subject

    # Find all the unique Global Object IDs
    $GlobalObjectIds = @($InitialCDOs.CleanGlobalObjectId | Where-Object {
            -not [string]::IsNullOrEmpty($_) -and
            $_ -ne "NotFound" -and
            $_ -ne "InvalidSchemaPropertyName" -and
            $_.Length -ge 90
        } | Select-Object -Unique)
    $script:SubjectMeetingIdCount = $GlobalObjectIds.Count
    $script:SubjectResolvedMeetingId = $null
    $script:SubjectCanCollectExceptions = $false
    $script:SubjectSkippedExceptionCollection = $false
    Write-Host "Found $($GlobalObjectIds.count) unique GlobalObjectIds."
    Write-Host "Getting the set of CalLogs for each GlobalObjectID."

    if ($GlobalObjectIds.count -eq 1) {
        $script:SubjectResolvedMeetingId = $GlobalObjectIds[0]
        $script:SubjectCanCollectExceptions = $Exceptions.IsPresent -and [string]::IsNullOrEmpty($ExceptionDate)
        $script:GCDO = $InitialCDOs; # use the CalLogs that we already have, since there is only one.
        if ($Exceptions.IsPresent -and [string]::IsNullOrEmpty($ExceptionDate)) {
            Write-Host -ForegroundColor Yellow "Subject search resolved to one MeetingID [$($script:SubjectResolvedMeetingId)]. Collecting Exceptions by default."
            CollectExceptionLogs -Identity $Identity -MeetingID $script:SubjectResolvedMeetingId
        } elseif (-not [string]::IsNullOrEmpty($ExceptionDate)) {
            $script:ExceptionCollectionStatus = "SkippedUntilMeetingIdChosen"
            Write-Host -ForegroundColor Yellow "Subject search resolved to one MeetingID [$($script:SubjectResolvedMeetingId)], but -ExceptionDate requires rerunning with -MeetingID for targeted Exception collection."
        } else {
            $script:ExceptionCollectionStatus = "SkippedBySwitch"
            Write-Host -ForegroundColor Green "Subject search resolved to one MeetingID [$($script:SubjectResolvedMeetingId)], but Exception collection was skipped."
        }
        BuildCSV
        BuildTimeline
    } elseif ($GlobalObjectIds.count -gt 1) {
        $script:SubjectSkippedExceptionCollection = $true
        $script:ExceptionCollectionStatus = "SkippedMultipleMeetingIds"
        Write-Host "Found multiple GlobalObjectIds: $($GlobalObjectIds.Count)."
        Write-Host -ForegroundColor Yellow "Exception collection is skipped when Subject search resolves to more than one MeetingID."
        Write-Host -ForegroundColor Yellow "Re-run with one of these MeetingIDs to collect meeting exceptions:"
        foreach ($MID in $GlobalObjectIds) {
            Write-Host -ForegroundColor Yellow "  -MeetingID $MID"
        }
        foreach ($MID in $GlobalObjectIds) {
            $script:CurrentIdentityRunStartTime = Get-Date
            Write-DashLineBoxColor "Processing MeetingID: [$MID]"
            $script:GCDO = GetCalendarDiagnosticObjects -Identity $Identity -MeetingID $MID
            Write-Verbose "Found $($GCDO.count) CalLogs with MeetingID[$MID] ."
            BuildCSV
            BuildTimeline
        }
    } else {
        $script:ExceptionCollectionStatus = "NoMeetingId"
        Write-Warning "No CalLogs were found."
    }
}
