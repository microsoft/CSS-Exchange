# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ===================================================================================================
# Constants to support the script
# ===================================================================================================

$script:CalendarItemTypes = @{
    'IPM.Schedule.Meeting.Request.AttendeeListReplication' = "AttendeeList"
    'IPM.Schedule.Meeting.Canceled'                        = "Cancellation"
    'IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}' = "Exception"
    'IPM.Schedule.Meeting.Notification.Forward'            = "Forward.Notification"
    'IPM.Appointment'                                      = "Ipm.Appointment"
    'IPM.Appointment.MP'                                   = "Ipm.Appointment"
    'IPM.Schedule.Meeting.Request'                         = "Meeting.Request"
    'IPM.CalendarSharing.EventUpdate'                      = "SharingCFM"
    'IPM.CalendarSharing.EventDelete'                      = "SharingDelete"
    'IPM.Schedule.Meeting.Resp'                            = "Resp.Any"
    'IPM.Schedule.Meeting.Resp.Neg'                        = "Resp.Neg"
    'IPM.Schedule.Meeting.Resp.Tent'                       = "Resp.Tent"
    'IPM.Schedule.Meeting.Resp.Pos'                        = "Resp.Pos"
    '(Occurrence Deleted)'                                 = "Exception.Deleted"
}

# ===================================================================================================
# Functions to support the script
# ===================================================================================================

<#
.SYNOPSIS
Looks to see if there is a Mapping of ExternalMasterID to FolderName
#>
function MapSharedFolder {
    param(
        $ExternalMasterID
    )
    if ($ExternalMasterID -eq "NotFound") {
        return "Not Shared"
    } else {
        $SharedFolders[$ExternalMasterID]
    }
}

<#
.SYNOPSIS
Replaces a value of NotFound with a blank string.
#>
function ReplaceNotFound {
    param (
        $Value
    )
    if ($Value -eq "NotFound") {
        return ""
    } else {
        return $Value
    }
}

<#
.SYNOPSIS
Creates a Mapping of ExternalMasterID to FolderName
#>
function CreateExternalMasterIDMap {
    # This function will create a Map of the log folder to ExternalMasterID
    $script:SharedFolders = [System.Collections.SortedList]::new()
    Write-Verbose "Starting CreateExternalMasterIDMap"

    foreach ($ExternalID in $script:GCDO.ExternalSharingMasterId | Select-Object -Unique) {
        if ($ExternalID -eq "NotFound") {
            continue
        }

        $AllFolderNames = @($script:GCDO | Where-Object { $_.ExternalSharingMasterId -eq $ExternalID } | Select-Object -ExpandProperty OriginalParentDisplayName | Select-Object -Unique)

        if ($AllFolderNames.count -gt 1) {
            # We have 2+ FolderNames, Need to find the best one. Remove 'Calendar' from possible names
            $AllFolderNames = $AllFolderNames | Where-Object { $_ -notmatch 'Calendar' } # Need a better way to do this for other languages...
        }

        if ($AllFolderNames.Count -eq 0) {
            $SharedFolders[$ExternalID] = "UnknownSharedCalendarCopy"
            Write-Host -ForegroundColor red "Found Zero to map to."
        }

        if ($AllFolderNames.Count -eq 1) {
            $SharedFolders[$ExternalID] = $AllFolderNames
            Write-Verbose "Found map: [$AllFolderNames] is for $ExternalID"
        } else {
            # we still have multiple possible Folder Names, need to chose one or combine
            Write-Host -ForegroundColor Red "Unable to Get Exact Folder for $ExternalID"
            Write-Host -ForegroundColor Red "Found $($AllFolderNames.count) possible folders"

            if ($AllFolderNames.Count -eq 2) {
                $SharedFolders[$ExternalID] = $AllFolderNames[0] + $AllFolderNames[1]
            } else {
                $SharedFolders[$ExternalID] = "UnknownSharedCalendarCopy"
            }
        }
    }

    Write-Host -ForegroundColor Green "Created the following Shared Calendar Mapping:"
    foreach ($Key in $SharedFolders.Keys) {
        Write-Host -ForegroundColor Green "$Key : $($SharedFolders[$Key])"
    }
    # ToDo: Need to check for multiple ExternalSharingMasterId pointing to the same FolderName
    Write-Verbose "Created the following Mapping :"
    Write-Verbose $SharedFolders
}

<#
.SYNOPSIS
Convert a csv value to multiLine.
#>
function MultiLineFormat {
    param(
        $PassedString
    )
    $PassedString = $PassedString -replace "},", "},`n"
    return $PassedString.Trim()
}

# ===================================================================================================
# Build CSV to output
# ===================================================================================================

<#
.SYNOPSIS
Builds the CSV output from the Calendar Diagnostic Objects
#>
function BuildCSV {

    Write-Host "Starting to Process Calendar Logs..."
    $GCDOResults = @()
    $script:MailboxList = @{}
    Write-Host "Creating Map of Mailboxes to CNs..."
    CreateExternalMasterIDMap

    ConvertCNtoSMTP

    Write-Host "Making Calendar Logs more readable..."
    $Index = 0
    foreach ($CalLog in $script:GCDO) {
        $Index++
        $ItemType = $CalendarItemTypes.($CalLog.ItemClass)

        # CleanNotFounds
        $PropsToClean = "FreeBusyStatus", "ClientIntent", "AppointmentSequenceNumber", "AppointmentLastSequenceNumber", "RecurrencePattern", "AppointmentAuxiliaryFlags", "EventEmailReminderTimer", "IsSeriesCancelled", "AppointmentCounterProposal", "MeetingRequestType", "SendMeetingMessagesDiagnostics"
        foreach ($Prop in $PropsToClean) {
            # Exception objects, etc. don't have these properties.
            if ($null -ne $CalLog.$Prop) {
                $CalLog.$Prop = ReplaceNotFound($CalLog.$Prop)
            }
        }

        # Record one row
        $GCDOResults += [PSCustomObject]@{
            'LogRow'                         = $Index
            'LogTimestamp'                   = ConvertDateTime($CalLog.LogTimestamp)
            'LogRowType'                     = $CalLog.LogRowType.ToString()
            'SubjectProperty'                = $CalLog.SubjectProperty
            'Client'                         = $CalLog.ShortClientInfoString
            'LogClientInfoString'            = $CalLog.LogClientInfoString
            'TriggerAction'                  = $CalLog.CalendarLogTriggerAction
            'ItemClass'                      = $ItemType
            'Seq:Exp:ItemVersion'            = CompressVersionInfo($CalLog)
            'Organizer'                      = $CalLog.From.FriendlyDisplayName
            'From'                           = GetBestFromAddress($CalLog.From)
            'FreeBusy'                       = $CalLog.FreeBusyStatus.ToString()
            'ResponsibleUser'                = GetSMTPAddress($CalLog.ResponsibleUserName)
            'Sender'                         = GetSMTPAddress($CalLog.SenderEmailAddress)
            'LogFolder'                      = $CalLog.ParentDisplayName
            'OriginalLogFolder'              = $CalLog.OriginalParentDisplayName
            'SharedFolderName'               = MapSharedFolder($CalLog.ExternalSharingMasterId)
            'ReceivedBy'                     = $CalLog.ReceivedBy.SmtpEmailAddress
            'ReceivedRepresenting'           = $CalLog.ReceivedRepresenting.SmtpEmailAddress
            'MeetingRequestType'             = $CalLog.MeetingRequestType.ToString()
            'StartTime'                      = ConvertDateTime($CalLog.StartTime)
            'EndTime'                        = ConvertDateTime($CalLog.EndTime)
            'OriginalStartDate'              = ConvertDateTime($CalLog.OriginalStartDate)
            'TimeZone'                       = $CalLog.TimeZone
            'Location'                       = $CalLog.Location
            'CalendarItemType'               = $CalLog.CalendarItemType.ToString()
            'IsException'                    = $CalLog.IsException
            'RecurrencePattern'              = $CalLog.RecurrencePattern
            'AppointmentAuxiliaryFlags'      = $CalLog.AppointmentAuxiliaryFlags.ToString()
            'DisplayAttendeesAll'            = $CalLog.DisplayAttendeesAll
            'AttendeeCount'                  = GetAttendeeCount($CalLog.DisplayAttendeesAll)
            'AppointmentState'               = $CalLog.AppointmentState.ToString()
            'ResponseType'                   = $CalLog.ResponseType.ToString()
            'ClientIntent'                   = $CalLog.ClientIntent.ToString()
            'AppointmentRecurring'           = $CalLog.AppointmentRecurring
            'HasAttachment'                  = $CalLog.HasAttachment
            'IsCancelled'                    = $CalLog.IsCancelled
            'IsAllDayEvent'                  = $CalLog.IsAllDayEvent
            'IsSeriesCancelled'              = $CalLog.IsSeriesCancelled
            'SendMeetingMessagesDiagnostics' = $CalLog.SendMeetingMessagesDiagnostics
            'AttendeeCollection'             = MultiLineFormat($CalLog.AttendeeCollection)
            'CalendarLogRequestId'           = $CalLog.CalendarLogRequestId.ToString()    # Move to front.../ Format in groups???
        }
    }
    $script:EnhancedCalLogs = $GCDOResults

    Write-Host -ForegroundColor Green "Calendar Logs have been processed, Exporting logs to file..."
    Export-CalLog
}

function ConvertDateTime {
    param(
        [string] $DateTime
    )
    if ([string]::IsNullOrEmpty($DateTime) -or
        $DateTime -eq "N/A" -or
        $DateTime -eq "NotFound") {
        return ""
    }
    return [DateTime]$DateTime
}

function GetAttendeeCount {
    param(
        [string] $AttendeeCollection
    )
    if ($From.SmtpAddress -ne "NotFound") {
        return ($AttendeeCollection -split ';').Count
    } else {
        return "-"
    }
}

function CompressVersionInfo {
    param(
        $CalLog
    )
    [string] $CompressedString = ""
    if ($CalLog.AppointmentSequenceNumber -eq "NotFound" -or [string]::IsNullOrEmpty($CalLog.AppointmentSequenceNumber)) {
        $CompressedString = "-:"
    } else {
        $CompressedString = $CalLog.AppointmentSequenceNumber.ToString() + ":"
    }
    if ($CalLog.AppointmentLastSequenceNumber -eq "NotFound" -or [string]::IsNullOrEmpty($CalLog.AppointmentLastSequenceNumber)) {
        $CompressedString += "-:"
    } else {
        $CompressedString += $CalLog.AppointmentLastSequenceNumber.ToString() + ":"
    }
    if ($CalLog.ItemVersion -eq "NotFound" -or [string]::IsNullOrEmpty($CalLog.ItemVersion)) {
        $CompressedString += "-"
    } else {
        $CompressedString += $CalLog.ItemVersion.ToString()
    }

    return $CompressedString
}
