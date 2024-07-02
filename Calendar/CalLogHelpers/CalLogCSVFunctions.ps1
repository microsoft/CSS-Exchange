﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ===================================================================================================
# Constants to support the script
# ===================================================================================================

$script:CalendarItemTypes = @{
    'IPM.Schedule.Meeting.Request.AttendeeListReplication' = "AttendeeList"
    'IPM.Schedule.Meeting.Canceled'                        = "Cancellation"
    'IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}' = "ExceptionMsgClass"
    'IPM.Schedule.Meeting.Notification.Forward'            = "ForwardNotification"
    'IPM.Appointment'                                      = "IpmAppointment"
    'IPM.Appointment.MP'                                   = "IpmAppointment"
    'IPM.Schedule.Meeting.Request'                         = "MeetingRequest"
    'IPM.CalendarSharing.EventUpdate'                      = "SharingCFM"
    'IPM.CalendarSharing.EventDelete'                      = "SharingDelete"
    'IPM.Schedule.Meeting.Resp'                            = "RespAny"
    'IPM.Schedule.Meeting.Resp.Neg'                        = "RespNeg"
    'IPM.Schedule.Meeting.Resp.Tent'                       = "RespTent"
    'IPM.Schedule.Meeting.Resp.Pos'                        = "RespPos"
}

# ===================================================================================================
# Functions to support the script
# ===================================================================================================

$ResponseTypeOptions = @{
    '0' = "None"
    "1" = "Organizer"
    '2' = "Tentative"
    '3' = "Accept"
    '4' = "Decline"
    '5' = "Not Responded"
}
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
    $script:SharedFolders = @{}
    Write-Verbose "Starting CreateExternalMasterIDMap"

    foreach ($ExternalID in $script:GCDO.ExternalSharingMasterId | Select-Object -Unique) {
        if ($ExternalID -eq "NotFound") {
            continue
        }

        $AllFolderNames = @($script:GCDO | Where-Object { $_.ExternalSharingMasterId -eq $ExternalID } | Select-Object -ExpandProperty OriginalParentDisplayName | Select-Object -Unique)

        if ($AllFolderNames.count -gt 1) {
            # We have 2+ FolderNames, Need to find the best one. #remove Calendar
            $AllFolderNames = $AllFolderNames | Where-Object { $_ -notmatch 'Calendar' } # This will not work for non-english
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
    param(
        $Identity
    )

    Write-Host "Starting to Process Calendar Logs..."
    $GCDOResults = @()
    $IsFromSharedCalendar = @()
    $IsIgnorable = @()
    $script:MailboxList = @{}
    Write-Host "Creating Map of Mailboxes to CNs..."
    CreateExternalMasterIDMap

    $ThisMeetingID = $script:GCDO.CleanGlobalObjectId | Select-Object -Unique
    $ShortMeetingID = $ThisMeetingID.Substring($ThisMeetingID.length - 6)

    ConvertCNtoSMTP

    Write-Host "Making Calendar Logs more readable..."
    $Index = 0
    foreach ($CalLog in $script:GCDO) {
        $CalLogACP = $CalLog.AppointmentCounterProposal.ToString()
        $Index++
        $ItemType = $CalendarItemTypes.($CalLog.ItemClass)
        $ShortClientName = @()
        $script:KeyInput = $CalLog.ClientInfoString
        $ResponseType = $ResponseTypeOptions.($CalLog.ResponseType.ToString())

        $ShortClientName = CreateShortClientName($CalLog.ClientInfoString)

        $IsIgnorable = SetIsIgnorable($CalLog)

        # CleanNotFounds
        $PropsToClean = "FreeBusyStatus", "ClientIntent", "AppointmentLastSequenceNumber", "RecurrencePattern", "AppointmentAuxiliaryFlags", "EventEmailReminderTimer", "IsSeriesCancelled", "AppointmentCounterProposal", "MeetingRequestType", "SendMeetingMessagesDiagnostics"
        foreach ($Prop in $PropsToClean) {
            # Exception objects, etc. don't have these properties.
            if ($null -ne $CalLog.$Prop) {
                $CalLog.$Prop = ReplaceNotFound($CalLog.$Prop)
            }
        }

        if ($CalLogACP -eq "NotFound") {
            $CalLogACP = ''
        }

        $IsFromSharedCalendar = ($null -ne $CalLog.externalSharingMasterId -and $CalLog.externalSharingMasterId -ne "NotFound")

        # Record one row
        $GCDOResults += [PSCustomObject]@{
            'LogRow'                         = $Index
            'LastModifiedTime'               = $CalLog.OriginalLastModifiedTime
            'IsIgnorable'                    = $IsIgnorable
            'SubjectProperty'                = $CalLog.SubjectProperty
            'Client'                         = $ShortClientName
            'ShortClientInfoString'          = $CalLog.ShortClientInfoString
            'ClientInfoString'               = $CalLog.ClientInfoString
            'TriggerAction'                  = $CalLog.CalendarLogTriggerAction
            'ItemClass'                      = $CalLog.ItemClass
            'ItemVersion'                    = $CalLog.ItemVersion
            'AppointmentSequenceNumber'      = $CalLog.AppointmentSequenceNumber
            'AppointmentLastSequenceNumber'  = $CalLog.AppointmentLastSequenceNumber  # Need to find out how we can combine these two...
            'Organizer'                      = $CalLog.From.FriendlyDisplayName
            'From'                           = GetBestFromAddress($CalLog.From)
            'FreeBusyStatus'                 = $CalLog.FreeBusyStatus
            'ResponsibleUser'                = GetSMTPAddress($CalLog.ResponsibleUserName)
            'Sender'                         = GetSMTPAddress($CalLog.SenderEmailAddress)
            'LogFolder'                      = $CalLog.ParentDisplayName
            'OriginalLogFolder'              = $CalLog.OriginalParentDisplayName
            'SharedFolderName'               = MapSharedFolder($CalLog.ExternalSharingMasterId)
            'IsFromSharedCalendar'           = $IsFromSharedCalendar
            'ExternalSharingMasterId'        = $CalLog.ExternalSharingMasterId
            'ReceivedBy'                     = $CalLog.ReceivedBy.SmtpEmailAddress
            'ReceivedRepresenting'           = $CalLog.ReceivedRepresenting.SmtpEmailAddress
            'MeetingRequestType'             = $CalLog.MeetingRequestType
            'StartTime'                      = $CalLog.StartTime
            'EndTime'                        = $CalLog.EndTime
            'TimeZone'                       = $CalLog.TimeZone
            'Location'                       = $CalLog.Location
            'ItemType'                       = $ItemType
            'CalendarItemType'               = $CalLog.CalendarItemType
            'IsException'                    = $CalLog.IsException
            'RecurrencePattern'              = $CalLog.RecurrencePattern
            'AppointmentAuxiliaryFlags'      = $CalLog.AppointmentAuxiliaryFlags.ToString()
            'DisplayAttendeesAll'            = $CalLog.DisplayAttendeesAll
            'AttendeeCount'                  = ($CalLog.DisplayAttendeesAll -split ';').Count
            'AppointmentState'               = $CalLog.AppointmentState.ToString()
            'ResponseType'                   = $ResponseType
            'AppointmentCounterProposal'     = $CalLogACP
            'SentRepresentingEmailAddress'   = $CalLog.SentRepresentingEmailAddress
            'SentRepresentingSMTPAddress'    = GetSMTPAddress($CalLog.SentRepresentingEmailAddress)
            'SentRepresentingDisplayName'    = $CalLog.SentRepresentingDisplayName
            'ResponsibleUserSMTPAddress'     = GetSMTPAddress($CalLog.ResponsibleUserName)
            'ResponsibleUserName'            = $CalLog.ResponsibleUserName
            'SenderEmailAddress'             = $CalLog.SenderEmailAddress
            'SenderSMTPAddress'              = GetSMTPAddress($CalLog.SenderEmailAddress)
            'ClientIntent'                   = $CalLog.ClientIntent.ToString()
            'NormalizedSubject'              = $CalLog.NormalizedSubject
            'AppointmentRecurring'           = $CalLog.AppointmentRecurring
            'HasAttachment'                  = $CalLog.HasAttachment
            'IsCancelled'                    = $CalLog.IsCancelled
            'IsAllDayEvent'                  = $CalLog.IsAllDayEvent
            'IsSeriesCancelled'              = $CalLog.IsSeriesCancelled
            'CreationTime'                   = $CalLog.CreationTime
            'OriginalStartDate'              = $CalLog.OriginalStartDate
            'SendMeetingMessagesDiagnostics' = $CalLog.SendMeetingMessagesDiagnostics
            'EventEmailReminderTimer'        = $CalLog.EventEmailReminderTimer
            'AttendeeListDetails'            = MultiLineFormat($CalLog.AttendeeListDetails)
            'AttendeeCollection'             = MultiLineFormat($CalLog.AttendeeCollection)
            'CalendarLogRequestId'           = $CalLog.CalendarLogRequestId.ToString()
            'AppointmentRecurrenceBlob'      = $CalLog.AppointmentRecurrenceBlob
            'GlobalObjectId'                 = $CalLog.GlobalObjectId
            'CleanGlobalObjectId'            = $CalLog.CleanGlobalObjectId
        }
    }
    $script:Results = $GCDOResults

    # Automation won't have access to this file - will add code in next version to save contents to a variable
    #$Filename = "$($Results[0].ReceivedBy)_$ShortMeetingID.csv";

    if ($Identity -like "*@*") {
        $ShortName = $Identity.Split('@')[0]
    }
    $ShortName = $ShortName.Substring(0, [System.Math]::Min(20, $ShortName.Length))
    $Filename = "$($ShortName)_$ShortMeetingID.csv"
    $FilenameRaw = "$($ShortName)_RAW_$($ShortMeetingID).csv"

    Write-Host -ForegroundColor Cyan -NoNewline "Enhanced Calendar Logs for [$Identity] have been saved to : "
    Write-Host -ForegroundColor Yellow "$Filename"

    Write-Host -ForegroundColor Cyan -NoNewline "Raw Calendar Logs for [$Identity] have been saved to : "
    Write-Host -ForegroundColor Yellow "$FilenameRaw"

    $GCDOResults | Export-Csv -Path $Filename -NoTypeInformation -Encoding UTF8
    $script:GCDO | Export-Csv -Path $FilenameRaw -NoTypeInformation -Encoding UTF8
}
