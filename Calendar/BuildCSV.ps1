# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# BuildCSV.ps1
# This script is used to support the Get-CalendarDiagnosticObjectsSummary.ps1 script.

# ===================================================================================================
# Build CSV to output
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
    Write-Host "Creating Map of Mailboxes to CN's..."
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
