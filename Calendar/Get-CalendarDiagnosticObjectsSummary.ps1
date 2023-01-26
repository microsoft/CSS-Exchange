# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# .DESCRIPTION
# This script runs the Get-CalendarDiagnosticObjects script and returns a summarized timeline of actions into clear english
#
# .PARAMETER Identity
# Address of User Mailbox to query
#
# .PARAMETER Subject
# Subject of the meeting to query
#
# .PARAMETER MeetingID
# The MeetingID of the meeting to query
#
# .EXAMPLE
# Get-CalendarDiagnosticObjectsSummary.ps1 -Identity user@contoso.com -MeetingID 040000008200E00074C5B7101A82E0080000000010E6401F9355D801000000000000000010000000996102014F1D484A8334C16DDBF8603E
#
# Get-CalendarDiagnosticObjectsSummary.ps1 -Identity user@contoso.com -Subject Test_OneTime_Meeting_Subject
#

[CmdLetBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Identity,
    [string]$Subject,
    [string]$MeetingID
)

function GetCalendarDiagnosticObjects {
    $CustomPropertyNameList = "AppointmentCounterProposal", "AppointmentRecurring", "CalendarItemType", "CalendarProcessed", "ClientIntent", "DisplayAttendeesCc", "DisplayAttendeesTo", "EventEmailReminderTimer", "ExternalSharingMasterId", "FreeBusyStatus", "From", "HasAttachment", "IsAllDayEvent", "IsCancelled", "IsMeeting", "MapiEndTime", "MapiStartTime", "OnlineMeetingConfLink", "OnlineMeetingExternalLink", "OnlineMeetingInternalLink", "SentRepresentingDisplayName", "SentRepresentingEmailAddress";
    if ($Identity -and $Subject -and $MeetingID) {
        $Global:GetCDO = Get-CalendarDiagnosticObjects -Identity $Identity -MeetingID $MeetingID -CustomPropertyNames $CustomPropertyNameList -WarningAction Ignore;
    }

    if ($Identity -and $Subject -and !$MeetingID) {
        $Global:GetCDO = Get-CalendarDiagnosticObjects -Identity $Identity -Subject $Subject -CustomPropertyNames $CustomPropertyNameList -WarningAction Ignore;
    }

    if ($Identity -and $MeetingID -and !$Subject) {
        $Global:GetCDO = Get-CalendarDiagnosticObjects -Identity $Identity -MeetingID $MeetingID -CustomPropertyNames $CustomPropertyNameList -WarningAction Ignore;
    }

    if ($Identity -and !$Subject -and !$MeetingID) {
        Write-Warning "Can't run command with just Identity, Subject or MeetingID is also needed";
        exit;
    }
}

GetCalendarDiagnosticObjects;

function FindMatch {
    param(
        [HashTable]$PassedHash
    )
    foreach ($val in $PassedHash.keys) {
        if ($Keyinput -like "*$val*") {
            return $PassedHash[$val];
        }
    }
}

function GetMailbox {
    param(
        [string]$Identity,
        [string]$Organization
    )

    if ($Identity -and $Organization) {
        $Global:GetMailboxOutput = Get-Mailbox -Identity $Identity -Organization $Organization  -ErrorAction stop;
        return $GetMailboxOutput;
    }
    if ($Identity -and !$Organization) {
        $Global:GetMailboxOutput = Get-Mailbox -Identity $Identity;
        return $GetMailboxOutput;
    }
}

function Transpose-Data {
    param(
        [Parameter(Mandatory = $True)]
        [string[]]$ArrayNames,
        [switch]$NoWarnings = $False
    )
    $ValidArrays, $ItemCounts = @(), @();
    $VariableLookup = @{};
    foreach ($Array in $ArrayNames) {
        try {
            $VariableData = Get-Variable -Name $Array -ErrorAction Stop;
            $VariableLookup[$Array] = $VariableData.Value;
            $ValidArrays += $Array;
            $ItemCounts += ($VariableData.Value | Measure-Object).Count;
        } catch {
            if (!$NoWarnings) {
                Write-Warning -Message "No variable found for [$Array]";
            }
        }
    }
    $MaxItemCount = ($ItemCounts | Measure-Object -Maximum).Maximum;
    $FinalArray = @();
    for ($Inc = 0; $Inc -lt $MaxItemCount; $Inc++) {
        $FinalObj = New-Object PsObject;
        foreach ($Item in $ValidArrays) {
            $FinalObj | Add-Member -MemberType NoteProperty -Name $Item -Value $VariableLookup[$Item][$Inc];
        }
        $FinalArray += $FinalObj;
    }
    return $TimeSum += $FinalArray;
    $FinalArray = @();
}

function GetDisplayName {
    param(
        $PassedValue
    )
    if ($PassedValue -match 'cn=([\w,\s.@-]*[^/])$') {
        $cNameMatch = $PassedValue -split "cn=";

        if ($cNameMatch[-1] -match "-[\w* -.]*") {
            $DisplayName = $cNameMatch.split('-')[-1];
        }
    }
    return $DisplayName;
}

function BuildCSV {
    $GCDOResults = @();
    $GlobalObjectId = @();
    $IsFromSharedCalendar = @();
    $CalendarItemType = @();
    $IsIgnorable = @();
    $ShortClientName = @();
    $ApptSequence = @();
    $Organizer = @();
    $ResponsibleUser = @();
    $MeetingID = @();
    $MailboxList = @{};

    $TestUser = GetMailbox -Identity $Identity;
    $Org = $TestUser.OrganizationalUnit.split('/')[-1];

    foreach ($ObjectId in $GCDO.CleanGlobalObjectId) {
        if (![string]::IsNullOrEmpty($ObjectId) -and $ObjectId -ne "NotFound" -and $ObjectId -ne "InvalidSchemaPropertyName" -and $ObjectId.length -ge 90) {
            $GlobalObjectId += $ObjectId;
        }
    }

    $MeetingID = $GlobalObjectId | Select-Object -Unique;
    $ShortMeetingID = $MeetingID.Substring($MeetingID.length - 6);

    foreach ($CNEntry in ($GCDO.SentRepresentingEmailAddress.ToUpper() | Select-Object -Unique)) {
        if ($CNEntry -match 'cn=([\w,\s.@-]*[^/])$') {
            $MailboxList[$CNEntry] = (GetMailbox -Identity $CNEntry -Organization $Org);
        }
    }

    $Global:CalendarItemTypes = @{
        'IPM.Schedule.Meeting.Request.AttendeeListReplication' = "AttendeeList"
        'IPM.Schedule.Meeting.Canceled'                        = "Canceled"
        'IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}' = "ExceptionMsgClass"
        'IPM.Schedule.Meeting.Notification.Forward'            = "ForwardNotification"
        'IPM.Appointment'                                      = "IpmAppointment"
        'IPM.Schedule.Meeting.Request'                         = "MeetingRequest"
        'IPM.CalendarSharing.EventUpdate'                      = "SharingCFM"
        'IPM.CalendarSharing.EventDelete'                      = "SharingDelete"
        'IPM.Schedule.Meeting.Resp'                            = "RespAny"
        'IPM.Schedule.Meeting.Resp.Neg'                        = "RespNeg"
        'IPM.Schedule.Meeting.Resp.Tent'                       = "RespTent"
        'IPM.Schedule.Meeting.Resp.Pos'                        = "RespPos"
    }

    $CalendarActors = @{
        'Unknown ActiveSync Device'             = "ActiveSyncUnknown"
        'Booking Agent'                         = "BookingAgent"
        'Calendar Assistant'                    = "CalendarAssistant"
        'Cisco Webex'                           = "CiscoWebex"
        'CalendarRepairAssistant'               = "CRA"
        'CalendarReplication'                   = "CalendarReplication"
        'Unidentified EWS Client'               = "EWS"
        'REST:GenericGriffinClient'             = "GriffinRestClient"
        'REST:LocationAssistantProcessor'       = "LocationProcessor"
        'Lync for Mac'                          = "LyncMac"
        'MacOutlook'                            = "MacOutlook"
        'MacOutlook:EWS'                        = "MacOutlookEWS"
        'MacOutlook:REST'                       = "MacOutlookRest"
        'Outlook'                               = "Outlook"
        'Outlook-iOS'                           = "OutlookiOS"
        'Outlook-Android'                       = "OutlookAndriod"
        'OWA'                                   = "OWA"
        'OWA-CalendarSharing'                   = "OwaCalSharing"
        'Outlook-CalendarSharing'               = "OutlookCalSharing"
        'Outlook Mobile App'                    = "OutlookMobile"
        'POP3/IMAP4'                            = "PopImap"
        'ResourceBookingAssistant'              = "RBA"
        'REST:Connector'                        = "RestConnector"
        'REST:UnspecifiedClient'                = "RestUnknown"
        'Remove-CalendarEvent Cmdlet'           = "RemoveCalendarEvent"
        'Microsoft System Attendant'            = "SysAdmin"
        'Salesforce Lightning Sync'             = "SalesForceLighting"
        'Teams'                                 = "Teams"
        'Skype Meeting Migration Service (MMS)' = "SkypeMMS"
        'Time Service'                          = "TimeService"
        'Transport'                             = "Transport"
        'Windows Phone'                         = "WindowsPhone"
        'CollabServiceProcessor'                = "CSP"
    }

    $SCN = @{
        'Client=Hub Transport'                       = "Transport"
        'Client=MSExchangeRPC'                       = "Outlook"
        'Lync for Mac'                               = "LyncMac"
        'AppId=00000004-0000-0ff1-ce00-000000000000' = "SkypeMMS"
        'MicrosoftNinja'                             = "Teams"
        'Remove-CalendarEvents'                      = "RemoveCalendarEvent"
        'Client=POP3/IMAP4'                          = "PopImap"
        'Client=OWA'                                 = "OWA"
        'PublishedBookingCalendar'                   = "BookingAgent"
        'LocationAssistantProcessor'                 = "LocationProcessor"
        'AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d' = "CalendarReplication"
        'AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0' = "CiscoWebex"
        'AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f' = "Time Service"
        'AppId=48af08dc-f6d2-435f-b2a7-069abd99c086' = "RestConnector"
        'GriffinRestClient'                          = "GriffinRestClient"
        'MacOutlook'                                 = "MacOutlookRest"
        'Outlook-iOS-Android'                        = "OutlookMobile"
        'Client=OutlookService;Outlook-Android'      = "OutlookAndriod"
        'Client=OutlookService;Outlook-iOS'          = "OutlookiOS"
    }

    $RT = @{
        '0' = "None"
        "1" = "Organizer"
        '2' = "Tentative"
        '3' = "Accept"
        '4' = "Decline"
        '5' = "Not Responded"
    }

    $AT = @{
        '1' = "Required"
        '2' = "Optional"
        '3' = "Resource"
    }

    $Index = 0;
    foreach ($CalLog in $GCDO) {
        $CalLogACP = $CalLog.AppointmentCounterProposal.ToString();
        $Index++;
        $ItemType = $CalendarItemTypes.($CalLog.ItemClass);
        $ShortClientName = @();
        $Global:Keyinput = $CalLog.ClientInfoString;
        $ResponseType = $RT.($CalLog.ResponseType.ToString());

        if (!$CalLog.ClientInfoString) {
            $ShortClientName = "NotFound";
        }

        if ($CalLog.ClientInfoString -like "Client=EBA*" -or $CalLog.ClientInfoString -like "Client=TBA*") {
            if ($CalLog.ClientInfoString -like "*ResourceBookingAssistant*") {
                $ShortClientName = "ResourceBookingAssistant";
            } elseif ($CalLog.ClientInfoString -like "*CalendarRepairAssistant*") {
                $ShortClientName = "CalendarRepairAssistant";
            } else {
                $client = $CalLog.ClientInfoString.Split(';')[0].Split('=')[-1];
                $Action = $CalLog.ClientInfoString.Split(';')[1].Split('=')[-1];
                $Data = $CalLog.ClientInfoString.Split(';')[-1];
                $ShortClientName = $client + ":" + $Action + ";" + $Data;
            }
        } elseif ($CalLog.ClientInfoString -like "Client=ActiveSync*") {
            if ($CalLog.clientinfostring -match 'UserAgent=(\w*-\w*)') {
                $ShortClientName = ($CalLog.clientinfostring -split "UserAgent=")[-1].Split("/")[0]
            } elseif ($CalLog.ClientInfoString -like "*Outlook-iOS-Android*") {
                $ShortClientName = "OutlookMobile"
            } else {
                $ShortClientName = "ActiveSyncUnknown"
            }
        } elseif ($CalLog.ClientInfoString -like "Client=Rest*") {
            if ($CalLog.ClientInfoString -like "*LocationAssistantProcessor*") {
                $ShortClientName = "LocationProcessor";
            } elseif ($CalLog.ClientInfoString -like "*AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d*") {
                $ShortClientName = "CalendarReplication";
            } elseif ($CalLog.ClientInfoString -like "*AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0*") {
                $ShortClientName = "CiscoWebex";
            } elseif ($CalLog.ClientInfoString -like "*AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f*") {
                $ShortClientName = "TimeService";
            } elseif ($CalLog.ClientInfoString -like "*AppId=48af08dc-f6d2-435f-b2a7-069abd99c086*") {
                $ShortClientName = "RestConnector";
            } elseif ($CalLog.ClientInfoString -like "*GriffinRestClient*") {
                $ShortClientName = "GriffinRestClient";
            } elseif ($CalLog.ClientInfoString -like "*NoUserAgent*") {
                $ShortClientName = "RestUnknown";
            } elseif ($CalLog.ClientInfoString -like "*MacOutlook*") {
                $ShortClientName = "MacOutlookRest";
            } else {
                $ShortClientName = "Rest";
            }
        } else {
            $ShortClientName = FindMatch -PassedHash $SCN;
        }

        if ($CalLog.ClientInfoString -like "*InternalCalendarSharing*" -and $CalLog.ClientInfoString -like "*OWA*") {
            $ShortClientName = "OwaCalSharing";
        }
        if ($CalLog.ClientInfoString -like "*InternalCalendarSharing*" -and $CalLog.ClientInfoString -like "*Outlook*") {
            $ShortClientName = "OutlookCalSharing";
        }
        if ($CalLog.ClientInfoString -like "Client=ActiveSync*" -and $CalLog.ClientInfoString -like "*Outlook*") {
            $ShortClientName = "OutlookCalSharing";
        }

        if ($CalLog.ResponsibleUserName -match 'cn=([\w,\s.@-]*[^/])$') {
            $cNameMatch = $CalLog.ResponsibleUserName -split "cn=";

            if ($cNameMatch[-1] -match "-[\w* -.]*") {
                $DisplayName = $cNameMatch.split('-')[-1];
            } else {
                $DisplayName = $cNameMatch[-1];
            }
        }

        if ($DisplayName -match "Microsoft System Attendant") {
            $ResponsibleUser = "Calendar Assistant";
        } else {
            $ResponsibleUser = $DisplayName;
        }

        if ($CalLog.SenderEmailAddress -match 'cn=([\w,\s.@-]*[^/])$') {
            $cNameMatch = $CalLog.SenderEmailAddress -split "cn=";

            if ($cNameMatch[-1] -match "-[\w* -.]*") {
                $SenderName = $cNameMatch.split('-')[-1];
            }
        }

        if ($ShortClientName -like "EBA*" `
                -or $ShortClientName -like "TBA*" `
                -or $ShortClientName -eq "LocationProcessor" `
                -or $ShortClientName -eq "GriffinRestClient" `
                -or $ShortClientName -eq "RestConnector" `
                -or $ShortClientName -eq "CalendarReplication" `
                -or $ShortClientName -eq "TimeService" `
                -or $CalendarItemTypes.($CalLog.ItemClass) -eq "SharingCFM" `
                -or $CalendarItemTypes.($CalLog.ItemClass) -eq "SharingDelete" `
                -or $CalendarItemTypes.($CalLog.ItemClass) -eq "AttendeeList" `
                -or $CalendarItemTypes.($CalLog.ItemClass) -eq "RespAny") {
            $IsIgnorable = "True";
        } else {
            $IsIgnorable = "False";
        }

        if ($CalLog.FreeBusyStatus -eq "NotFound") {
            $CalLog.FreeBusyStatus = '';
        }

        if ($CalLog.AppointmentAuxiliaryFlags.ToString() -eq "NotFound") {
            $CalLog.AppointmentAuxiliaryFlags = '';
        }

        if ($CalLog.AppointmentCounterProposal -eq "NotFound") {
            $CalLog.AppointmentCounterProposal = '';
        }

        if ($CalLogACP -eq "NotFound") {
            $CalLogACP = '';
        }

        if ($CalLog.ClientIntent.ToString() -eq "NotFound") {
            $CalLog.ClientIntent = '';
        }

        $IsFromSharedCalendar = ($null -ne $CalLog.externalSharingMasterId -and $CalLog.externalSharingMasterId -ne "NotFound");

        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -and $CalLog.IsOrganizerProperty -eq $True -or $CalendarItemTypes.($CalLog.ItemClass) -eq "MeetingRequest" -or $CalendarItemTypes.($CalLog.ItemClass) -eq "AttendeeList") {
            [bool] $GetIsOrganizer = $True;
        }

        $GCDOResults += [pscustomobject]@{
            'LogRow'                       = $Index
            'LastModifiedTime'             = $CalLog.OriginalLastModifiedTime
            'IsIgnorable'                  = $IsIgnorable
            'SubjectProperty'              = $CalLog.SubjectProperty
            'Client'                       = $ShortClientName
            'TriggerAction'                = $CalLog.CalendarLogTriggerAction
            'ItemClass'                    = $CalLog.ItemClass
            'ItemVersion'                  = $CalLog.ItemVersion
            'ApptSequence'                 = $CalLog.AppointmentSequenceNumber
            'Organizer'                    = $CalLog.From.FriendlyDisplayName
            'From'                         = $CalLog.From.SmtpEmailAddress
            'FreeBusyStatus'               = $CalLog.FreeBusyStatus
            'ResponsibleUser'              = $ResponsibleUser
            'Sender'                       = $SenderName
            'LogFolder'                    = $CalLog.ParentDisplayName
            'OriginalLogFolder'            = $CalLog.OriginalParentDisplayName
            'IsFromSharedCalendar'         = $IsFromSharedCalendar
            'ReceivedBy'                   = $CalLog.ReceivedBy.SmtpEmailAddress
            'ReceivedRepresenting'         = $CalLog.ReceivedRepresenting.SmtpEmailAddress
            'MeetingRequestType'           = $CalLog.MeetingRequestType
            'StartTime'                    = $CalLog.StartTime
            'EndTime'                      = $CalLog.EndTime
            'TimeZone'                     = $CalLog.TimeZone
            'Location'                     = $CalLog.Location
            'CalendarItemType'             = $CalLog.CalendarItemType
            'RecurrencePattern'            = $CalLog.RecurrencePattern
            'AppointmentAuxiliaryFlags'    = $CalLog.AppointmentAuxiliaryFlags.ToString()
            'DisplayAttendeesAll'          = $CalLog.DisplayAttendeesAll
            'AppointmentState'             = $CalLog.AppointmentState.ToString()
            'ResponseType'                 = $ResponseType
            'AppointmentCounterProposal'   = $CalLogACP
            'SentRepresentingEmailAddress' = $CalLog.SentRepresentingEmailAddress
            'ResponsibleUserName'          = $CalLog.ResponsibleUserName
            'SenderEmailAddress'           = $CalLog.SenderEmailAddress
            'ClientInfoString'             = $CalLog.ClientInfoString
            'CalendarLogRequestId'         = $CalLog.CalendarLogRequestId.ToString()
            'ClientIntent'                 = $CalLog.ClientIntent.ToString()
            'CleanGlobalObjectId'          = $CalLog.CleanGlobalObjectId
            'MapiStartTime'                = $CalLog.MapiStartTime
            'MapiEndTime'                  = $CalLog.MapiEndTime
            'NormalizedSubject'            = $CalLog.NormalizedSubject
            'AppointmentRecurring'         = $CalLog.AppointmentRecurring
            'HasAttachment'                = $CalLog.HasAttachment
            'IsCancelled'                  = $CalLog.IsCancelled
            'IsAllDayEvent'                = $CalLog.IsAllDayEvent
            'IsSeriesCancelled'            = $CalLog.IsSeriesCancelled
            'IsOrganizer'                  = $GetIsOrganizer
            'SentRepresentingDisplayName'  = $CalLog.SentRepresentingDisplayName
            'IsException'                  = $CalLog.IsException
            'IsOrganizerProperty'          = $CalLog.IsOrganizerProperty
            'EventEmailReminderTimer'      = $CalLog.EventEmailReminderTimer
            'EstimatedAcceptCount'         = $CalLog.EstimatedAcceptCount
            'EstimatedTentativeCount'      = $CalLog.EstimatedTentativeCount
            'EstimatedDeclineCount'        = $CalLog.EstimatedDeclineCount
            'OnlineMeetingConfLink'        = $CalLog.OnlineMeetingConfLink
            'OnlineMeetingExternalLink'    = $CalLog.OnlineMeetingExternalLink
            'OnlineMeetingInternalLink'    = $CalLog.OnlineMeetingInternalLink
        }
    }
    $Global:Results = $GCDOResults;
    $Global:Filename = "$($Identity)_$ShortMeetingID.csv";
    #Write-Host "`n`nTo save the original Calendar Diagnostic Object csv log file, run the running command in this powershell session `n`$GetCDO | Export-Csv -Path Original_`$Filename -NoTypeInformation" -ForegroundColor Cyan;
    #Write-Host "`n`nTo save the custom modified Calendar Diagnostic Object csv log file, run the funning command in this powershell session `n`$Results | Export-Csv -Path `$Filename -NoTypeInformation" -ForegroundColor Cyan;
    $GCDOResults | Export-Csv -Path $Filename -NoTypeInformation

    $MeetingTimeLine = $Results | Where-Object { $_.IsIgnorable -eq "False" } ;
    if (($MeetingTimeLine.Count) -lt 1) {
        "`n`n`nThis is the meetingID $MeetingID`nThis is Short MeetingID $ShortMeetingID`nFound $($GCDO.count) Log entries, Only 1 entry will be analyzed.";
    } else {
        "`n`n`nThis is the meetingID $MeetingID`nThis is Short MeetingID $ShortMeetingID`nFound $($GCDO.count) Log entries, Only $($MeetingTimeLine.count) entries will be analyzed.";
    }
    return;
}

function MeetingSummary {
    param(
        [Array]$Time,
        $MeetingChanges,
        $Entry,
        [switch]$LongVersion,
        [switch]$ShortVersion
    )

    $InitialSubject = "Subject: " + $Entry.NormalizedSubject;
    $InitialOrganizer = "Organizer: " + $Entry.SentRepresentingDisplayName;
    $InitialSender = "Sender: " + $Entry.SentRepresentingDisplayName;
    $InitialToList = "To List: " + $Entry.DisplayAttendeesAll;
    $InitialLocation = "Location: " + $Entry.Location;

    if ($ShortVersion -or $LongVersion) {
        $InitialStartTime = "StartTime: " + $Entry.StartTime.ToString();
        $InitialEndTime = "EndTime: " + $Entry.EndTime.ToString();
    }

    if ($longVersion -and ($Entry.Timezone -ne "")) {
        $InitialTimeZone = "Time Zone: " + $Entry.Timezone;
    } else {
        $InitialTimeZone = "Time Zone: Not Populated"
    }

    if ($Entry.AppointmentRecurring) {
        $InitialRecurring = "Recurring: Yes - Recurring";
    } else {
        $InitialRecurring = "Recurring: No - Single instance";
    }

    if ($longVersion -and $Entry.AppointmentRecurring) {
        $InitialRecurrencePattern = "RecurrencePattern: " + $Entry.RecurrencePattern;
        $InitialSeriesStartTime = "Series StartTime: " + $Entry.ViewStartTime.ToString();
        $InitialSeriesEndTime = "Series EndTime: " + $Entry.ViewStartTime.ToString();
        if (!$Entry.ViewEndTime) {
            $InitialEndDate = "Meeting Series does not have an End Date.";
        }
    }

    if (!$Time) {
        $Time = $CalLog.LastModifiedTime.ToString();
    }

    if (!$MeetingChanges) {
        $MeetingChanges = @();
        $MeetingChanges += $InitialSubject, $InitialOrganizer, $InitialSender, $InitialToList, $InitialLocation, $InitialStartTime, $InitialEndTime, $InitialTimeZone, $InitialRecurring, $InitialRecurrencePattern, $InitialSeriesStartTime , $InitialSeriesEndTime , $InitialEndDate;
    }

    if ($ShortVersion) {
        $MeetingChanges = @();
        $MeetingChanges += $InitialToList, $InitialLocation, $InitialStartTime, $InitialEndTime, $InitialRecurring;
    }

    Transpose-Data -ArrayNames "Time", "MeetingChanges";
}

function BuildTimeline {
    [Array]$Header = ("Subject: " + ($GCDO[0].NormalizedSubject) + " | Display Name: " + ($GCDO[0].SentRepresentingDisplayName) + " | MeetingID: " + ($GCDO[0].CleanGlobalObjectId));
    MeetingSummary -Time "Calendar Logs for Meeting with" -MeetingChanges $Header;
    MeetingSummary -Time "Initial Message Values" -Entry $GCDO[0] -LongVersion;
    $Global:MeetingTimeLine = $Results | Where-Object { $_.IsIgnorable -eq "False" };

    foreach ($CalLog in $MeetingTimeLine) {
        [bool] $MeetingSummaryNeeded = $False;
        [bool] $AddChangedProperties = $False;
        [array] $Output = "****I'm starting loop with a clean slate****"
        function ChangedProperties {
            if ($CalLog.Client -ne "LocationProcessor" -or $CalLog.Client -notlike "EBA:*" -or $CalLog.Client -notlike "TBA:*") {
                if ($PreviousCalLog -and $AddChangedProperties) {
                    if ($CalLog.MapiStartTime.ToString() -ne $PreviousCalLog.MapiStartTime.ToString()) {
                        [Array]$TimeLineText = "The StartTime changed from [$($PreviousCalLog.MapiStartTime)] to: [$($CalLog.MapiStartTime)]";
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText;
                    }

                    if ($CalLog.MapiEndTime.ToString() -ne $PreviousCalLog.MapiEndTime.ToString()) {
                        [Array]$TimeLineText = "The EndTime changed from [$($PreviousCalLog.MapiEndTime)] to: [$($CalLog.MapiEndTime)]";
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText;
                    }

                    if ($CalLog.SubjectProperty -ne $PreviousCallog.SubjectProperty) {
                        [Array]$TimeLineText = "The EndTime changed from [$($PreviousCallog.SubjectProperty)] to: [$($CalLog.SubjectProperty)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText;
                    }

                    if ($CalLog.NormalizedSubject -ne $PreviousCallog.NormalizedSubject) {
                        [Array]$TimeLineText = "The EndTime changed from [$($PreviousCallog.NormalizedSubject)] to: [$($CalLog.NormalizedSubject)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText;
                    }
                    if ($CalLog.Location -ne $PreviousCalLog.Location) {
                        [Array]$TimeLineText = "The Location changed from [$($PreviousCalLog.Location)] to: [$($CalLog.Location)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.TimeZone -ne $PreviousCalLog.TimeZone) {
                        [Array]$TimeLineText = "The TimeZone changed from [$($PreviousCalLog.TimeZone)] to: [$($CalLog.TimeZone)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.DisplayAttendeesAll -ne $PreviousCalLog.DisplayAttendeesAll) {
                        [Array]$TimeLineText = "The All Attendees changed from [$($PreviousCalLog.DisplayAttendeesAll)] to: [$($CalLog.DisplayAttendeesAll)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.AppointmentRecurring -ne $PreviousCalLog.AppointmentRecurring) {
                        [Array]$TimeLineText = "The Appointment Recurrence changed from [$($PreviousCalLog.AppointmentRecurring)] to: [$($CalLog.AppointmentRecurring)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.HasAttachment -ne $PreviousCalLog.HasAttachment) {
                        [Array]$TimeLineText = "The Meeting has Attachment changed from [$($PreviousCalLog.HasAttachment)] to: [$($CalLog.HasAttachment)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.IsCancelled -ne $PreviousCalLog.IsCancelled) {
                        [Array]$TimeLineText = "The Meeting is Cancelled changed from [$($PreviousCalLog.IsCancelled)] to: [$($CalLog.IsCancelled)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.IsAllDayEvent -ne $PreviousCalLog.IsAllDayEvent) {
                        [Array]$TimeLineText = "The Meeting is an All Day Event changed from [$($PreviousCalLog.IsAllDayEvent)] to: [$($CalLog.IsAllDayEvent)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.IsException -ne $PreviousCalLog.IsException) {
                        [Array]$TimeLineText = "The Meeting Is Exception changed from [$($PreviousCalLog.IsException)] to: [$($CalLog.IsException)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.IsSeriesCancelled -ne $PreviousCalLog.IsSeriesCancelled) {
                        [Array]$TimeLineText = "The Is Series Cancelled changed from [$($PreviousCalLog.IsSeriesCancelled)] to: [$($CalLog.IsSeriesCancelled)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.IsOrganizerProperty -ne $PreviousCalLog.IsOrganizerProperty) {
                        [Array]$TimeLineText = "The Is Organizer changed from [$($PreviousCalLog.IsOrganizerProperty)] to: [$($CalLog.IsOrganizerProperty)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.EventEmailReminderTimer -ne $PreviousCalLog.EventEmailReminderTimer) {
                        [Array]$TimeLineText = "The Email Reminder changed from [$($PreviousCalLog.EventEmailReminderTimer)] to: [$($CalLog.EventEmailReminderTimer)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.FreeBusyStatus -ne $PreviousCalLog.FreeBusyStatus) {
                        [Array]$TimeLineText = "The FreeBusy Status changed from [$($PreviousCalLog.FreeBusyStatus)] to: [$($CalLog.FreeBusyStatus)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.AppointmentState -ne $PreviousCalLog.AppointmentState) {
                        [Array]$TimeLineText = "The Appointment State changed from [$($PreviousCalLog.AppointmentState)] to: [$($CalLog.AppointmentState)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.MeetingRequestType -ne $PreviousCalLog.MeetingRequestType) {
                        [Array]$TimeLineText = "The Meeting Request Type changed from [$($PreviousCalLog.MeetingRequestType)] to: [$($CalLog.MeetingRequestType)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.CalendarItemType -ne $PreviousCalLog.CalendarItemType) {
                        [Array]$TimeLineText = "The Calendar Item Type changed from [$($PreviousCalLog.CalendarItemType)] to: [$($CalLog.CalendarItemType)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.ResponseType -ne $PreviousCalLog.ResponseType) {
                        [Array]$TimeLineText = "The ResponseType changed from [$($PreviousCalLog.ResponseType)] to: [$($CalLog.ResponseType)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.EstimatedAcceptCount -ne $PreviousCalLog.EstimatedAcceptCount) {
                        [Array]$TimeLineText = "The Estimated Accept Count changed from [$($PreviousCalLog.EstimatedAcceptCount)] to: [$($CalLog.EstimatedAcceptCount)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.EstimatedTentativeCount -ne $PreviousCalLog.EstimatedTentativeCount) {
                        [Array]$TimeLineText = "The Estimated Tentative Count changed from [$($PreviousCalLog.EstimatedTentativeCount)] to: [$($CalLog.EstimatedTentativeCount)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.EstimatedDeclineCount -ne $PreviousCalLog.EstimatedDeclineCount) {
                        [Array]$TimeLineText = "The Estimated Declined Count changed from [$($PreviousCalLog.EstimatedDeclineCount)] to: [$($CalLog.EstimatedDeclineCount)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.OnlineMeetingConfLink -ne $PreviousCalLog.OnlineMeetingConfLink) {
                        [Array]$TimeLineText = "The Online Meeting Conference Link changed from [$($PreviousCalLog.OnlineMeetingConfLink)] to: [$($CalLog.OnlineMeetingConfLink)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.OnlineMeetingExternalLink -ne $PreviousCalLog.OnlineMeetingExternalLink) {
                        [Array]$TimeLineText = "The Online Meeting External Link changed from [$($PreviousCalLog.OnlineMeetingExternalLink)] to: [$($CalLog.OnlineMeetingExternalLink)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.OnlineMeetingInternalLink -ne $PreviousCalLog.OnlineMeetingInternalLink) {
                        [Array]$TimeLineText = "The Online Meeting Internal Link changed from [$($PreviousCalLog.OnlineMeetingInternalLink)] to: [$($CalLog.OnlineMeetingInternalLink)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.SenderEmailAddress -ne $PreviousCalLog.SenderEmailAddress) {
                        [Array]$TimeLineText = "The Sender Email Address changed from [$($PreviousCalLog.SenderEmailAddress)] to: [$($CalLog.SenderEmailAddress)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.From -ne $PreviousCalLog.From) {
                        [Array]$TimeLineText = "The From changed from [$($PreviousCalLog.From)] to: [$($CalLog.From)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.ReceivedBy -ne $PreviousCalLog.ReceivedBy) {
                        [Array]$TimeLineText = "The Received By changed from [$($PreviousCalLog.ReceivedBy)] to: [$($CalLog.ReceivedBy)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.ReceivedRepresenting -ne $PreviousCalLog.ReceivedRepresenting) {
                        [Array]$TimeLineText = "The Received Representing changed from [$($PreviousCalLog.ReceivedRepresenting)] to: [$($CalLog.ReceivedRepresenting)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }
                }
            }
        }

        switch ($CalendarItemTypes.($CalLog.ItemClass)) {
            MeetingRequest {
                switch ($CalLog.TriggerAction) {
                    Create {
                        if ($CalLog.IsOrganizer) {
                            if ($CalLog.IsException) {
                                $Output1 = "A new Exception $($CalLog.MeetingRequestType) Meeting Request was created with $($CalLog.Client)";
                            } else {
                                $Output1 = "A new $($CalLog.MeetingRequestType.Value) Meeting Request was created with $($CalLog.Client)";
                            }

                            if ($CalLog.SentRepresentingEmailAddress -eq $CalLog.SenderEmailAddress) {
                                $Output2 = " by the Organizer $($CalLog.ResponsibleUser)";
                            } else {
                                $Output2 = " by the Delegate";
                            }

                            [array] $Output = $Output1 + $Output2;
                            [bool] $MeetingSummaryNeeded = $True;
                        } else {
                            if ($CalLog.DisplayAttendeesTo -ne $PreviousCalLog.DisplayAttendeesTo -or $CalLog.DisplayAttendeesCc -ne $PreviousCalLog.DisplayAttendeesCc) {
                                [array] $Output = "The user Forwarded a Meeting Request with $($CalLog.Client)";
                            } else {
                                if ($CalLog.Client -eq "Transport") {
                                    [array] $Output = "Transport delivered a new $($CalLog.MeetingRequestType) Meeting Request from $($CalLog.SentRepresentingDisplayName)";
                                    [bool] $MeetingSummaryNeeded = $True;
                                } else {
                                    [array] $Output = "$($CalLog.ResponsibleUser) sent a $($CalLog.MeetingRequestType.Value) update for the Meeting Request and was processed by $($CalLog.Client)";
                                }
                            }
                        }
                    }
                    Update {
                        [array] $Output = "$($CalLog.ResponsibleUser) updated on the $($CalLog.MeetingRequestType) Meeting Request with $($CalLog.Client)";
                    }
                    MoveToDeletedItems {
                        [array] $Output = "$($CalLog.ResponsibleUser) deleted the Meeting Request with $($CalLog.Client)";
                    }
                    default {
                        [array] $Output = "$($CalLog.TriggerAction) was performed on the $($CalLog.MeetingRequestType) Meeting Request by $($CalLog.ResponsibleUser) with $($CalLog.Client)";
                    }
                }
            }
            RespTent {
                $MeetingRespType = "Tentative";
                if ($CalLog.AppointmentCounterProposal -eq "True") {
                    [array] $Output = "$($CalLog.SentRepresentingDisplayName) send a $($MeetingRespType) response message with a New Time Proposal: $($CalLog.MapiStartTime) to $($CalLog.MapiEndTime)";
                } else {
                    if ($CalLog.TriggerAction -eq "Update") {
                        $Action = "updated";
                    } else {
                        $Action = "sent";
                    }

                    if ($CalLog.IsOrganizer) {
                        [array] $Output = "$($CalLog.SentRepresentingDisplayName) $($Action) a $($MeetingRespType) Meeting Response message.";
                    } else {
                        switch ($CalLog.Client) {
                            RBA {
                                [array] $Output = "RBA $($Action) a $($MeetingRespType) Meeting Response message.";
                            }
                            Transport {
                                [array] $Output = "$($CalLog.SentRepresentingDisplayName) $($Action) $($MeetingRespType) Meeting Response message.";
                            }
                            default {
                                [array] $Output = "$($MeetingRespType) Meeting Response message was $($Action) by $($CalLog.SentRepresentingDisplayName) with $($CalLog.Client)";
                            }
                        }
                    }
                }
            }
            RespNeg {
                $MeetingRespType = "DECLINE";
                if ($CalLog.AppointmentCounterProposal -eq "True") {
                    [array] $Output = "$($CalLog.SentRepresentingDisplayName) send a $($MeetingRespType) response message with a New Time Proposal: $($CalLog.MapiStartTime) to $($CalLog.MapiEndTime)";
                } else {
                    if ($CalLog.TriggerAction -eq "Update") {
                        $Action = "updated"
                    } else {
                        $Action = "sent"
                    }

                    if ($CalLog.IsOrganizer) {
                        [array] $Output = "$($CalLog.SentRepresentingDisplayName) $($Action) a $($MeetingRespType) Meeting Response message.";
                    } else {
                        switch ($CalLog.Client) {
                            RBA {
                                [array] $Output = "RBA $($Action) a $($MeetingRespType) Meeting Response message.";
                            }
                            Transport {
                                [array] $Output = "$($CalLog.SentRepresentingDisplayName) $($Action) $($MeetingRespType) Meeting Response message.";
                            }
                            default {
                                [array] $Output = "$($MeetingRespType) Meeting Response message was $($Action) by $($CalLog.SentRepresentingDisplayName) with $($CalLog.Client)";
                            }
                        }
                    }
                }
            }
            RespPos {
                $MeetingRespType = "ACCEPT";
                if ($CalLog.AppointmentCounterProposal -eq "True") {
                    [array] $Output = "$($CalLog.SentRepresentingDisplayName) send a $($MeetingRespType) response message with a New Time Proposal: $($CalLog.MapiStartTime) to $($CalLog.MapiEndTime)";
                } else {
                    if ($CalLog.TriggerAction -eq "Update") {
                        $Action = "updated";
                    } else {
                        $Action = "sent";
                    }

                    if ($CalLog.IsOrganizer) {
                        [array] $Output = "$($CalLog.SentRepresentingDisplayName) $($Action) a $($MeetingRespType) Meeting Response message.";
                    } else {
                        switch ($CalLog.Client) {
                            RBA {
                                [array] $Output = "RBA $($Action) a $($MeetingRespType) Meeting Response message.";
                            }
                            Transport {
                                [array] $Output = "$($CalLog.SentRepresentingDisplayName) $($Action) $($MeetingRespType) Meeting Response message.";
                            }
                            default {
                                [array] $Output = "$($MeetingRespType) Meeting Response message was $($Action) by $($CalLog.SentRepresentingDisplayName) with $($CalLog.Client)";
                            }
                        }
                    }
                }
            }
            ForwardNotification {
                [array] $Output = "The meeting was FORWARDED by $($CalLog.SentRepresentingDisplayName)";
            }
            ExceptionMsgClass {
                if ($CalLog.TriggerAction -eq "Create") {
                    $Action = "New";
                } else {
                    $Action = "$($CalLog.TriggerAction)";
                }

                if ($CalLog.ResponsibleUser -ne "Calendar Assistant") {
                    [array] $Output = "$($Action) Exception to the meeting series added by $($CalLog.ResponsibleUser) with $($CalLog.Client)";
                }
            }
            IpmAppointment {
                switch ($CalLog.TriggerAction) {
                    Create {
                        if ($CalLog.IsOrganizer) {
                            if ($CalLog.Client -eq "Transport") {
                                [array] $Output = "Transport created a new meeting.";
                            } else {
                                [array] $Output = "$($CalLog.SentRepresentingDisplayName) created a new Meeting with $($CalLog.Client)";
                            }
                        } else {
                            switch ($CalLog.Client) {
                                Transport {
                                    [array] $Output = "$($CalLog.Client) added a new Tentative Meeting from $($CalLog.SentRepresentingDisplayName) to the Calendar.";
                                }
                                RBA {
                                    [array] $Output = "$($CalLog.Client) added a new Tentative Meeting from $($CalLog.SentRepresentingDisplayName) to the Calendar.";
                                }
                                default {
                                    [array] $Output = "Meeting was created by [$($CalLog.ResponsibleUser)] with $($CalLog.Client).";
                                }
                            }
                        }
                    }
                    Update {
                        switch ($CalLog.Client) {
                            Transport {
                                [array] $Output = "Transport $($CalLog.TriggerAction)d the meeting from $($CalLog.SentRepresentingDisplayName).";
                            }
                            LocationProcessor {
                                [array] $Output = "";
                            }
                            RBA {
                                [array] $Output = "RBA $($CalLog.TriggerAction) the Meeting";
                            }
                            default {
                                if ($CalLog.ResponsibleUser -eq "Calendar Assistant") {
                                    [array] $Output = "The Exchange System $($CalLog.TriggerAction) the meeting";
                                } else {
                                    [array] $Output = "The Meeting was $($CalLog.TriggerAction) by [$($CalLog.ResponsibleUser)] with $($CalLog.Client).";
                                    $AddChangedProperties = $True;
                                }
                            }
                        }

                        if ($CalLog.FreeBusyStatus -eq 2 -and $PreviousCalLog.FreeBusyStatus -ne 2) {
                            [array] $Output = "The $($CalLog.ResponsibleUser) accepted the Meeting with $($CalLog.Client)";
                            $AddChangedProperties = $False;
                        } elseif ($CalLog.FreeBusyStatus -ne 2 -and $PreviousCalLog.FreeBusyStatus -eq 2) {
                            [array] $Output = "The $($CalLog.ResponsibleUser) declined the Meeting with $($CalLog.Client)";
                            $AddChangedProperties = $False;
                        }
                    }
                    SoftDelete {
                        switch ($CalLog.Client) {
                            Transport {
                                [array] $Output = "Transport $($CalLog.TriggerAction)d the Meeting from $($CalLog.SentRepresentingDisplayName).";
                            }
                            LocationProcessor {
                                [array] $Output = "";
                            }
                            RBA {
                                [array] $Output = "RBA $($CalLog.TriggerAction) the Meeting";
                            }
                            default {
                                if ($CalLog.ResponsibleUser -eq "Calendar Assistant") {
                                    [array] $Output = "The Exchange System $($CalLog.TriggerAction) the meeting";
                                } else {
                                    [array] $Output = "The Meeting was $($CalLog.TriggerAction) by [$($CalLog.ResponsibleUser)] with $($CalLog.Client).";
                                    $AddChangedProperties = $True;
                                }
                            }
                        }

                        if ($CalLog.FreeBusyStatus -eq 2 -and $PreviousCalLog.FreeBusyStatus -ne 2) {
                            [array] $Output = "The $($CalLog.ResponsibleUser) accepted the Meeting with $($CalLog.Client)";
                            $AddChangedProperties = $False;
                        } elseif ($CalLog.FreeBusyStatus -ne 2 -and $PreviousCalLog.FreeBusyStatus -eq 2) {
                            [array] $Output = "The $($CalLog.ResponsibleUser) declined the Meeting with $($CalLog.Client)";
                            $AddChangedProperties = $False;
                        }
                    }
                    MoveToDeletedItems {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] moved the Meeting to the Deleted Items with $($CalLog.Client).";
                    }
                    default {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction) the Meeting with $($CalLog.Client).";
                        [bool] $MeetingSummaryNeeded = $False;
                    }
                }
            }
            Canceled {
                [array] $Output = "$($CalLog.ResponsibleUser) Created a new Cancellation message for the $($CalendarItemTypes.($CalLog.ItemClass)) with $($CalLog.Client)";
            }
            default {
                if ($CalLog.TriggerAction -eq "Create") {
                    $Action = "New";
                } else {
                    $Action = "$($CalLog.TriggerAction)";
                }
                [array] $Output = "$($Action) was performed on the $($CalLog.ItemClass) by $($CalLog.ResponsibleUser) with $($CalLog.Client)";
            }
        }

        $Time = "$($CalLog.LogRow) -- $($CalLog.LastModifiedTime)"

        if ($Output) {
            if ($MeetingSummaryNeeded) {
                MeetingSummary -Time $Time -MeetingChanges $Output;
                $MeetingChanges = @();
                MeetingSummary -Time " " -ShortVersion -Entry $CalLog;
            } else {
                MeetingSummary -Time $Time -MeetingChanges $Output;
                if ($AddChangedProperties) {
                    ChangedProperties
                }
            }
        }

        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -or $CalendarItemTypes.($CalLog.ItemClass) -eq "ExceptionMsgClass") {
            $PreviousCalLog = $CalLog;
        }
    }

    $Results = @();
}

$GlobalObjectId = @();

foreach ($ObjectId in $GetCDO.CleanGlobalObjectId) {
    if (![string]::IsNullOrEmpty($ObjectId) -and $ObjectId -ne "NotFound" -and $ObjectId -ne "InvalidSchemaPropertyName" -and $ObjectId.length -ge 90) {
        $GlobalObjectId += $ObjectId;
    }
}

$UniqueMeetingID = $GlobalObjectId | Select-Object -Unique;

if ($UniqueMeetingID.count -gt 1) {
    $UniqueMeetingID | ForEach-Object {
        $MeetingID = $_;
        $Global:GCDO = Get-CalendarDiagnosticObjects -Identity $Identity -MeetingID $MeetingID -CustomPropertyNames AppointmentCounterProposal, AppointmentRecurring, CalendarItemType, CalendarProcessed, ClientIntent, DisplayAttendeesCc, DisplayAttendeesTo, EventEmailReminderTimer, ExternalSharingMasterId, FreeBusyStatus, From, HasAttachment, IsAllDayEvent, IsCancelled, IsMeeting, MapiEndTime, MapiStartTime, OnlineMeetingConfLink, OnlineMeetingExternalLink, OnlineMeetingInternalLink, SentRepresentingDisplayName, SentRepresentingEmailAddress -WarningAction Ignore;
        BuildCSV;
        BuildTimeline;
    }
} elseif ($UniqueMeetingID.count -eq 1) {
    $GCDO = $GetCDO;
    $GetCDO = @();
    BuildCSV;
    BuildTimeline;
} else {
    Write-Warning "A valid meeting ID was not found, manually confirm the meetingID";
}
$TimeSum = @();
