# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# This Exchange Online script runs the Get-CalendarDiagnosticObjects script and returns a summarized timeline of actions in clear english
# as well as the Calendar Diagnostic Objects in CSV format.
#
# .PARAMETER Identity
# Address of EXO User Mailbox to query
#
# .PARAMETER Subject
# Subject of the meeting to query
#
# .PARAMETER MeetingID
# The MeetingID of the meeting to query
#
# .EXAMPLE
# Get-CalendarDiagnosticObjectsSummary.ps1 -Identity someuser@microsoft.com -MeetingID 040000008200E00074C5B7101A82E008000000008063B5677577D9010000000000000000100000002FCDF04279AF6940A5BFB94F9B9F73CD
#
# Get-CalendarDiagnosticObjectsSummary.ps1 -Identity someuser@microsoft.com -Subject "Test OneTime Meeting Subject"
#
#

[CmdletBinding(DefaultParameterSetName = 'Subject')]
param (
    [Parameter(Mandatory, Position = 0)]
    [string]$Identity,

    [Parameter(Mandatory, ParameterSetName = 'Subject', Position = 1)]
    [string]$Subject,

    [Parameter(Mandatory, ParameterSetName = 'MeetingID', Position = 1)]
    [string]$MeetingID
)

# ===================================================================================================
# Constants to support the script
# ===================================================================================================

$CustomPropertyNameList =
"AppointmentCounterProposal",
"AppointmentLastSequenceNumber",
"AppointmentRecurring",
"CalendarItemType",
"CalendarProcessed",
"ClientIntent",
"DisplayAttendeesCc",
"DisplayAttendeesTo",
"EventEmailReminderTimer",
"ExternalSharingMasterId",
"FreeBusyStatus",
"From",
"HasAttachment",
"IsAllDayEvent",
"IsCancelled",
"IsMeeting",
"MapiEndTime",
"MapiStartTime",
"NormalizedSubject",
"SentRepresentingDisplayName",
"SentRepresentingEmailAddress";

$LogLimit = 2000;

$WellKnownCN_CA = "MICROSOFT SYSTEM ATTENDANT"
$CalAttendant = "Calendar Assistant"
$WellKnownCN_Trans = "MicrosoftExchange"
$Transport = "Transport Service"

$script:CalendarItemTypes = @{
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

$ShortClientNameProcessor = @{
    'Client=Hub Transport'                       = "Transport"
    'Client=MSExchangeRPC'                       = "Outlook-MAPI"
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
    'Client=OutlookService;Outlook-Android'      = "OutlookAndroid"
    'Client=OutlookService;Outlook-iOS'          = "OutlookiOS"
}

$ResponseTypeOptions = @{
    '0' = "None"
    "1" = "Organizer"
    '2' = "Tentative"
    '3' = "Accept"
    '4' = "Decline"
    '5' = "Not Responded"
}

# ===================================================================================================
# Functions to support the script
# ===================================================================================================

<#
.SYNOPSIS
Run Get-CalendarDiagnosticObjects for passed in User with Subject or MeetingID.
#>
function GetCalendarDiagnosticObjects {

    # Use MeetingID if we have it.
    if ($Identity -and $MeetingID) {
        Write-Verbose "Getting CalLogs for [$Identity] with MeetingID [$MeetingID]."
        $script:InitialCDOs = Get-CalendarDiagnosticObjects -Identity $Identity -MeetingID $MeetingID -CustomPropertyNames $CustomPropertyNameList -WarningAction Ignore -MaxResults $LogLimit -ResultSize $LogLimit -ShouldBindToItem $true;
    }

    # Otherwise do a search on the subject.
    if ($Identity -and $Subject -and !$MeetingID) {
        Write-Verbose "Getting CalLogs for [$Identity] with Subject [$Subject]."
        $script:InitialCDOs = Get-CalendarDiagnosticObjects -Identity $Identity -Subject $Subject -CustomPropertyNames $CustomPropertyNameList -WarningAction Ignore -MaxResults $LogLimit -ResultSize $LogLimit -ShouldBindToItem $true;

        # No Results, do a Deep search with ExactMatch.
        if ($script:InitialCDOs.count -lt 1) {
            $script:InitialCDOs = Get-CalendarDiagnosticObjects -Identity $Identity -Subject $Subject -ExactMatch $true -CustomPropertyNames $CustomPropertyNameList -WarningAction Ignore -MaxResults $LogLimit -ResultSize $LogLimit -ShouldBindToItem $true;
        }
    }

    if ($Identity -and !$Subject -and !$MeetingID) {
        Write-Warning "Can't run command with just Identity, either Subject or MeetingID must be provided.";
        exit;
    }
}

function FindMatch {
    param(
        [HashTable] $PassedHash
    )
    foreach ($Val in $PassedHash.keys) {
        if ($KeyInput -like "*$Val*") {
            return $PassedHash[$Val];
        }
    }
}

<#
.SYNOPSIS
Get the Mailbox for the Passed in Identity.
Might want to extend to do 'Get-MailUser' as well.
.PARAMETER CN of the Mailbox
    The mailbox for which to retrieve properties.
.PARAMETER Organization
    [Optional] Organization to search for the mailbox in.
#>
function GetMailbox {
    param(
        [string]$Identity,
        [string]$Organization
    )

    try {
        Write-Verbose "Searching Get-Mailbox $(if ($Organization -ne `"`" ) {"with Org: $Organization"}) for $Identity."

        # See if it is a Customer Tenant running the cmdlet. (They will not have access to Organization parameter)
        $MSSupport = [Bool](Get-Help Get-Mailbox -Parameter Organization -ErrorAction SilentlyContinue)
        Write-Verbose "MSSupport: $MSSupport"

        if ($Identity -and $Organization) {
            if ($MSSupport) {
                Write-Verbose  "Using Organization parameter"
                $GetMailboxOutput = Get-Mailbox -Identity $Identity -Organization $Organization  -ErrorAction SilentlyContinue;
            } else {
                Write-Verbose  "Using -OrganizationalUnit parameter"
                $GetMailboxOutput = Get-Mailbox -Identity $Identity -OrganizationalUnit $Organization  -ErrorAction SilentlyContinue;
            }
        } else {
            $GetMailboxOutput = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue;
        }

        if (!$GetMailboxOutput) {
            Write-Host "Unable to find [$Identity] in Organization:[$Organization]"
            return $null
        } else {
            Write-Verbose "Found [$($GetMailboxOutput.DisplayName)]"
        }

        if (CheckForNoPIIAccess($script:GetMailboxOutput.DisplayName)) {
            Write-Host -ForegroundColor Magenta "No PII Access for [$Identity]"
        } else {
            Write-Verbose "Found [$($GetMailboxOutput.DisplayName)]"
        }
        return $GetMailboxOutput;
    } catch {
        Write-Error "An error occurred while running Get-Mailbox: [$_]";
    }
}

function Convert-Data {
    param(
        [Parameter(Mandatory = $True)]
        [string[]] $ArrayNames,
        [switch ] $NoWarnings = $False
    )
    $ValidArrays = @();
    $ItemCounts = @();
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
    return $FinalArray;
    $FinalArray = @();
}

<#
.SYNOPSIS
    Retrieves mailbox properties for a given mailbox.
.DESCRIPTION
    This function retrieves mailbox properties for a given mailbox using Exchange Web Services (EWS).
.PARAMETER CN of the Mailbox
    The mailbox for which to retrieve properties.
.PARAMETER PropertySet
    The set of properties to retrieve.
#>
function GetMailboxProp {
    param(
        $PassedCN,
        $Prop
    )

    Write-Verbose "GetMailboxProp: [$Prop]: Searching for:[$PassedCN]..."

    if (($Prop -ne "PrimarySmtpAddress") -and ($Prop -ne "DisplayName")) {
        Write-Error "GetMailboxProp:Invalid Property: [$Prop]"
        return "Invalid Property"
    }

    if ($script:MailboxList.count -gt 0) {
        switch -Regex ($PassedCN) {
            $WellKnownCN_CA {
                return $CalAttendant
            }
            $WellKnownCN_Trans {
                return $Transport
            }
            default {
                if ($null -ne $script:MailboxList[$PassedCN]) {
                    $ReturnValue = $script:MailboxList[$PassedCN].$Prop;

                    if ($null -eq $ReturnValue) {
                        Write-Error "`t GetMailboxProp:$Prop :NotFound for ::[$PassedCN]"
                        return BetterThanNothingCNConversion($PassedCN)
                    }

                    Write-Verbose "`t GetMailboxProp:[$Prop] :Found::[$ReturnValue]"
                    if (CheckForNoPIIAccess($ReturnValue)) {
                        Write-Verbose "No PII Access for [$ReturnValue]"
                        return BetterThanNothingCNConversion($PassedCN)
                    }
                    return $ReturnValue;
                } else {
                    Write-Verbose "`t GetMailboxProp:$Prop :NotFound::$PassedCN"
                    return BetterThanNothingCNConversion($PassedCN)
                }
            }
        }
    } else {
        Write-Host -ForegroundColor Red "$script:MailboxList is empty, unable to do CN to SMTP mapping."
        return BetterThanNothingCNConversion($PassedCN)
    }
}

<#
.SYNOPSIS
    This function gets a more readable Name from a CN or the Calendar Assistant.
.PARAMETER PassedCN
    The common name (CN) of the mailbox user or the Calendar Assistant.
.OUTPUTS
    Returns the last part of the CN so that it is more readable
#>
function BetterThanNothingCNConversion {
    param (
        $PassedCN
    )
    if ($PassedCN -match $WellKnownCN_CA) {
        return $CalAttendant
    }

    if ($PassedCN -match $WellKnownCN_Trans) {
        return $Transport
    }

    if ($PassedCN -match 'cn=([\w,\s.@-]*[^/])$') {
        $cNameMatch = $PassedCN -split "cn=";

        # Normally a readable name is sectioned off with a "-" at the end.
        # example /o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=d61149258ba04404adda42f336b504ed-Delegate
        if ($cNameMatch[-1] -match "-[\w* -.]*") {
            Write-Verbose "BetterThanNothingCNConversion: Returning : [$($cNameMatch[-1])]"
            return $cNameMatch.split('-')[-1];
        }
        # Sometimes we do not have the "-" in front of the Name.
        # example: "/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=user123"
        if ($cNameMatch[-1] -match "[\w* -.]*") {
            Write-Verbose "BetterThanNothingCNConversion: Returning : [$($cNameMatch[-1])]"
            return $cNameMatch.split('-')[-1];
        }
    }
}

<#
.SYNOPSIS
Gets SMTP Address from a passed in CN that matches an entry in the MailboxList
#>
function GetSMTPAddress {
    param(
        $PassedCN
    )

    if ($PassedCN -match 'cn=([\w,\s.@-]*[^/])$') {
        return GetMailboxProp -PassedCN $PassedCN -Prop "PrimarySmtpAddress"
    } else {
        if ($PassedCN -match "@") {
            Write-Verbose "Looks like we have an SMTP Address already: [$PassedCN]"
            return $PassedCN
        }
        # We have a problem, we don't have a CN or an SMTP Address
        Write-Error "GetSMTPAddress: Passed in Value does not look like a CN or SMTP Address: [$PassedCN]"
        return $PassedCN
    }
}

<#
.SYNOPSIS
Gets DisplayName from a passed in CN that matches an entry in the MailboxList
#>
function GetDisplayName {
    param(
        $PassedCN
    )
    return GetMailboxProp -PassedCN $PassedCN -Prop "DisplayName"
}

<#
.SYNOPSIS
Checks if an entries is Redacted to protect PII.
#>
function CheckForNoPIIAccess {
    param(
        $PassedString
    )
    if ($PassedString -match "REDACTED-") {
        return $true
    } else {
        return $false
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
            # We have 2+ FolderNames,  Need to find the best one. #remove Calendar
            $AllFolderNames = $AllFolderNames | Where-Object { $_ -notmatch 'Calendar' }  # This will not work for non-english
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
                $SharedFolders[$ExternalID] =  $AllFolderNames[0] + $AllFolderNames[1]
            } else {
                $SharedFolders[$ExternalID] =  "UnknownSharedCalendarCopy"
            }
        }
    }
    Write-Verbose "Created the following Mapping :"
    Write-Verbose $SharedFolders
}

<#
.SYNOPSIS
Creates a list of CN that are used in the Calendar Logs, Looks up the Mailboxes and stores them in the MailboxList.
#>
function ConvertCNtoSMTP {
    # Creates a list of CN's that we will do MB look up on
    $CNEntries = @();
    $CNEntries += ($script:GCDO.SentRepresentingEmailAddress.ToUpper() | Select-Object -Unique)
    $CNEntries += ($script:GCDO.ResponsibleUserName.ToUpper() | Select-Object -Unique)
    $CNEntries += ($script:GCDO.SenderEmailAddress.ToUpper() | Select-Object -Unique)
    $CNEntries = $CNEntries | Select-Object -Unique
    Write-Verbose " Have $($CNEntries.count) CNEntries to look for..."
    Write-Verbose "CNEntries: "; foreach ($CN in $CNEntries) { Write-Verbose $CN }

    $Org = $script:MB.OrganizationalUnit.split('/')[-1];

    # Creates a Dictionary of MB's that we will use to look up the CN's
    Write-Verbose "Converting CN entries into SMTP Addresses..."
    foreach ($CNEntry in $CNEntries) {
        if ($CNEntry -match 'cn=([\w,\s.@-]*[^/])$') {
            if ($CNEntry -match $WellKnownCN_CA) {
                $MailboxList[$CNEntry] = $CalAttendant
            } elseif ($CNEntry -match $WellKnownCN_Trans) {
                $MailboxList[$CNEntry] = $Transport
            } else {
                $MailboxList[$CNEntry] = (GetMailbox -Identity $CNEntry -Organization $Org);
            }
        }
    }

    foreach ($key in $MailboxList.Keys) {
        $value = $MailboxList[$key]
        Write-Verbose "$key :: $($value.DisplayName)"
    }
}

<#
.SYNOPSIS
Creates Friendly / short client names
#>
function CreateShortClientName {
    param(
        $ClientInfoString
    )
    $ShortClientName= @();

    # Map ClientInfoString to ShortClientName
    if (!$ClientInfoString) {
        $ShortClientName = "NotFound";
    }

    if ($ClientInfoString -like "Client=EBA*" -or $ClientInfoString -like "Client=TBA*") {
        if ($ClientInfoString -like "*ResourceBookingAssistant*") {
            $ShortClientName = "ResourceBookingAssistant";
        } elseif ($ClientInfoString -like "*CalendarRepairAssistant*") {
            $ShortClientName = "CalendarRepairAssistant";
        } else {
            $client = $ClientInfoString.Split(';')[0].Split('=')[-1];
            $Action = $ClientInfoString.Split(';')[1].Split('=')[-1];
            $Data = $ClientInfoString.Split(';')[-1];
            $ShortClientName = $client+":"+$Action+";"+$Data;
        }
    } elseif ($ClientInfoString -like "Client=ActiveSync*") {
        if ($ClientInfoString -match 'UserAgent=(\w*-\w*)') {
            $ShortClientName = ($ClientInfoString -split "UserAgent=")[-1].Split("/")[0]
        } elseif ($ClientInfoString -like "*Outlook-iOS-Android*") {
            $ShortClientName = "OutlookMobile"
        } else {
            $ShortClientName = "ActiveSyncUnknown"
        }
    } elseif ($ClientInfoString -like "Client=Rest*") {
        if ($ClientInfoString -like "*LocationAssistantProcessor*") {
            $ShortClientName = "LocationProcessor";
        } elseif ($ClientInfoString -like "*AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d*") {
            $ShortClientName = "CalendarReplication";
        } elseif ($ClientInfoString -like "*AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0*") {
            $ShortClientName = "CiscoWebex";
        } elseif ($ClientInfoString -like "*AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f*") {
            $ShortClientName = "TimeService";
        } elseif ($ClientInfoString -like "*AppId=48af08dc-f6d2-435f-b2a7-069abd99c086*") {
            $ShortClientName = "RestConnector";
        } elseif ($ClientInfoString -like "*GriffinRestClient*") {
            $ShortClientName = "GriffinRestClient";
        } elseif ($ClientInfoString -like "*NoUserAgent*") {
            $ShortClientName = "RestUnknown";
        } elseif ($ClientInfoString -like "*MacOutlook*") {
            $ShortClientName = "MacOutlookRest";
        } elseif ($ClientInfoString -like "*Microsoft Outlook 16*") {
            $ShortClientName = "Outlook-ModernCalendarSharing";
        } else {
            $ShortClientName = "Rest";
        }
    } else {
        $ShortClientName = findMatch -PassedHash $ShortClientNameProcessor;
    }

    if ($ClientInfoString -like "*InternalCalendarSharing*" -and $ClientInfoString -like "*OWA*") {
        $ShortClientName = "Owa-ModernCalendarSharing";
    }
    if ($ClientInfoString -like "*InternalCalendarSharing*" -and $ClientInfoString -like "*MacOutlook*") {
        $ShortClientName = "MacOutlook-ModernCalendarSharing";
    }
    if ($ClientInfoString -like "*InternalCalendarSharing*" -and $ClientInfoString -like "*Outlook*") {
        $ShortClientName = "Outlook-ModernCalendarSharing";
    }
    if ($ClientInfoString -like "Client=ActiveSync*" -and $ClientInfoString -like "*Outlook*") {
        $ShortClientName = "Outlook-ModernCalendarSharing";
    }

    return $ShortClientName;
}

<#
.SYNOPSIS
Checks to see if the Calendar Log is Ignorable.
Many updates are not interesting in the Calendar Log, marking these as ignorable.  99% of the time this is correct.
#>
function SetIsIgnorable {
    param(
        $CalLog
    )

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
        return "True";
    } else {
        return "False";
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
Gets the Best Address from the From Property
#>
function GetBestFromAddress {
    param(
        $From
    )

    if ($null -ne $($From.SmtpEmailAddress)) {
        return $($From.SmtpEmailAddress)
    } elseif ($($From.EmailAddress) -ne "none") {
        return BetterThanNothingCNConversion($($From.EmailAddress))
    } else {
        Write-Verbose "GetBestFromAddress : Unable to Process From Address: [$From]"
        return "NotFound"
    }
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

# ===================================================================================================
# Build CSV to output
# ===================================================================================================
<#
.SYNOPSIS
Builds the CSV output from the Calendar Diagnostic Objects
#>
function BuildCSV {
    Write-Output "Starting to Process Calendar Logs..."
    $GCDOResults = @();
    $IsFromSharedCalendar = @();
    $IsIgnorable = @();
    $script:MailboxList = @{};
    Write-Output "Creating Map of Mailboxes to CN's..."
    CreateExternalMasterIDMap;

    $ThisMeetingID = $script:GCDO.CleanGlobalObjectId | Select-Object -Unique;
    $ShortMeetingID = $ThisMeetingID.Substring($ThisMeetingID.length - 6);

    ConvertCNtoSMTP;

    Write-Output "Making Calendar Logs more readable..."
    $Index = 0;
    foreach ($CalLog in $script:GCDO) {
        $CalLogACP = $CalLog.AppointmentCounterProposal.ToString();
        $Index++;
        $ItemType = $CalendarItemTypes.($CalLog.ItemClass);
        $ShortClientName = @();
        $script:KeyInput = $CalLog.ClientInfoString;
        $ResponseType = $ResponseTypeOptions.($CalLog.ResponseType.ToString());

        $ShortClientName = CreateShortClientName($CalLog.ClientInfoString);

        $IsIgnorable = SetIsIgnorable($CalLog)

        # CleanNotFounds;
        $PropsToClean = "FreeBusyStatus", "ClientIntent", "AppointmentLastSequenceNumber", "RecurrencePattern", "AppointmentAuxiliaryFlags", "IsOrganizerProperty", "EventEmailReminderTimer", "IsSeriesCancelled", "AppointmentCounterProposal", "MeetingRequestType"
        foreach ($Prop in $PropsToClean) {
            $CalLog.$Prop = ReplaceNotFound($CalLog.$Prop);
        }

        if ($CalLogACP -eq "NotFound") {
            $CalLogACP = '';
        }

        $IsFromSharedCalendar = ($null -ne $CalLog.externalSharingMasterId -and $CalLog.externalSharingMasterId -ne "NotFound");

        # Need to ask about this
        $GetIsOrganizer = ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -and
            $CalLog.IsOrganizerProperty -eq $True -and
            $CalLog.externalSharingMasterId -eq "NotFound")

        # Record one row
        $GCDOResults += [PSCustomObject]@{
            'LogRow'                        = $Index
            'LastModifiedTime'              = $CalLog.OriginalLastModifiedTime
            'IsIgnorable'                   = $IsIgnorable
            'SubjectProperty'               = $CalLog.SubjectProperty
            'Client'                        = $ShortClientName
            'ClientInfoString'              = $CalLog.ClientInfoString
            'TriggerAction'                 = $CalLog.CalendarLogTriggerAction
            'ItemClass'                     = $CalLog.ItemClass
            'ItemVersion'                   = $CalLog.ItemVersion
            'AppointmentSequenceNumber'     = $CalLog.AppointmentSequenceNumber
            'AppointmentLastSequenceNumber' = $CalLog.AppointmentLastSequenceNumber   # Need to find out how we can combine these two...
            'Organizer'                     = $CalLog.From.FriendlyDisplayName
            'From'                          = GetBestFromAddress($CalLog.From)
            'FreeBusyStatus'                = $CalLog.FreeBusyStatus
            'ResponsibleUser'               = GetSMTPAddress($CalLog.ResponsibleUserName)
            'Sender'                        = GetSMTPAddress($CalLog.SenderEmailAddress)
            'LogFolder'                     = $CalLog.ParentDisplayName
            'OriginalLogFolder'             = $CalLog.OriginalParentDisplayName
            'SharedFolderName'              = MapSharedFolder($CalLog.ExternalSharingMasterId)
            'IsFromSharedCalendar'          = $IsFromSharedCalendar
            'ExternalSharingMasterId'       = $CalLog.ExternalSharingMasterId
            'ReceivedBy'                    = $CalLog.ReceivedBy.SmtpEmailAddress
            'ReceivedRepresenting'          = $CalLog.ReceivedRepresenting.SmtpEmailAddress
            'MeetingRequestType'            = $CalLog.MeetingRequestType
            'StartTime'                     = $CalLog.StartTime
            'EndTime'                       = $CalLog.EndTime
            'TimeZone'                      = $CalLog.TimeZone
            'Location'                      = $CalLog.Location
            'ItemType'                      = $ItemType
            'CalendarItemType'              = $CalLog.CalendarItemType
            'IsException'                   = $CalLog.IsException
            'RecurrencePattern'             = $CalLog.RecurrencePattern
            'AppointmentAuxiliaryFlags'     = $CalLog.AppointmentAuxiliaryFlags.ToString()
            'DisplayAttendeesAll'           = $CalLog.DisplayAttendeesAll
            'AppointmentState'              = $CalLog.AppointmentState.ToString()
            'ResponseType'                  = $ResponseType
            'AppointmentCounterProposal'    = $CalLogACP
            'SentRepresentingEmailAddress'  = $CalLog.SentRepresentingEmailAddress
            'SentRepresentingSMTPAddress'   = GetSMTPAddress($CalLog.SentRepresentingEmailAddress)
            'SentRepresentingDisplayName'   = $CalLog.SentRepresentingDisplayName
            'ResponsibleUserSMTPAddress'    = GetSMTPAddress($CalLog.ResponsibleUserName)
            'ResponsibleUserName'           = GetDisplayName($CalLog.ResponsibleUserName)
            'SenderEmailAddress'            = $CalLog.SenderEmailAddress
            'SenderSMTPAddress'             = GetSMTPAddress($CalLog.SenderEmailAddress)
            'CalendarLogRequestId'          = $CalLog.CalendarLogRequestId.ToString()
            'ClientIntent'                  = $CalLog.ClientIntent.ToString()
            'MapiStartTime'                 = $CalLog.MapiStartTime
            'MapiEndTime'                   = $CalLog.MapiEndTime
            'NormalizedSubject'             = $CalLog.NormalizedSubject
            'AppointmentRecurring'          = $CalLog.AppointmentRecurring
            'HasAttachment'                 = $CalLog.HasAttachment
            'IsCancelled'                   = $CalLog.IsCancelled
            'IsAllDayEvent'                 = $CalLog.IsAllDayEvent
            'IsSeriesCancelled'             = $CalLog.IsSeriesCancelled
            'IsOrganizer'                   = $GetIsOrganizer
            'IsOrganizerProperty'           = $CalLog.IsOrganizerProperty
            'EventEmailReminderTimer'       = $CalLog.EventEmailReminderTimer
            'CleanGlobalObjectId'           = $CalLog.CleanGlobalObjectId
        }
    }
    $script:Results = $GCDOResults;

    # Automation won't have access to this file - will add code in next version to save contents to a variable
    #$Filename = "$($Results[0].ReceivedBy)_$ShortMeetingID.csv";
    $Filename = "$($Identity)_$ShortMeetingID.csv";
    $GCDOResults | Export-Csv -Path $Filename -NoTypeInformation
    Write-Output "Calendar Logs for $Identity have been saved to $Filename."
    $GCDOResults | Export-Csv -Path $Filename -NoTypeInformation -Encoding UTF8

    $MeetingTimeLine = $Results | Where-Object { $_.IsIgnorable -eq "False" } ;
    Write-Output "`n`n`nThis is the meetingID $ThisMeetingID`nThis is Short MeetingID $ShortMeetingID"
    Write-Output "Found $($script:GCDO.count) Log entries, Only $($MeetingTimeLine.count) entries will be analyzed.";
    return;
}

# ===================================================================================================
# Create Meeting Summary
# ===================================================================================================
function MeetingSummary {
    param(
        [array] $Time,
        $MeetingChanges,
        $Entry,
        [switch] $LongVersion,
        [switch] $ShortVersion
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
        $InitialSeriesStartTime = "Series StartTime: " + $Entry.StartTime.ToString() + "Z";
        $InitialSeriesEndTime = "Series EndTime: " + $Entry.StartTime.ToString() + "Z";
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

    Convert-Data -ArrayNames "Time", "MeetingChanges";
}

# ===================================================================================================
# BuildTimeline
# ===================================================================================================
function BuildTimeline {
    [Array]$Header = ("Subject: " + ($script:GCDO[0].NormalizedSubject) + " | Display Name: " + ($script:GCDO[0].SentRepresentingDisplayName) + " | MeetingID: "+ ($script:GCDO[0].CleanGlobalObjectId));
    MeetingSummary -Time "Calendar Logs for Meeting with" -MeetingChanges $Header;
    MeetingSummary -Time "Initial Message Values" -Entry $script:GCDO[0] -LongVersion;
    $MeetingTimeLine = $Results | Where-Object { $_.IsIgnorable -eq "False" };

    foreach ($CalLog in $MeetingTimeLine) {
        [bool] $MeetingSummaryNeeded = $False;
        [bool] $AddChangedProperties = $False;

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

                    if ($CalLog.SubjectProperty -ne $PreviousCalLog.SubjectProperty) {
                        [Array]$TimeLineText = "The EndTime changed from [$($PreviousCalLog.SubjectProperty)] to: [$($CalLog.SubjectProperty)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText;
                    }

                    if ($CalLog.NormalizedSubject -ne $PreviousCalLog.NormalizedSubject) {
                        [Array]$TimeLineText = "The EndTime changed from [$($PreviousCalLog.NormalizedSubject)] to: [$($CalLog.NormalizedSubject)]"
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

                    if ($CalLog.SenderSMTPAddress -ne $PreviousCalLog.SenderSMTPAddress) {
                        [Array]$TimeLineText = "The Sender Email Address changed from [$($PreviousCalLog.SenderSMTPAddress)] to: [$($CalLog.SenderSMTPAddress)]"
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

                            [array] $Output = $Output1+$Output2;
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
                MeetingSummary -Time " " -ShortVersion -Entry $CalLog;
            } else {
                MeetingSummary -Time $Time -MeetingChanges $Output;
                if ($AddChangedProperties) {
                    ChangedProperties;
                }
            }
        }

        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -or $CalendarItemTypes.($CalLog.ItemClass) -eq "ExceptionMsgClass") {
            $PreviousCalLog = $CalLog;
        }
    }

    $Results = @();
}

# ===================================================================================================
# Main
# ===================================================================================================

if (Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue) {
    Write-Verbose "Validated Get-Mailbox"
} else {
    Write-Error "Get-Mailbox not found.  Please validate that you are running this script from an Exchange Management Shell and try again."
    Write-Host "Look at Import-Module ExchangeOnlineManagement and Connect-ExchangeOnline."
    exit;
}

Write-Output "Checking for a valid mailbox..."
$script:MB = GetMailbox -Identity $Identity
if ($null -eq $script:MB) {
    # -or $script:MB.GetType().FullName -ne "Microsoft.Exchange.Data.Directory.Management.Mailbox") {
    Write-Host "`n`n`n============================================================================"
    Write-Error "Mailbox [$Identity] not found on Exchange Online.  Please validate the mailbox name and try again."
    Write-Host "======================================================================================="
    #exit;
}

# Get initial CalLogs (saved in $script:InitialCDOs)
Write-Output "Getting initial Calendar Logs..."
GetCalendarDiagnosticObjects;

$GlobalObjectIds = @();

# Find all the unique Global Object IDs
foreach ($ObjectId in $script:InitialCDOs.CleanGlobalObjectId) {
    if (![string]::IsNullOrEmpty($ObjectId) -and
        $ObjectId -ne "NotFound" -and
        $ObjectId -ne "InvalidSchemaPropertyName" -and
        $ObjectId.Length -ge 90) {
        $GlobalObjectIds += $ObjectId;
    }
}

$GlobalObjectIds = $GlobalObjectIds | Select-Object -Unique;

# Get the CalLogs for each MeetingID found.
if ($GlobalObjectIds.count -gt 1) {
    Write-Verbose "Found GlobalObjectIds: $($GlobalObjectIds.Count)"
    $GlobalObjectIds | ForEach-Object {
        #$MeetingID = $_;
        Write-Verbose "Processing MeetingID: $_"
        $script:GCDO = Get-CalendarDiagnosticObjects -Identity $Identity -MeetingID $_ -CustomPropertyNames $CustomPropertyNameList -WarningAction Ignore -MaxResults $LogLimit -ResultSize $LogLimit -ShouldBindToItem $true;
        BuildCSV;
        BuildTimeline;
    }
} elseif ($GlobalObjectIds.count -eq 1) {
    $script:GCDO = $script:InitialCDOs; # use the CalLogs that we already have, since there is only one.
    $script:InitialCDOs = @(); # clear the Initial CDOs.
    BuildCSV;
    BuildTimeline;
} else {
    Write-Warning "A valid meeting ID was not found, manually confirm the meetingID";
}

Write-Host -ForegroundColor Yellow "`n`n`n============================================================================"
Write-Host -ForegroundColor Yellow "Hope this script was helpful in getting (and understanding) the Calendar Logs."
Write-Host -ForegroundColor Yellow "If you have issues or suggestion for this script,"
Write-Host -ForegroundColor Yellow "`t please send them to <callogformatterdevs@microsoft.com>"
Write-Host -ForegroundColor Yellow "============================================================================`n`n`n"
