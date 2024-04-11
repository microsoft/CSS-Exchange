# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# This Exchange Online script runs the Get-CalendarDiagnosticObjects script and returns a summarized timeline of actions in clear english
# as well as the Calendar Diagnostic Objects in CSV format.
#
# .PARAMETER Identity
# One or more SMTP Address of EXO User Mailbox to query.
#
# .PARAMETER Subject
# Subject of the meeting to query, only valid if Identity is a single user.
#
# .PARAMETER MeetingID
# The MeetingID of the meeting to query.
#
# .PARAMETER TrackingLogs
# Include specific tracking logs in the output. Only useable with the MeetingID parameter.
#
# .PARAMETER Exceptions
# Include Exception objects in the output. Only useable with the MeetingID parameter.
#
# .EXAMPLE
# Get-CalendarDiagnosticObjectsSummary.ps1 -Identity someuser@microsoft.com -MeetingID 040000008200E00074C5B7101A82E008000000008063B5677577D9010000000000000000100000002FCDF04279AF6940A5BFB94F9B9F73CD
#
# Get-CalendarDiagnosticObjectsSummary.ps1 -Identity someuser@microsoft.com -Subject "Test OneTime Meeting Subject"
#
# Get-CalendarDiagnosticObjectsSummary.ps1 -Identity User1, User2, Delegate -MeetingID $MeetingID
#

[CmdletBinding(DefaultParameterSetName = 'Subject')]
param (
    [Parameter(Mandatory, Position = 0)]
    [string[]]$Identity,

    [Parameter(Mandatory, ParameterSetName = 'MeetingID', Position = 1)]
    [string]$MeetingID,
    [switch]$TrackingLogs,
    [switch]$Exceptions,

    [Parameter(Mandatory, ParameterSetName = 'Subject', Position = 1)]
    [string]$Subject
)

# ===================================================================================================
# Auto update script
# ===================================================================================================

$BuildVersion = ""

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

if (Test-ScriptVersion -AutoUpdate -Confirm:$false) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command." -ForegroundColor Yellow
    return
}

Write-Verbose "Script Versions: $BuildVersion"

# ===================================================================================================
# Constants to support the script
# ===================================================================================================

$script:CustomPropertyNameList =
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
"NormalizedSubject",
"SendMeetingMessagesDiagnostics",
"SentRepresentingDisplayName",
"SentRepresentingEmailAddress",
"OriginalLastModifiedTime",
"ClientInfoString",
"OriginalStartDate",
"LastModifiedTime",
"CreationTime",
"TimeZone"

$LogLimit = 2000

$WellKnownCN_CA = "MICROSOFT SYSTEM ATTENDANT"
$CalAttendant = "Calendar Assistant"
$WellKnownCN_Trans = "MicrosoftExchange"
$Transport = "Transport Service"

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

$ShortClientNameProcessor = @{
    'Client=Hub Transport'                       = "Transport"
    'Client=MSExchangeRPC'                       = "Outlook-MAPI"
    'OneOutlook'                                 = "OneOutlook"
    'Lync for Mac'                               = "LyncMac"
    'AppId=00000004-0000-0ff1-ce00-000000000000' = "SkypeMMS"
    'MicrosoftNinja'                             = "Teams"
    'SkypeSpaces'                                = "Teams"
    'Remove-CalendarEvents'                      = "RemoveCalendarEvent"
    'Client=POP3/IMAP4'                          = "PopImap"
    'Client=OWA'                                 = "OWA"
    'PublishedBookingCalendar'                   = "BookingAgent"
    'LocationAssistantProcessor'                 = "LocationProcessor"
    'AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d' = "CalendarReplication"
    'AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0' = "CiscoWebex"
    'AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f' = "Time Service"
    'AppId=48af08dc-f6d2-435f-b2a7-069abd99c086' = "RestConnector"
    'AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419' = "Bookings B2 Service"
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

function FindMatch {
    param(
        [HashTable] $PassedHash
    )
    foreach ($Val in $PassedHash.keys) {
        if ($KeyInput -like "*$Val*") {
            return $PassedHash[$Val]
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
        Write-Verbose "Searching Get-Mailbox $(if (-not ([string]::IsNullOrEmpty($Organization))) {"with Org: $Organization"}) for $Identity."

        if ($Identity -and $Organization) {
            if ($script:MSSupport) {
                Write-Verbose "Using Organization parameter"
                $GetMailboxOutput = Get-Mailbox -Identity $Identity -Organization $Organization -ErrorAction SilentlyContinue
            } else {
                Write-Verbose "Using -OrganizationalUnit parameter"
                $GetMailboxOutput = Get-Mailbox -Identity $Identity -OrganizationalUnit $Organization -ErrorAction SilentlyContinue
            }
        } else {
            $GetMailboxOutput = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue
        }

        if (!$GetMailboxOutput) {
            Write-Host "Unable to find [$Identity]$(if ($Organization -ne `"`" ) {" in Organization:[$Organization]"})."
            Write-Host "Trying to find a Group Mailbox for [$Identity]..."
            $GetMailboxOutput = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue -GroupMailbox
            if (!$GetMailboxOutput) {
                Write-Host "Unable to find a Group Mailbox for [$Identity] either."
                return $null
            } else {
                Write-Verbose "Found GroupMailbox [$($GetMailboxOutput.DisplayName)]"
            }
        } else {
            Write-Verbose "Found [$($GetMailboxOutput.DisplayName)]"
        }

        if (CheckForNoPIIAccess($script:GetMailboxOutput.DisplayName)) {
            Write-Host -ForegroundColor Magenta "No PII Access for [$Identity]"
        } else {
            Write-Verbose "Found [$($GetMailboxOutput.DisplayName)]"
        }
        return $GetMailboxOutput
    } catch {
        Write-Error "An error occurred while running Get-Mailbox: [$_]"
    }
}

<#
.SYNOPSIS
Checks if a set of Calendar Logs is from the Organizer.
#>
function SetIsOrganizer {
    param(
        $CalLogs
    )
    [bool] $IsOrganizer = $false

    foreach ($CalLog in $CalLogs) {
        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -and
            $CalLog.ExternalSharingMasterId -eq "NotFound" -and
            ($CalLog.ResponseType -eq "1" -or $CalLogs.ResponseType -eq "Organizer")) {
            $IsOrganizer = $true
            Write-Verbose "IsOrganizer: [$IsOrganizer]"
            return $IsOrganizer
        }
    }
    Write-Verbose "IsOrganizer: [$IsOrganizer]"
    return $IsOrganizer
}

function SetIsRoom {
    param(
        $CalLogs
    )
    [bool] $IsRoom = $false
    # Simple logic is if RBA is running on the MB, it is a Room MB, otherwise it is not.
    foreach ($CalLog in $CalLogs) {
        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -and
            $CalLog.ExternalSharingMasterId -eq "NotFound" -and
            $CalLog.Client -eq "ResourceBookingAssistant" ) {
            $IsRoom = $true
            return $IsRoom
        }
    }
    return $IsRoom
}

function SetIsRecurring {
    param(
        $CalLogs
    )
    Write-Host -ForegroundColor Yellow "Looking for signs of a recurring meeting."
    [bool] $IsRecurring = $false
    # See if this is a recurring meeting
    foreach ($CalLog in $CalLogs) {
        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -and
            $CalLog.ExternalSharingMasterId -eq "NotFound" -and
            ($CalLog.CalendarItemType.ToString() -eq "RecurringMaster" -or
            $CalLog.IsException -eq $true)) {
            $IsRecurring = $true
            Write-Verbose "Found recurring meeting."
            return $IsRecurring
        }
    }
    Write-Verbose "Did not find signs of recurring meeting."
    return $IsRecurring
}

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

    Write-Debug "GetMailboxProp: [$Prop]: Searching for:[$PassedCN]..."

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
                    $ReturnValue = $script:MailboxList[$PassedCN].$Prop

                    if ($null -eq $ReturnValue) {
                        Write-Error "`t GetMailboxProp:$Prop :NotFound for ::[$PassedCN]"
                        return BetterThanNothingCNConversion($PassedCN)
                    }

                    Write-Verbose "`t GetMailboxProp:[$Prop] :Found::[$ReturnValue]"
                    if (CheckForNoPIIAccess($ReturnValue)) {
                        Write-Verbose "No PII Access for [$ReturnValue]"
                        return BetterThanNothingCNConversion($PassedCN)
                    }
                    return $ReturnValue
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
        $cNameMatch = $PassedCN -split "cn="

        # Normally a readable name is sectioned off with a "-" at the end.
        # Example /o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=d61149258ba04404adda42f336b504ed-Delegate
        if ($cNameMatch[-1] -match "-[\w* -.]*") {
            Write-Verbose "BetterThanNothingCNConversion: Matched : [$($cNameMatch[-1])]"
            $cNameSplit = $cNameMatch.split('-')[-1]
            # Sometimes we have a more than one "-" in the name, so we end up with only 1-4 chars which is too little.
            # Example: .../CN=RECIPIENTS/CN=83DAA772E6A94DA19402AA6B41770486-4DB5F0EB-4A
            if ($cNameSplit.length -lt 5) {
                Write-Verbose "BetterThanNothingCNConversion: [$cNameSplit] is too short"
                $cNameSplit= $cNameMatch.split('-')[-2] + '-' + $cNameMatch.split('-')[-1]
                Write-Verbose "BetterThanNothingCNConversion: Returning Lengthened : [$cNameSplit]"
            }
            return $cNameSplit
        }
        # Sometimes we do not have the "-" in front of the Name.
        # Example: "/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=user123"
        if ($cNameMatch[-1] -match "[\w* -.]*") {
            Write-Verbose "BetterThanNothingCNConversion: Returning : [$($cNameMatch[-1])]"
            return $cNameMatch.split('-')[-1]
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
    } elseif ($PassedCN -match "@") {
        Write-Verbose "Looks like we have an SMTP Address already: [$PassedCN]"
        return $PassedCN
    } elseif ($PassedCN -match "NotFound") {
        return $PassedCN
    } else {
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
Creates a list of CN that are used in the Calendar Logs, Looks up the Mailboxes and stores them in the MailboxList.
#>
function ConvertCNtoSMTP {
    # Creates a list of CN's that we will do MB look up on
    $CNEntries = @()
    $CNEntries += ($script:GCDO.SentRepresentingEmailAddress.ToUpper() | Select-Object -Unique)
    $CNEntries += ($script:GCDO.ResponsibleUserName.ToUpper() | Select-Object -Unique)
    $CNEntries += ($script:GCDO.SenderEmailAddress.ToUpper() | Select-Object -Unique)
    $CNEntries = $CNEntries | Select-Object -Unique
    Write-Verbose "`t Have $($CNEntries.count) CNEntries to look for..."
    Write-Verbose "CNEntries: "; foreach ($CN in $CNEntries) { Write-Verbose $CN }

    $Org = $script:MB.OrganizationalUnit.split('/')[-1]

    # Creates a Dictionary of MB's that we will use to look up the CN's
    Write-Verbose "Converting CN entries into SMTP Addresses..."
    foreach ($CNEntry in $CNEntries) {
        if ($CNEntry -match 'cn=([\w,\s.@-]*[^/])$') {
            if ($CNEntry -match $WellKnownCN_CA) {
                $script:MailboxList[$CNEntry] = $CalAttendant
            } elseif ($CNEntry -match $WellKnownCN_Trans) {
                $script:MailboxList[$CNEntry] = $Transport
            } else {
                $script:MailboxList[$CNEntry] = (GetMailbox -Identity $CNEntry -Organization $Org)
            }
        }
    }

    foreach ($key in $script:MailboxList.Keys) {
        $value = $script:MailboxList[$key]
        Write-Verbose "$key :: $($value.DisplayName)"
    }
}

<#
.SYNOPSIS
Creates friendly / short client names from the ClientInfoString
#>
function CreateShortClientName {
    param(
        $ClientInfoString
    )
    $ShortClientName= @()

    # Map ClientInfoString to ShortClientName
    if (!$ClientInfoString) {
        $ShortClientName = "NotFound"
    }

    if ($ClientInfoString -like "Client=EBA*" -or $ClientInfoString -like "Client=TBA*") {
        if ($ClientInfoString -like "*ResourceBookingAssistant*") {
            $ShortClientName = "ResourceBookingAssistant"
        } elseif ($ClientInfoString -like "*CalendarRepairAssistant*") {
            $ShortClientName = "CalendarRepairAssistant"
        } else {
            $client = $ClientInfoString.Split(';')[0].Split('=')[-1]
            $Action = $ClientInfoString.Split(';')[1].Split('=')[-1]
            $Data = $ClientInfoString.Split(';')[-1]
            $ShortClientName = $client+":"+$Action+";"+$Data
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
            $ShortClientName = "LocationProcessor"
        } elseif ($ClientInfoString -like "*AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d*") {
            $ShortClientName = "CalendarReplication"
        } elseif ($ClientInfoString -like "*AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0*") {
            $ShortClientName = "CiscoWebex"
        } elseif ($ClientInfoString -like "*AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f*") {
            $ShortClientName = "TimeService"
        } elseif ($ClientInfoString -like "*AppId=48af08dc-f6d2-435f-b2a7-069abd99c086*") {
            $ShortClientName = "RestConnector"
        } elseif ($ClientInfoString -like "*Client=OutlookService;Outlook-Android*") {
            $ShortClientName = "OutlookAndroid"
        } elseif ($ClientInfoString -like "*GriffinRestClient*") {
            $ShortClientName = "GriffinRestClient"
        } elseif ($ClientInfoString -like "*MacOutlook*") {
            $ShortClientName = "MacOutlookRest"
        } elseif ($ClientInfoString -like "*Microsoft Outlook 16*") {
            $ShortClientName = "Outlook-ModernCalendarSharing"
        } elseif ($ClientInfoString -like "*SkypeSpaces*") {
            $ShortClientName = "Teams"
        } elseif ($ClientInfoString -like "*AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419*") {
            $ShortClientName = "Bookings B2 Service"
        } elseif ($ClientInfoString -like "*bcad1a65-78eb-4725-9bce-ce1a8ed30b95*" -or
            $ClientInfoString -like "*43375d74-c6a5-4d4e-a0a3-de139860ea75*" -or
            $ClientInfoString -like "*af9fc99a-5ae5-46e1-bbd7-fa25088e16c9*") {
            $ShortClientName = "ELC-B2"
        } elseif ($ClientInfoString -like "*NoUserAgent*") {
            $ShortClientName = "RestUnknown"
        } else {
            $ShortClientName = "[Unknown Rest Client]"
        }
        #    Client=WebServices;Mozilla/5.0 (ZoomPresence.Android 8.1.0 x86);
    } else {
        $ShortClientName = findMatch -PassedHash $ShortClientNameProcessor
    }

    if ($ShortClientName -eq "" -And $ClientInfoString -like "Client=WebServices*") {
        if ($ClientInfoString -like "*ZoomPresence*") {
            $ShortClientName = "ZoomPresence"
        } else {
            $ShortClientName = "Unknown EWS App"
        }
    }

    if ($ClientInfoString -like "*InternalCalendarSharing*" -and
        $ClientInfoString -like "*OWA*" -and
        $ClientInfoString -notlike "*OneOutlook*") {
        $ShortClientName = "Owa-ModernCalendarSharing"
    }
    if ($ClientInfoString -like "*InternalCalendarSharing*" -and $ClientInfoString -like "*MacOutlook*") {
        $ShortClientName = "MacOutlook-ModernCalendarSharing"
    }
    if ($ClientInfoString -like "*InternalCalendarSharing*" -and $ClientInfoString -like "*Outlook*") {
        $ShortClientName = "Outlook-ModernCalendarSharing"
    }
    if ($ClientInfoString -like "Client=ActiveSync*" -and $ClientInfoString -like "*Outlook*") {
        $ShortClientName = "Outlook-ModernCalendarSharing"
    }
    if ($ClientInfoString -like "*OneOutlook*") {
        $ShortClientName = "OneOutlook"
    }
    if ($ShortClientName -eq "") {
        $ShortClientName = "[NoShortNameFound]"
    }

    return $ShortClientName
}

<#
.SYNOPSIS
Checks to see if the Calendar Log is Ignorable.
Many updates are not interesting in the Calendar Log, marking these as ignorable. 99% of the time this is correct.
#>
function SetIsIgnorable {
    param(
        $CalLog
    )

    if ($CalLog.ItemClass -eq "(Occurrence Deleted)") {
        return "Ignorable"
    } elseif ($ShortClientName -like "TBA*SharingSyncAssistant" -or
        $ShortClientName -eq "CalendarReplication" -or
        $CalendarItemTypes.($CalLog.ItemClass) -eq "SharingCFM" -or
        $CalendarItemTypes.($CalLog.ItemClass) -eq "SharingDelete") {
        return "Sharing"
    } elseif ($ShortClientName -like "EBA*" -or
        $ShortClientName -like "TBA*" -or
        $ShortClientName -eq "LocationProcessor" -or
        $ShortClientName -eq "GriffinRestClient" -or
        $ShortClientName -eq "RestConnector" -or
        $ShortClientName -eq "ELC-B2" -or
        $ShortClientName -eq "TimeService" ) {
        return "Ignorable"
    } elseif ($CalLog.ItemClass -eq "IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}" ) {
        return "Exception"
    } elseif (($CalendarItemTypes.($CalLog.ItemClass) -like "*Resp*" -and $CalLog.CalendarLogTriggerAction -ne "Create" ) -or
        $CalendarItemTypes.($CalLog.ItemClass) -eq "AttendeeList" ) {
        return "Cleanup"
    } else {
        return "False"
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

function MultiLineFormat {
    param(
        $PassedString
    )
    $PassedString = $PassedString -replace "},", "},`n"
    return $PassedString.Trim()
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
function BuildTimeline {
    param (
        [string] $Identity
    )
    $ThisMeetingID = $script:GCDO.CleanGlobalObjectId | Select-Object -Unique
    $ShortMeetingID = $ThisMeetingID.Substring($ThisMeetingID.length - 6)
    if ($Identity -like "*@*") {
        $ShortName = $Identity.Split('@')[0]
    }
    $ShortName = $ShortName.Substring(0, [System.Math]::Min(20, $ShortName.Length))
    $Script:TimeLineFilename = "$($ShortName)_TimeLine_$ShortMeetingID.csv"

    Write-DashLineBoxColor " TimeLine for [$Identity]:",
    "  Subject: $($script:GCDO[0].NormalizedSubject)",
    "  Organizer: $($script:GCDO[0].SentRepresentingDisplayName)",
    "  MeetingID: $($script:GCDO[0].CleanGlobalObjectId)"
    [Array]$Header = ("Subject: " + ($script:GCDO[0].NormalizedSubject) + " | MeetingID: "+ ($script:GCDO[0].CleanGlobalObjectId))
    MeetingSummary -Time "Calendar Log Timeline for Meeting with" -MeetingChanges $Header
    MeetingSummary -Time "Initial Message Values" -Entry $script:GCDO[0] -LongVersion
    # Ignorable and items from Shared Calendars are not included in the TimeLine.
    $MeetingTimeLine = $Results | Where-Object { $_.IsIgnorable -eq "False" -and $_.IsFromSharedCalendar -eq $False }

    Write-Host "`n`n`nThis is the meetingID $ThisMeetingID`nThis is Short MeetingID $ShortMeetingID"
    if ($MeetingTimeLine.count -eq 0) {
        Write-Host "All CalLogs are Ignorable, nothing to create a timeline with, displaying initial values."
    } else {
        Write-Host "Found $($script:GCDO.count) Log entries, only the $($MeetingTimeLine.count) Non-Ignorable entries will be analyzed in the TimeLine."
    }

    foreach ($CalLog in $MeetingTimeLine) {
        [bool] $MeetingSummaryNeeded = $False
        [bool] $AddChangedProperties = $False

        <#
        .SYNOPSIS
            Determines if key properties of the calendar log have changed.
        .DESCRIPTION
            This function checks if the properties of the calendar log have changed by comparing the current
            Calendar log to the Previous calendar log (where it was an IPM.Appointment - i.e. the meeting)

            Changed properties will be added to the Timeline.
        #>
        function ChangedProperties {
            if ($CalLog.Client -ne "LocationProcessor" -or $CalLog.Client -notlike "EBA:*" -or $CalLog.Client -notlike "TBA:*") {
                if ($PreviousCalLog -and $AddChangedProperties) {
                    if ($CalLog.StartTime.ToString() -ne $PreviousCalLog.StartTime.ToString()) {
                        [Array]$TimeLineText = "The StartTime changed from [$($PreviousCalLog.StartTime)] to: [$($CalLog.StartTime)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.EndTime.ToString() -ne $PreviousCalLog.EndTime.ToString()) {
                        [Array]$TimeLineText = "The EndTime changed from [$($PreviousCalLog.EndTime)] to: [$($CalLog.EndTime)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.SubjectProperty -ne $PreviousCalLog.SubjectProperty) {
                        [Array]$TimeLineText = "The SubjectProperty changed from [$($PreviousCalLog.SubjectProperty)] to: [$($CalLog.SubjectProperty)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.NormalizedSubject -ne $PreviousCalLog.NormalizedSubject) {
                        [Array]$TimeLineText = "The NormalizedSubject changed from [$($PreviousCalLog.NormalizedSubject)] to: [$($CalLog.NormalizedSubject)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
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
                        [Array]$TimeLineText = "The Meeting Request Type changed from [$($PreviousCalLog.MeetingRequestType.Value)] to: [$($CalLog.MeetingRequestType.Value)]"
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

        <#
        .SYNOPSIS
            This is the part that generates the heart of the timeline, a Giant Switch statement based on the ItemClass.
        #>
        switch -Wildcard ($CalendarItemTypes.($CalLog.ItemClass)) {
            MeetingRequest {
                switch ($CalLog.TriggerAction) {
                    Create {
                        if ($IsOrganizer) {
                            if ($CalLog.IsException -eq $True) {
                                [array] $Output = "[$($CalLog.ResponsibleUser)] Created an Exception Meeting Request with $($CalLog.Client) for [$($CalLog.StartTime)]."
                            } else {
                                [array] $Output  = "[$($CalLog.ResponsibleUser)] Created a Meeting Request was with $($CalLog.Client)"
                            }
                        } else {
                            if ($CalLog.DisplayAttendeesTo -ne $PreviousCalLog.DisplayAttendeesTo -or $CalLog.DisplayAttendeesCc -ne $PreviousCalLog.DisplayAttendeesCc) {
                                [array] $Output = "The user Forwarded a Meeting Request with $($CalLog.Client)."
                            } else {
                                if ($CalLog.Client -eq "Transport") {
                                    if ($CalLog.IsException -eq $True) {
                                        [array] $Output = "Transport delivered a new Meeting Request from [$($CalLog.SentRepresentingDisplayName)] for an exception starting on [$($CalLog.StartTime)]" + $(if ($null -ne $($CalLog.ReceivedRepresenting)) { " for user [$($CalLog.ReceivedRepresenting)]" })  + "."
                                        $MeetingSummaryNeeded = $True
                                    } else {
                                        [Array]$Output = "Transport delivered a new Meeting Request from [$($CalLog.SentRepresentingDisplayName)]" +
                                        $(if ($null -ne $($CalLog.ReceivedRepresenting) -and $CalLog.ReceivedRepresenting -ne $CalLog.ReceivedBy)
                                            { " for user [$($CalLog.ReceivedRepresenting)]" }) + "."
                                    }
                                } elseif ($CalLog.Client -eq "CalendarRepairAssistant") {
                                    if ($CalLog.IsException -eq $True) {
                                        [array] $Output = "CalendarRepairAssistant Created a new Meeting Request to repair an inconsistency with an exception starting on [$($CalLog.StartTime)]."
                                    } else {
                                        [array] $Output = "CalendarRepairAssistant Created a new Meeting Request to repair an inconsistency."
                                    }
                                } else {
                                    if ($CalLog.IsException -eq $True) {
                                        [array] $Output = "[$($CalLog.ResponsibleUser)] Created a new Meeting Request with $($CalLog.Client) for an exception starting on [$($CalLog.StartTime)]."
                                    } else {
                                        [array] $Output = "[$($CalLog.ResponsibleUser)] Created a new Meeting Request with $($CalLog.Client)."
                                    }
                                }
                            }
                        }
                    }
                    Update {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] Updated on the $($CalLog.MeetingRequestType.Value) Meeting Request with $($CalLog.Client)."
                    }
                    MoveToDeletedItems {
                        if ($CalLog.ResponsibleUser -eq "Calendar Assistant") {
                            [array] $Output = "$($CalLog.Client) Deleted the Meeting Request."
                        } else {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] Deleted the Meeting Request with $($CalLog.Client)."
                        }
                    }
                    default {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] Deleted the $($CalLog.MeetingRequestType.Value) Meeting Request with $($CalLog.Client)."
                    }
                }
            }
            Resp* {
                switch ($CalLog.ItemClass) {
                    "IPM.Schedule.Meeting.Resp.Tent" { $MeetingRespType = "Tentative" }
                    "IPM.Schedule.Meeting.Resp.Neg" { $MeetingRespType = "DECLINE" }
                    "IPM.Schedule.Meeting.Resp.Pos" { $MeetingRespType = "ACCEPT" }
                }

                if ($CalLog.AppointmentCounterProposal -eq "True") {
                    [array] $Output = "[$($CalLog.SentRepresentingDisplayName)] send a $($MeetingRespType) response message with a New Time Proposal: $($CalLog.StartTime) to $($CalLog.EndTime)"
                } else {
                    switch -Wildcard ($CalLog.TriggerAction) {
                        "Update" { $Action = "Updated" }
                        "Create" { $Action = "Sent" }
                        "*Delete*" { $Action = "Deleted" }
                        default {
                            $Action = "Updated"
                        }
                    }

                    $Extra = ""
                    if ($CalLog.IsException) {
                        $Extra = " to the meeting starting $($CalLog.StartTime)"
                    } elseif ($CalLog.AppointmentRecurring) {
                        $Extra = " to the meeting series"
                    }

                    if ($IsOrganizer) {
                        [array] $Output = "[$($CalLog.SentRepresentingDisplayName)] $($Action) a $($MeetingRespType) Meeting Response message$($Extra)."
                    } else {
                        switch ($CalLog.Client) {
                            ResourceBookingAssistant {
                                [array] $Output = "ResourceBookingAssistant $($Action) a $($MeetingRespType) Meeting Response message."
                            }
                            Transport {
                                [array] $Output = "[$($CalLog.From)] $($Action) $($MeetingRespType) Meeting Response message."
                            }
                            default {
                                [array] $Output = "[$($CalLog.ResponsibleUser)] $($Action) [$($CalLog.SentRepresentingDisplayName)]'s $($MeetingRespType) Meeting Response with $($CalLog.Client)."
                            }
                        }
                    }
                }
            }
            ForwardNotification {
                [array] $Output = "The meeting was FORWARDED by [$($CalLog.SentRepresentingDisplayName)]."
            }
            ExceptionMsgClass {
                if ($CalLog.ResponsibleUser -ne "Calendar Assistant") {
                    [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d Exception to the meeting series with $($CalLog.Client)."
                }
            }
            IpmAppointment {
                switch ($CalLog.TriggerAction) {
                    Create {
                        if ($IsOrganizer) {
                            if ($CalLog.Client -eq "Transport") {
                                [array] $Output = "Transport Created a new meeting."
                            } else {
                                [array] $Output = "[$($CalLog.ResponsibleUser)] Created a new Meeting with $($CalLog.Client)."
                            }
                        } else {
                            switch ($CalLog.Client) {
                                Transport {
                                    [array] $Output = "Transport Created a new Meeting on the calendar from [$($CalLog.SentRepresentingDisplayName)] and marked it Tentative."
                                }
                                ResourceBookingAssistant {
                                    [array] $Output = "ResourceBookingAssistant Created a new Meeting on the calendar from [$($CalLog.SentRepresentingDisplayName)] and marked it Tentative."
                                }
                                default {
                                    [array] $Output = "[$($CalLog.ResponsibleUser)] Created the Meeting with $($CalLog.Client)."
                                }
                            }
                        }
                    }
                    Update {
                        switch ($CalLog.Client) {
                            Transport {
                                if ($CalLog.ResponsibleUser -eq "Calendar Assistant") {
                                    [array] $Output = "Transport Updated the meeting based on changes made to the meeting on [$($CalLog.Sender)] calendar."
                                } else {
                                    [array] $Output = "Transport $($CalLog.TriggerAction)d the meeting based on changes made by [$($CalLog.ResponsibleUser)]."
                                }
                            }
                            LocationProcessor {
                                [array] $Output = ""
                            }
                            ResourceBookingAssistant {
                                [array] $Output = "ResourceBookingAssistant $($CalLog.TriggerAction)d the Meeting."
                            }
                            CalendarRepairAssistant {
                                [array] $Output = "CalendarRepairAssistant $($CalLog.TriggerAction)d the Meeting to repair an inconsistency."
                            }
                            default {
                                if ($CalLog.ResponsibleUser -eq "Calendar Assistant") {
                                    [array] $Output = "The Exchange System $($CalLog.TriggerAction)d the meeting via the Calendar Assistant."
                                } else {
                                    [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d the Meeting with $($CalLog.Client)."
                                    $AddChangedProperties = $True
                                }
                            }
                        }

                        if ($CalLog.FreeBusyStatus -eq 2 -and $PreviousCalLog.FreeBusyStatus -ne 2) {
                            if ($CalLog.ResponsibleUserName -eq "Calendar Assistant") {
                                [array] $Output = "$($CalLog.Client) Accepted the meeting."
                            } else {
                                [array] $Output = "[$($CalLog.ResponsibleUser)] Accepted the meeting with $($CalLog.Client)."
                            }
                            $AddChangedProperties = $False
                        } elseif ($CalLog.FreeBusyStatus -ne 2 -and $PreviousCalLog.FreeBusyStatus -eq 2) {
                            if ($IsOrganizer) {
                                [array] $Output = "[$($CalLog.ResponsibleUser)] Cancelled the Meeting with $($CalLog.Client)."
                            } else {
                                if ($CalLog.ResponsibleUser -ne "Calendar Assistant") {
                                    [array] $Output = "[$($CalLog.ResponsibleUser)] Declined the meeting with $($CalLog.Client)."
                                }
                            }
                            $AddChangedProperties = $False
                        }
                    }
                    SoftDelete {
                        switch ($CalLog.Client) {
                            Transport {
                                [array] $Output = "Transport $($CalLog.TriggerAction)d the meeting based on changes by [$($CalLog.SentRepresentingDisplayName)]."
                            }
                            LocationProcessor {
                                [array] $Output = ""
                            }
                            ResourceBookingAssistant {
                                [array] $Output = "ResourceBookingAssistant $($CalLog.TriggerAction)d the Meeting."
                            }
                            default {
                                if ($CalLog.ResponsibleUser -eq "Calendar Assistant") {
                                    [array] $Output = "The Exchange System $($CalLog.TriggerAction)d the meeting via the Calendar Assistant."
                                } else {
                                    [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d the meeting with $($CalLog.Client)."
                                    $AddChangedProperties = $True
                                }
                            }
                        }

                        if ($CalLog.FreeBusyStatus -eq 2 -and $PreviousCalLog.FreeBusyStatus -ne 2) {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] Accepted the Meeting with $($CalLog.Client)."
                            $AddChangedProperties = $False
                        } elseif ($CalLog.FreeBusyStatus -ne 2 -and $PreviousCalLog.FreeBusyStatus -eq 2) {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] Declined the Meeting with $($CalLog.Client)."
                            $AddChangedProperties = $False
                        }
                    }
                    MoveToDeletedItems {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] Deleted the Meeting with $($CalLog.Client) (Moved the Meeting to the Deleted Items)."
                    }
                    default {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction) the Meeting with $($CalLog.Client)."
                        $MeetingSummaryNeeded = $False
                    }
                }
            }
            Cancellation {
                switch ($CalLog.Client) {
                    Transport {
                        if ($CalLog.IsException -eq $True) {
                            [array] $Output = "Transport $($CalLog.TriggerAction)d a Meeting Cancellation based on changes by [$($CalLog.SenderSMTPAddress)] for the exception starting on [$($CalLog.StartTime)]"
                        } else {
                            [array] $Output = "Transport $($CalLog.TriggerAction)d a Meeting Cancellation based on changes by [$($CalLog.SenderSMTPAddress)]."
                        }
                    }
                    default {
                        if ($CalLog.IsException -eq $True) {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d a Cancellation with $($CalLog.Client) for the exception starting on [$($CalLog.StartTime)]."
                        } elseif ($CalLog.CalendarItemType -eq "RecurringMaster") {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d a Cancellation for the Series with $($CalLog.Client)."
                        } else {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d the Cancellation with $($CalLog.Client)."
                        }
                    }
                }
            }
            default {
                if ($CalLog.TriggerAction -eq "Create") {
                    $Action = "New"
                } else {
                    $Action = "$($CalLog.TriggerAction)"
                }
                [array] $Output = "[$($CalLog.ResponsibleUser)] performed a $($Action) on the $($CalLog.ItemClass) with $($CalLog.Client)."
            }
        }

        # Create the Timeline by adding to Time to the generated Output
        $Time = "$($CalLog.LogRow) -- $($CalLog.LastModifiedTime)"

        if ($Output) {
            if ($MeetingSummaryNeeded) {
                MeetingSummary -Time $Time -MeetingChanges $Output
                MeetingSummary -Time " " -ShortVersion -Entry $CalLog
            } else {
                MeetingSummary -Time $Time -MeetingChanges $Output
                if ($AddChangedProperties) {
                    ChangedProperties
                }
            }
        }

        # Setup Previous log (if current logs is an IPM.Appointment)
        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -or $CalendarItemTypes.($CalLog.ItemClass) -eq "ExceptionMsgClass") {
            $PreviousCalLog = $CalLog
        }
    }

    $Results = @()
}

<#
.SYNOPSIS
    Function to write a line of text surrounded by a dash line box.

.DESCRIPTION
    The Write-DashLineBoxColor function is used to create a quick and easy display around a line of text. It generates a box made of dash characters ("-") and displays the provided line of text inside the box.

.PARAMETER Line
    Specifies the line of text to be displayed inside the dash line box.

.PARAMETER Color
    Specifies the color of the dash line box and the text. The default value is "White".

.PARAMETER DashChar
    Specifies the character used to create the dash line. The default value is "-".

.EXAMPLE
    Write-DashLineBoxColor -Line "Hello, World!" -Color "Yellow" -DashChar "="
    Displays:
    ==============
    Hello, World!
    ==============
#>
function Write-DashLineBoxColor {
    [CmdletBinding()]
    param(
        [string[]]$Line,
        [string] $Color = "White",
        [char] $DashChar = "-"
    )
    $highLineLength = 0
    $Line | ForEach-Object { if ($_.Length -gt $highLineLength) { $highLineLength = $_.Length } }
    $dashLine = [string]::Empty
    1..$highLineLength | ForEach-Object { $dashLine += $DashChar }
    Write-Host
    Write-Host -ForegroundColor $Color $dashLine
    $Line | ForEach-Object { Write-Host -ForegroundColor $Color $_ }
    Write-Host -ForegroundColor $Color $dashLine
    Write-Host
}

<#
.SYNOPSIS
Checks the identities are EXO Mailboxes.
#>
function CheckIdentities {
    if (Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue) {
        Write-Host "Validated connection to Exchange Online."
    } else {
        Write-Error "Get-Mailbox cmdlet not found. Please validate that you are running this script from an Exchange Management Shell and try again."
        Write-Host "Look at Import-Module ExchangeOnlineManagement and Connect-ExchangeOnline."
        exit
    }

    # See if it is a Customer Tenant running the cmdlet. (They will not have access to Organization parameter)
    $script:MSSupport = [Bool](Get-Help Get-Mailbox -Parameter Organization -ErrorAction SilentlyContinue)
    Write-Verbose "MSSupport: $script:MSSupport"

    Write-Host "Checking for at least one valid mailbox..."
    $IdentityList = @()

    Write-Host "Preparing to check $($Identity.count) Mailbox(es)..."

    foreach ($Id in $Identity) {
        $Account = GetMailbox -Identity $Id
        if ($null -eq $Account) {
            # -or $script:MB.GetType().FullName -ne "Microsoft.Exchange.Data.Directory.Management.Mailbox") {
            Write-DashLineBoxColor "`n Error: Mailbox [$Id] not found on Exchange Online.  Please validate the mailbox name and try again.`n" -Color Red
            continue
        }
        if (CheckForNoPIIAccess $Account.DisplayName) {
            Write-Host -ForegroundColor DarkRed "No PII access for Mailbox [$Id]. Falling back to SMTP Address."
            $IdentityList += $ID
            if ($null -eq $script:MB) {
                $script:MB = $Account
            }
        } else {
            Write-Host "Mailbox [$Id] found as : $($Account.DisplayName)"
            $IdentityList += $Account.PrimarySmtpAddress.ToString()
            if ($null -eq $script:MB) {
                $script:MB = $Account
            }
        }
        if ($Account.CalendarVersionStoreDisabled -eq $true) {
            Write-Host -ForegroundColor DarkRed "Mailbox [$Id] has CalendarVersionStoreDisabled set to True.  This mailbox will not have Calendar Logs."
            Write-Host -ForegroundColor DarkRed "Some logs will be available for Mailbox [$Id] but they will not be complete."
        }
    }

    Write-Verbose "IdentityList: $IdentityList"

    if ($IdentityList.count -eq 0) {
        Write-DashLineBoxColor "`n No valid mailboxes found.  Please validate the mailbox name and try again. `n" Red
        exit
    }

    return $IdentityList
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
    Write-Host "Getting CalLogs based for [$Identity] with subject [$Subject]]"

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
        BuildCSV -Identity $Identity
        BuildTimeline -Identity $Identity
    }

    # Get the CalLogs for each MeetingID found.
    if ($GlobalObjectIds.count -gt 1) {
        Write-Host "Found multiple GlobalObjectIds: $($GlobalObjectIds.Count)."
        foreach ($MID in $GlobalObjectIds) {
            Write-DashLineBoxColor "Processing MeetingID: [$MID]"
            $script:GCDO = GetCalendarDiagnosticObjects -Identity $Identity -MeetingID $MID
            Write-Verbose "Found $($GCDO.count) CalLogs with MeetingID[$MID] ."
            BuildCSV -Identity $Identity
            BuildTimeline -Identity $Identity
        }
    } else {
        Write-Warning "No CalLogs were found."
    }
}

# ===================================================================================================
# Main
# ===================================================================================================

$ValidatedIdentities = CheckIdentities -Identity $Identity

if (-not ([string]::IsNullOrEmpty($Subject)) ) {
    if ($ValidatedIdentities.count -gt 1) {
        Write-Warning "Multiple mailboxes were found, but only one is supported for Subject searches.  Please specify a single mailbox."
        exit
    }
    GetCalLogsWithSubject -Identity $ValidatedIdentities -Subject $Subject
} elseif (-not ([string]::IsNullOrEmpty($MeetingID))) {
    # Process Logs based off Passed in MeetingID
    foreach ($ID in $ValidatedIdentities) {
        Write-DashLineBoxColor "Looking for CalLogs from [$ID] with passed in MeetingID."
        Write-Verbose "Running: Get-CalendarDiagnosticObjects -Identity [$ID] -MeetingID [$MeetingID] -CustomPropertyNames $CustomPropertyNameList -WarningAction Ignore -MaxResults $LogLimit -ResultSize $LogLimit -ShouldBindToItem $true;"
        $script:GCDO = GetCalendarDiagnosticObjects -Identity $ID -MeetingID $MeetingID

        if ($script:GCDO.count -gt 0) {
            Write-Host -ForegroundColor Cyan "Found $($script:GCDO.count) CalLogs with MeetingID [$MeetingID]."
            $script:IsOrganizer = (SetIsOrganizer -CalLogs $script:GCDO)
            Write-Host -ForegroundColor Cyan "The user [$ID] $(if ($IsOrganizer) {"IS"} else {"is NOT"}) the Organizer of the meeting."
            $IsRoomMB = (SetIsRoom -CalLogs $script:GCDO)
            if ($IsRoomMB) {
                Write-Host -ForegroundColor Cyan "The user [$ID] is a Room Mailbox."
            }

            if ($Exceptions.IsPresent) {
                Write-Verbose "Looking for Exception Logs..."
                $IsRecurring = SetIsRecurring -CalLogs $script:GCDO
                Write-Verbose "Meeting IsRecurring: $IsRecurring"

                if ($IsRecurring) {
                    #collect Exception Logs
                    $ExceptionLogs = @()
                    $LogToExamine = @()
                    $LogToExamine = $script:GCDO | Where-Object { $_.ItemClass -like 'IPM.Appointment*' } | Sort-Object ItemVersion

                    Write-Host -ForegroundColor Cyan "Found $($LogToExamine.count) CalLogs to examine for Exception Logs."
                    if ($LogToExamine.count -gt 100) {
                        Write-Host -ForegroundColor Cyan "`t This is a large number of logs to examine, this may take a while."
                        Write-Host -ForegroundColor Blue "`Press Y to continue..."
                        $Answer = [console]::ReadKey($true).Key
                        if ($Answer -ne "Y") {
                            Write-Host -ForegroundColor Cyan "User chose not to continue, skipping Exception Logs."
                            $LogToExamine = $null
                        }
                    }
                    Write-Host -ForegroundColor Cyan "`t Ignore the next [$($LogToExamine.count)] warnings..."
                    $logLeftCount = $LogToExamine.count

                    $ExceptionLogs = $LogToExamine | ForEach-Object {
                        $logLeftCount -= 1
                        Write-Verbose "Getting Exception Logs for [$($_.ItemId.ObjectId)]"
                        Get-CalendarDiagnosticObjects -Identity $ID -ItemIds $_.ItemId.ObjectId -ShouldFetchRecurrenceExceptions $true -CustomPropertyNames $CustomPropertyNameList
                        if ($logLeftCount % 50 -eq 0) {
                            Write-Host -ForegroundColor Cyan "`t [$($logLeftCount)] logs left to examine..."
                        }
                    }
                    # Remove the IPM.Appointment logs as they are already in the CalLogs.
                    $ExceptionLogs = $ExceptionLogs | Where-Object { $_.ItemClass -notlike "IPM.Appointment*" }
                    Write-Host -ForegroundColor Cyan "Found $($ExceptionLogs.count) Exception Logs, adding them into the CalLogs."

                    $script:GCDO = $script:GCDO + $ExceptionLogs | Select-Object *, @{n='OrgTime'; e= { [DateTime]::Parse($_.OriginalLastModifiedTime.ToString()) } } | Sort-Object OrgTime
                    $LogToExamine = $null
                    $ExceptionLogs = $null
                } else {
                    Write-Host -ForegroundColor Cyan "No Recurring Meetings found, no Exception Logs to collect."
                }
            }

            BuildCSV -Identity $ID
            BuildTimeline -Identity $ID
        } else {
            Write-Warning "No CalLogs were found for [$ID] with MeetingID [$MeetingID]."
        }
    }
} else {
    Write-Warning "A valid MeetingID was not found, nor Subject. Please confirm the MeetingID or Subject and try again."
}

Write-DashLineBoxColor "Hope this script was helpful in getting and understanding the Calendar Logs.",
"If you have issues or suggestion for this script, please send them to: ",
"`t CalLogFormatterDevs@microsoft.com" -Color Yellow -DashChar =
