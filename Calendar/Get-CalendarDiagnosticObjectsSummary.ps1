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
# Support scripts
# ===================================================================================================
. $PSScriptRoot\BuildTimeline.ps1
. $PSScriptRoot\BuildCSV.ps1
. $PSScriptRoot\CalLogMailboxUtilities.ps1
. $PSScriptRoot\CreateShortClientName.ps1
. $PSScriptRoot\MeetingSummary.ps1


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

function MultiLineFormat {
    param(
        $PassedString
    )
    $PassedString = $PassedString -replace "},", "},`n"
    return $PassedString.Trim()
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
