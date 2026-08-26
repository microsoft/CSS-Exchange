# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
This Exchange Online script runs the Get-CalendarDiagnosticObjects script and returns a summarized timeline of actions in clear English
as well as the Calendar Diagnostic Objects in Excel.

.PARAMETER Identity
One or more SMTP Address of EXO User Mailbox to query.

.PARAMETER Subject
Subject of the meeting to query, only valid if Identity is a single user.

.PARAMETER MeetingID
The MeetingID of the meeting to query.

.PARAMETER TrackingLogs
Include specific tracking logs in the output. Only usable with the MeetingID parameter. Collected by default; use -NoTrackingLogs to skip.

.PARAMETER NoTrackingLogs
Do not collect Tracking Logs.

.PARAMETER Exceptions
Include Exception objects in the output. Collected by default for direct MeetingID searches and for Subject searches that resolve to exactly one MeetingID; use -NoExceptions to skip.

.PARAMETER ExportToExcel
Export the output to an Excel file with formatting.  Running the script for multiple users will create multiple tabs in the Excel file. (Default)

.PARAMETER ExportToCSV
Export the output to 3 CSV files per user.

.PARAMETER CaseNumber
Case Number to include in the Filename of the output.

.PARAMETER ShortLogs
Limit Logs to 500 instead of the default 2000, in case the server has trouble responding with the full logs.

.PARAMETER MaxLogs
Increase log limit to 12,000 in case the default 2000 does not contain the needed information. Note this can be time consuming, and it does not contain all the logs such as User Responses.

.PARAMETER CustomProperty
Advanced users can add custom properties to the output in the RAW output. This is not recommended unless you know what you are doing. The properties must be in the format of "PropertyName1, PropertyName2, PropertyName3". The properties will only be added to the RAW output.

.PARAMETER ExceptionDate
Date of the Exception Meeting to collect logs for. Fastest way to get Exceptions for a meeting after you have identified the MeetingID.

.PARAMETER NoExceptions
Do not collect Exception Meetings.  This was the default behavior of the script, now exceptions are collected by default.

.PARAMETER ClassicExceptions
Use the legacy per-appointment Exception collector instead of the default fast AppointmentRecurrenceBlob-based collector.

.PARAMETER AllExceptions
When collecting Exceptions with the default fast mode, collect all Exception dates instead of the default last 3 months.

.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity someuser@microsoft.com -MeetingID 040000008200E00074C5B7101A82E008000000008063B5677577D9010000000000000000100000002FCDF04279AF6940A5BFB94F9B9F73CD
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity someuser@microsoft.com -Subject "Test One Meeting Subject"
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity someuser@microsoft.com -Subject "Test One Meeting Subject" -NoExceptions
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity User1, User2, Delegate -MeetingID $MeetingID
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -NoExceptions
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -NoTrackingLogs
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -ExportToExcel -CaseNumber 123456
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -ExceptionDate "01/28/2024" -CaseNumber 123456
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -AllExceptions
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -ClassicExceptions

.SYNOPSIS
Used to collect easy to read Calendar Logs.

.LINK
    https://aka.ms/callogformatter
#>

[CmdletBinding(DefaultParameterSetName = 'Subject',
    SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory, Position = 0, HelpMessage = "Enter the Identity of the mailbox(es) to query. Press <Enter> again when done.")]
    [string[]]$Identity,
    [Parameter(HelpMessage = "Export all Logs to Excel (Default).")]
    [switch]$ExportToExcel,
    [Parameter(HelpMessage = "Export all Logs to CSV files.")]
    [switch]$ExportToCSV,
    [Parameter(HelpMessage = "Case Number to include in the Filename of the output.")]
    [string]$CaseNumber,
    [Parameter(HelpMessage = "Limit Logs to 500 instead of the default 2000, in case the server has trouble responding with the full logs.")]
    [switch]$ShortLogs,
    [Parameter(HelpMessage = "Limit Logs to 12000 instead of the default 2000, in case the server has trouble responding with the full logs.")]
    [switch]$MaxLogs,
    [Parameter(HelpMessage = "Custom Property to add to the RAW output.")]
    [string[]]$CustomProperty,

    [Parameter(Mandatory, ParameterSetName = 'MeetingID', Position = 1, HelpMessage = "Enter the MeetingID of the meeting to query. Recommended way to search for CalLogs.")]
    [string]$MeetingID,
    [Parameter(HelpMessage = "Include specific tracking logs in the output. Only usable with the MeetingID parameter.")]
    [switch]$TrackingLogs,
    [Parameter(HelpMessage = "Do Not collect Tracking Logs.")]
    [switch]$NoTrackingLogs,
    [Parameter(HelpMessage = "Include Exception objects in the output. Subject searches also collect them when exactly one MeetingID is found.")]
    [switch]$Exceptions,
    [Parameter(HelpMessage = "Date of the Exception to collect the logs for after identifying the MeetingID.")]
    [DateTime]$ExceptionDate,
    [Parameter(HelpMessage = "Do Not collect Exception Meetings.")]
    [switch]$NoExceptions,
    [Parameter(HelpMessage = "Use the legacy per-appointment Exception collector instead of the default fast AppointmentRecurrenceBlob-based collector.")]
    [switch]$ClassicExceptions,
    [Parameter(HelpMessage = "When using default fast Exception collection, collect all Exception dates instead of the default last 3 months.")]
    [switch]$AllExceptions,

    [Parameter(Mandatory, ParameterSetName = 'Subject', Position = 1, HelpMessage = "Enter the Subject of the meeting. Do not include the RE:, FW:, etc.,  No wild cards (* or ?)")]
    [string]$Subject
)

# ===================================================================================================
# Auto update script
# ===================================================================================================
$BuildVersion = ""
. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
if (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/CL-VersionsUrl" -Confirm:$false) {
    # Update was downloaded, so stop here.
    Write-Host -ForegroundColor Red "Script was updated. Please rerun the command."
    return
}

$script:command = $MyInvocation
$script:RunNumber = 0
$script:PreRunErrorCount = $Error.Count
Write-Verbose "The script was started with the following command line:"
Write-Verbose "Name:  $($script:command.MyCommand.name)"
Write-Verbose "Command Line:  $($script:command.line)"
Write-Verbose "Script Version: $BuildVersion"
$script:BuildVersion = $BuildVersion
$script:SubjectSearch = $false
$script:SubjectMeetingIdCount = 0
$script:SubjectResolvedMeetingId = $null
$script:SubjectCanCollectExceptions = $false
$script:SubjectSkippedExceptionCollection = $false
$script:ExceptionCollectionStatus = $null
# ===================================================================================================
# Support scripts
# ===================================================================================================
. $PSScriptRoot\CalLogHelpers\CalLogCSVFunctions.ps1
. $PSScriptRoot\CalLogHelpers\TimelineFunctions.ps1
. $PSScriptRoot\CalLogHelpers\MeetingSummaryFunctions.ps1
. $PSScriptRoot\CalLogHelpers\Invoke-GetMailbox.ps1
. $PSScriptRoot\CalLogHelpers\Invoke-GetCalLogs.ps1
. $PSScriptRoot\CalLogHelpers\CalLogInfoFunctions.ps1
. $PSScriptRoot\CalLogHelpers\ExceptionCollectionFunctions.ps1
. $PSScriptRoot\CalLogHelpers\CalLogExportFunctions.ps1
. $PSScriptRoot\CalLogHelpers\CreateTimelineRow.ps1
. $PSScriptRoot\CalLogHelpers\FindChangedPropFunctions.ps1
. $PSScriptRoot\CalLogHelpers\Write-DashLineBoxColor.ps1

# Default to Excel unless specified otherwise.
if (!$ExportToCSV.IsPresent) {
    Write-Host -ForegroundColor Yellow "Exporting to Excel."
    $script:ExportToExcel = $true
    . $PSScriptRoot\..\Shared\Confirm-Administrator.ps1
    $script:IsAdministrator = Confirm-Administrator
    . $PSScriptRoot\CalLogHelpers\ExcelModuleInstaller.ps1
    . $PSScriptRoot\CalLogHelpers\ExportToExcelFunctions.ps1
}

if ($AllExceptions.IsPresent -and $ClassicExceptions.IsPresent) {
    Write-Warning "-AllExceptions only applies to default fast Exception collection. The switch will be ignored when -ClassicExceptions is used."
}

# Default to Collecting Tracking Logs (MeetingID only)
if (-not ([string]::IsNullOrEmpty($MeetingID))) {
    if (!$NoTrackingLogs.IsPresent) {
        $TrackingLogs = $true
        Write-Host -ForegroundColor Yellow "Collecting Tracking Logs."
        Write-Host -ForegroundColor Yellow "`tTo skip collecting Tracking Logs, use the -NoTrackingLogs switch."
    } else {
        Write-Host -ForegroundColor Green "Not Collecting Tracking Logs."
    }

    # Default to Collecting Exceptions
    if ((!$NoExceptions.IsPresent) -and ([string]::IsNullOrEmpty($ExceptionDate))) {
        $Exceptions = $true
        Write-Host -ForegroundColor Yellow "Collecting Exceptions."
        Write-Host -ForegroundColor Yellow "`tTo skip collecting Exceptions, use the -NoExceptions switch."
        if ($ClassicExceptions.IsPresent) {
            Write-Host -ForegroundColor Yellow "`tClassic exception collection is enabled and will use the legacy per-appointment path."
        } else {
            Write-Host -ForegroundColor Yellow "`tFast exception collection is enabled by default and will parse AppointmentRecurrenceBlob first."
            if ($AllExceptions.IsPresent) {
                Write-Host -ForegroundColor Yellow "`tAll Exception dates will be collected."
            } else {
                Write-Host -ForegroundColor Yellow "`tOnly Exception dates from the last 3 months will be collected by default."
            }
        }
    } else {
        Write-Host -ForegroundColor Green "---------------------------------------"
        if ($NoExceptions.IsPresent) {
            Write-Host -ForegroundColor Green "Not Checking for Exceptions"
        } else {
            Write-Host -ForegroundColor Green "Checking for Exceptions on $ExceptionDate"
        }
        Write-Host -ForegroundColor Green "---------------------------------------"
    }
} else {
    # Subject-based search
    $script:SubjectSearch = $true
    if ((!$NoExceptions.IsPresent) -and ([string]::IsNullOrEmpty($ExceptionDate))) {
        $Exceptions = $true
        Write-Host -ForegroundColor Yellow "Using Subject search. Exception collection will run if the search resolves to exactly one MeetingID."
        Write-Host -ForegroundColor Yellow "`tTo skip collecting Exceptions for a single resolved MeetingID, use the -NoExceptions switch."
        if ($ClassicExceptions.IsPresent) {
            Write-Host -ForegroundColor Yellow "`tClassic exception collection is enabled for single-MeetingID Subject results."
        } else {
            Write-Host -ForegroundColor Yellow "`tFast exception collection is enabled by default for single-MeetingID Subject results."
            if ($AllExceptions.IsPresent) {
                Write-Host -ForegroundColor Yellow "`tAll Exception dates will be collected."
            } else {
                Write-Host -ForegroundColor Yellow "`tOnly Exception dates from the last 3 months will be collected by default."
            }
        }
    } else {
        Write-Host -ForegroundColor Green "Using Subject search without automatic Exception collection."
        if ($NoExceptions.IsPresent) {
            Write-Host -ForegroundColor Green "`t-NoExceptions was specified, so Exception collection will be skipped."
        } elseif (-not ([string]::IsNullOrEmpty($ExceptionDate))) {
            Write-Host -ForegroundColor Green "`t-ExceptionDate applies only after a specific MeetingID is selected."
        }
    }
    Write-Host -ForegroundColor Yellow "`tTracking Logs still require running the script with -MeetingID."
}

# ===================================================================================================
# Main
# ===================================================================================================

[array]$ValidatedIdentities = CheckIdentities -Identity $Identity

if ($ExportToExcel.IsPresent) {
    CheckExcelModuleInstalled
}

if (-not ([string]::IsNullOrEmpty($Subject)) ) {
    if ($ValidatedIdentities.count -gt 1) {
        Write-Error "Subject-based searches only support a single mailbox, but $($ValidatedIdentities.count) were provided: [$($ValidatedIdentities -join ', ')]."
        Write-Host -ForegroundColor Yellow "Options:"
        Write-Host -ForegroundColor Yellow "  1. Re-run with a single -Identity and -Subject."
        Write-Host -ForegroundColor Yellow "  2. Use -MeetingID instead of -Subject to search multiple mailboxes at once."
        Write-Host -ForegroundColor Yellow "     Tip: Run the script once with -Subject for one user, then use the MeetingID from the output to collect from all participants."
        exit
    }
    $script:Identity = $ValidatedIdentities[0]
    $script:CurrentIdentityRunStartTime = Get-Date
    GetCalLogsWithSubject -Identity $ValidatedIdentities -Subject $Subject
} elseif (-not ([string]::IsNullOrEmpty($MeetingID))) {
    #Validate MeetingID is good
    if ($MeetingID -like "UID:*") {
        $MeetingID = $MeetingID.Replace("UID:", "")
    }
    if ($MeetingID -notlike "040000008*") {
        Write-Error "This does not look like a valid MeetingID: $MeetingID."
        Write-Error "Calendar MeetingID almost always start with 040000008..."
    }
    # Process Logs based off Passed in MeetingID
    foreach ($ID in $ValidatedIdentities) {
        $script:CurrentIdentityRunStartTime = Get-Date
        Write-DashLineBoxColor "Looking for CalLogs from [$ID] with passed in MeetingID."
        Write-Verbose "Running: Get-CalendarDiagnosticObjects -Identity [$ID] -MeetingID [$MeetingID] -CustomPropertyNames $CustomPropertyNameList -WarningAction Ignore -MaxResults $LogLimit -ResultSize $LogLimit -ShouldBindToItem $true;"
        [array] $script:GCDO = GetCalendarDiagnosticObjects -Identity $ID -MeetingID $MeetingID
        $script:Identity = $ID
        if ($script:GCDO.count -gt 0) {
            Write-Host -ForegroundColor Cyan "Found $($script:GCDO.count) CalLogs with MeetingID [$MeetingID]."
            $script:IsOrganizer = (SetIsOrganizer -CalLogs $script:GCDO)
            Write-Host -ForegroundColor Cyan "The user [$ID] $(if ($IsOrganizer) {"IS"} else {"is NOT"}) the Organizer of the meeting."
            $script:IsRoomMB = (SetIsRoom -CalLogs $script:GCDO)
            if ($script:IsRoomMB) {
                Write-Host -ForegroundColor Cyan "The user [$ID] is a Room Mailbox."
            }

            if ($Exceptions) {
                CollectExceptionLogs -Identity $ID -MeetingID $MeetingID
            }

            BuildCSV
            BuildTimeline
        } else {
            Write-Warning "No CalLogs were found for [$ID] with MeetingID [$MeetingID]."
        }
    }
} else {
    Write-Warning "A valid MeetingID was not found, nor Subject. Please confirm the MeetingID or Subject and try again."
}

Write-DashLineBoxColor "Hope this script was helpful in getting and understanding the Calendar Logs.",
"More Info on Getting the logs: https://aka.ms/GetCalLogs",
"and on Analyzing the logs: https://aka.ms/AnalyzeCalLogs",
"If you have issues or suggestion for this script, please send them to: ",
"`t CalLogFormatterDevs@microsoft.com" -Color Yellow -DashChar "="

if ($ExportToExcel.IsPresent) {
    Write-Host
    Write-Host -ForegroundColor Blue -NoNewline "All Calendar Logs are saved to: "
    Write-Host -ForegroundColor Yellow ".\$Filename"
}
