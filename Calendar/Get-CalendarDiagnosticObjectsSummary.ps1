# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
This Exchange Online script runs the Get-CalendarDiagnosticObjects script and returns a summarized timeline of actions in clear english
as well as the Calendar Diagnostic Objects in CSV format.

.PARAMETER Identity
One or more SMTP Address of EXO User Mailbox to query.

.PARAMETER Subject
Subject of the meeting to query, only valid if Identity is a single user.

.PARAMETER MeetingID
The MeetingID of the meeting to query.

.PARAMETER TrackingLogs
Include specific tracking logs in the output. Only useable with the MeetingID parameter.

.PARAMETER Exceptions
Include Exception objects in the output. Only useable with the MeetingID parameter.

.PARAMETER ExportToExcel
[Beta Feature] Export the output to an Excel file with formatting.  Running the scrip for multiple users will create multiple tabs in the Excel file.

.PARAMETER CaseNumber
Case Number to include in the Filename of the output.

.PARAMETER ShortLogs
Limit Logs to 500 instead of the default 2000, in case the server has trouble responding with the full logs.

.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity someuser@microsoft.com -MeetingID 040000008200E00074C5B7101A82E008000000008063B5677577D9010000000000000000100000002FCDF04279AF6940A5BFB94F9B9F73CD
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity someuser@microsoft.com -Subject "Test One Meeting Subject"
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity User1, User2, Delegate -MeetingID $MeetingID
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -TrackingLogs -Exceptions
.EXAMPLE
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -TrackingLogs -Exceptions -ExportToExcel -CaseNumber 123456

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
    [Parameter(HelpMessage = "Export all Logs to Excel.")]
    [switch]$ExportToExcel,
    [Parameter(HelpMessage = "Case Number to include in the Filename of the output.")]
    [string]$CaseNumber,
    [Parameter(HelpMessage = "Limit Logs to 500 instead of the default 2000, in case the server has trouble responding with the full logs.")]
    [switch]$ShortLogs,

    [Parameter(Mandatory, ParameterSetName = 'MeetingID', Position = 1, HelpMessage = "Enter the MeetingID of the meeting to query. Recommended way to search for CalLogs.")]
    [string]$MeetingID,
    [Parameter(HelpMessage = "Include specific tracking logs in the output. Only useable with the MeetingID parameter.")]
    [switch]$TrackingLogs,
    [Parameter(HelpMessage = "Include Exception objects in the output. Only useable with the MeetingID parameter.")]
    [switch]$Exceptions,

    [Parameter(Mandatory, ParameterSetName = 'Subject', Position = 1, HelpMessage = "Enter the Subject of the meeting. Do not include the RE:, FW:, etc..")]
    [string]$Subject
)

# ===================================================================================================
# Auto update script
# ===================================================================================================
$BuildVersion = ""
. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
if (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/CL-VersionsUrl" -Confirm:$false) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command." -ForegroundColor Yellow
    return
}

$script:command = $MyInvocation
Write-Verbose "The script was started with the following command line:"
Write-Verbose "Name:  $($script:command.MyCommand.name)"
Write-Verbose "Command Line:  $($script:command.line)"
Write-Verbose "Script Version: $BuildVersion"
$script:BuildVersion = $BuildVersion

# ===================================================================================================
# Support scripts
# ===================================================================================================
. $PSScriptRoot\CalLogHelpers\CalLogCSVFunctions.ps1
. $PSScriptRoot\CalLogHelpers\TimelineFunctions.ps1
. $PSScriptRoot\CalLogHelpers\MeetingSummaryFunctions.ps1
. $PSScriptRoot\CalLogHelpers\Invoke-GetMailbox.ps1
. $PSScriptRoot\CalLogHelpers\Invoke-GetCalLogs.ps1
. $PSScriptRoot\CalLogHelpers\CalLogInfoFunctions.ps1
. $PSScriptRoot\CalLogHelpers\CalLogExportFunctions.ps1
. $PSScriptRoot\CalLogHelpers\CreateTimelineRow.ps1
. $PSScriptRoot\CalLogHelpers\FindChangedPropFunctions.ps1
. $PSScriptRoot\CalLogHelpers\Write-DashLineBoxColor.ps1

if ($ExportToExcel.IsPresent) {
    . $PSScriptRoot\..\Shared\Confirm-Administrator.ps1
    $script:IsAdministrator = Confirm-Administrator
    . $PSScriptRoot\CalLogHelpers\ExcelModuleInstaller.ps1
    . $PSScriptRoot\CalLogHelpers\ExportToExcelFunctions.ps1
}

# ===================================================================================================
# Main
# ===================================================================================================

$ValidatedIdentities = CheckIdentities -Identity $Identity

if ($ExportToExcel.IsPresent) {
    CheckExcelModuleInstalled
}

if (-not ([string]::IsNullOrEmpty($Subject)) ) {
    if ($ValidatedIdentities.count -gt 1) {
        Write-Warning "Multiple mailboxes were found, but only one is supported for Subject searches.  Please specify a single mailbox."
        exit
    }
    $script:Identity = $ValidatedIdentities
    GetCalLogsWithSubject -Identity $ValidatedIdentities -Subject $Subject
} elseif (-not ([string]::IsNullOrEmpty($MeetingID))) {
    # Process Logs based off Passed in MeetingID
    foreach ($ID in $ValidatedIdentities) {
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

            if (CheckForBifurcation($script:GCDO) -ne false) {
                Write-Host -ForegroundColor Red "Warning: No IPM.Appointment found. CalLogs start to expire after 31 days."
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
                    }
                    $logLeftCount = $LogToExamine.count

                    $ExceptionLogs = $LogToExamine | ForEach-Object {
                        $logLeftCount -= 1
                        Write-Verbose "Getting Exception Logs for [$($_.ItemId.ObjectId)]"
                        Get-CalendarDiagnosticObjects -Identity $ID -ItemIds $_.ItemId.ObjectId -ShouldFetchRecurrenceExceptions $true -CustomPropertyNames $CustomPropertyNameList -ShouldBindToItem $true -WarningAction SilentlyContinue
                        if (($logLeftCount % 10 -eq 0) -and ($logLeftCount -gt 0)) {
                            Write-Host -ForegroundColor Cyan "`t [$($logLeftCount)] logs left to examine..."
                        }
                    }
                    # Remove the IPM.Appointment logs as they are already in the CalLogs.
                    $ExceptionLogs = $ExceptionLogs | Where-Object { $_.ItemClass -notlike "IPM.Appointment*" }
                    Write-Host -ForegroundColor Cyan "Found $($ExceptionLogs.count) Exception Logs, adding them into the CalLogs."

                    $script:GCDO = $script:GCDO + $ExceptionLogs | Select-Object *, @{n='OrgTime'; e= { [DateTime]::Parse($_.LogTimestamp.ToString()) } } | Sort-Object OrgTime
                    $LogToExamine = $null
                    $ExceptionLogs = $null
                } else {
                    Write-Host -ForegroundColor Cyan "No Recurring Meetings found, no Exception Logs to collect."
                }
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
