<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

# Version 0.00.00.1

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
# Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -TrackingLogs -Exceptions
#
param
(
    [Parameter(Position=0, Mandatory=$False, HelpMessage="Specifies the Bookings mailbox to be accessed.")]
    [ValidateNotNullOrEmpty()]
    [string]$identity,

    [Parameter(Position=1, Mandatory=$False, HelpMessage="Verify Staff permissions for the Bookings mailbox.")]
    [switch]$Staff,

    [Parameter(Position=2, Mandatory=$False, HelpMessage="Get the Staff Membership Log for the Bookings mailbox.")]
    [switch]$StaffMembershipLog,

    [Parameter(Position=3, Mandatory=$False, HelpMessage="Use Graph API to get the Bookings mailbox, Staff, Services and Availiability.")]
    [switch]$Graph,

    [Parameter(Position=4, Mandatory=$False, HelpMessage="Get MessageTrace logs for the Bookings mailbox(Past 5 days).")]
    [switch]$GetMessageTrace,

    [Parameter(Position=5, Mandatory=$False, HelpMessage="Export all data to Excel.")]
    [switch]$ExportExcel

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
# Helper scripts
# ===================================================================================================
. $PSScriptRoot\BookingHelpers\BookingGenericFunctions.ps1
. $PSScriptRoot\BookingHelpers\BookingTenantSettingsHelper.ps1
. $PSScriptRoot\BookingHelpers\BookingTenantSettingsLogic.ps1
. $PSScriptRoot\BookingHelpers\BookingMBHelpers.ps1
. $PSScriptRoot\BookingHelpers\BookingMBLogic.ps1
. $PSScriptRoot\BookingHelpers\BookingMessageTrackingLogHelper.ps1
. $PSScriptRoot\BookingHelpers\BookingMessageTrackingLogLogic.ps1
. $PSScriptRoot\BookingHelpers\BookingStaffHelpers.ps1
. $PSScriptRoot\BookingHelpers\BookingStaffLogic.ps1
. $PSScriptRoot\BookingHelpers\bookingStaffLogHelper.ps1
. $PSScriptRoot\BookingHelpers\bookingStaffLogLogic.ps1
. $PSScriptRoot\BookingHelpers\fileSaveHelpers.ps1
. $PSScriptRoot\BookingHelpers\ExcelWrite.ps1
. $PSScriptRoot\CalLogHelpers\Write-DashLineBoxColor.ps1
. $PSScriptRoot\CalLogHelpers\ExcelModuleInstaller.ps1




# Populating Global Variables and getting general data

# See if it is a Customer Tenant running the cmdlet. (They will not have access to Organization parameter)
$script:MSSupport = [Bool](Get-Help Get-Mailbox -Parameter Organization -ErrorAction SilentlyContinue)
Write-Verbose "MSSupport: $script:MSSupport"

$script:PadCharsMessage = 40
$script:indent = "         "
$script:MessageTrackingDays = 5

IsGetMailboxAvailable

$script:Domain = SplitDomainFromEmail $identity -errorAction SilentlyContinue
$script:OrgConfig=""
$script:OWAMBPolicy = ""
$script:AcceptedDomains = ""
$script:TenantSettings = Get-BookingTenantSettings -Domain $script:Domain -ErrorAction SilentlyContinue

#removed BMB variable, is unused
#$script:BMB =""
$script:bookingMBData = Get-BookingMBData -Identity $identity -ErrorAction SilentlyContinue
$script:BookingStaffMembershipLog = GetStaffMembershipLogs -Identity $identity
$script:BookingStaffMembershipLogArray = GetMembershipLogArray  -Identity $identity
$script:MessageTrackingLogs = Get-MessageTrackingLogs -identity $identity -ErrorAction SilentlyContinue

$script:MBPermissions = Get-MBPermissions -Identity $identity -ErrorAction SilentlyContinue
$script:MBRecipientPermissions = Get-MBRecipientPermissions -Identity $identity -ErrorAction SilentlyContinue
$script:StaffData = Get-StaffData | Format-Table




$script:TenantSettings
$script:bookingMBData
$script:StaffData
$script:MessageTrackingLogs
#$script:BMB

#start verifications
RunTenantTests
RunMBTests
RunMBStaffLogChecks
RunMessageTrackingLogTests

saveDataAsCSV -Identity $identity

ExcelWrite -identity $identity









