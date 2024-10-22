# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Version 0.00.00.1

#
# .DESCRIPTION
# This Exchange Online script runs the Get-BookingsDiagnosticSummary script and returns a summary of basic bookings tests on
# a selected Bookings mailbox. The script will return the Bookings Mailbox, Staff, Services, Custom Questions,
# as well as MessageTrace logs for the past 5 days.
# The script will also return the Staff Membership Log for the Bookings mailbox.
#
# .PARAMETER Identity
# The Bookings mailbox SMTP address to query. (Mandatory)
#
# .PARAMETER Staff
# Verify Staff permissions for the Bookings mailbox.
#
# .PARAMETER StaffMembershipLog
# Get the Staff Membership Log for the Bookings mailbox.
#
# .PARAMETER Graph
# Use Graph API to get the Bookings mailbox, Staff, Services and Availiability.
# This will require the Microsoft.Graph.Bookings and Microsoft.Graph.Authentication modules to be installed.
# (For the rist run, the script will install the modules if they are not already installed,
#  for this you need to run the script as an administrator)
#
# .PARAMETER GetMessageTrace
# Get MessageTrace logs for the Bookings mailbox(Past 5 days).
#
# .PARAMETER ExportExcel
# Export all data to Excel.
# This will require the ImportExcel module to be installed.
# (For the rist run, the script will install the module if not already installed,
#  for this you need to run the script as an administrator)
#
# .EXAMPLE
# Get-BookingsDiagnosticSummary.ps1 -Identity fooBooking@microsoft.com
#
param
(
    [Parameter(Position=0, Mandatory=$False, HelpMessage="Specifies the Bookings mailbox to be accessed.")]
    [ValidateNotNullOrEmpty()]
    [string]$identity,

    [Parameter(Position=1, Mandatory=$False, HelpMessage="Verify Staff permissions for the Bookings mailbox.")]
    [bool]$Staff=$true,

    [Parameter(Position=2, Mandatory=$False, HelpMessage="Get the Staff Membership Log for the Bookings mailbox.")]
    [bool]$StaffMembershipLog = $true,

    [Parameter(Position=3, Mandatory=$False, HelpMessage="Use Graph API to get the Bookings mailbox, Staff, Services and Availiability.")]
    [bool]$Graph = $true,

    [Parameter(Position=4, Mandatory=$False, HelpMessage="Get MessageTrace logs for the Bookings mailbox(Past 5 days).")]
    [bool]$MessageTrace = $true,

    [Parameter(Position=5, Mandatory=$False, HelpMessage="Export all data to CSV.")]
    [bool]$ExportToCSV = $true,

    [Parameter(Position=6, Mandatory=$False, HelpMessage="Export all data to Excel.")]
    [bool]$ExportToExcel = $true

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

CheckEXOConnection

$script:Domain = SplitDomainFromEmail $identity -errorAction SilentlyContinue
$script:OrgConfig=""
$script:OWAMBPolicy = ""
$script:AcceptedDomains = ""
$script:TenantSettings = GetBookingTenantSettings -Domain $script:Domain -ErrorAction SilentlyContinue

$script:bookingMBData = GetBookingMBData -Identity $identity -ErrorAction SilentlyContinue
if ($StaffMembershipLog -eq $true) {
    $script:BookingStaffMembershipLog = GetStaffMembershipLogs -Identity $identity
}

$script:BookingStaffMembershipLogArray = GetMembershipLogArray  -Identity $identity
$script:MessageTrackingLogs = GetMessageTrackingLog -identity $identity -ErrorAction SilentlyContinue

$script:MBPermissions = Get-MBPermissions -Identity $identity -ErrorAction SilentlyContinue
$script:MBRecipientPermissions = Get-MBRecipientPermissions -Identity $identity -ErrorAction SilentlyContinue
$script:StaffData = Get-StaffData | Format-Table

#start verifications
RunTenantTests
RunMBTests
if ($StaffMembershipLog -eq $true) {
    RunMBStaffLogValidation
}

if ($MessageTrace -eq $true) {
    RunMessageTrackingLogValidation
}

#start data collection
if ($ExportToCSV -eq $true) {
    saveDataAsCSV -Identity $identity
}

if ($ExportToExcel -eq $true) {
    ExcelWrite -identity $identity
}
