# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
# Use Graph API to get the Bookings mailbox, Staff, Services and Availability.
# This will require the Microsoft.Graph.Bookings and Microsoft.Graph.Authentication modules to be installed.
# (For the first run, the script will install the modules if they are not already installed,
#  for this you need to run the script as an administrator)
#
# .PARAMETER GetMessageTrace
# Get MessageTrace logs for the Bookings mailbox(Past 5 days).
#
# .PARAMETER ExportExcel
# Export all data to Excel.
# This will require the ImportExcel module to be installed.
# (For the first run, the script will install the module if not already installed,
#  for this you need to run the script as an administrator)
#
# .EXAMPLE
# Get-BookingsDiagnosticSummary.ps1 -Identity fooBooking@microsoft.com
#
param
(
    [Parameter(Position=0, Mandatory=$true, HelpMessage="Specifies the Bookings mailbox to be accessed.")]
    [string]$Identity,

    [Parameter(Position=1, Mandatory=$False, HelpMessage="Verify Staff permissions for the Bookings mailbox.")]
    [bool]$Staff=$true,

    [Parameter(Position=2, Mandatory=$False, HelpMessage="Get the Staff Membership Log for the Bookings mailbox.")]
    [bool]$StaffMembershipLog = $true,

    [Parameter(Position=3, Mandatory=$False, HelpMessage="Use Graph API to get the Bookings mailbox, Staff, Services and Availability.")]
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
. $PSScriptRoot\BookingHelpers\BookingStaffLogHelper.ps1
. $PSScriptRoot\BookingHelpers\BookingStaffLogLogic.ps1
. $PSScriptRoot\BookingHelpers\FileSaveHelpers.ps1
. $PSScriptRoot\BookingHelpers\ExcelWrite.ps1
. $PSScriptRoot\CalLogHelpers\Write-DashLineBoxColor.ps1
. $PSScriptRoot\CalLogHelpers\ExcelModuleInstaller.ps1
. $PSScriptRoot\..\Shared\Confirm-Administrator.ps1

# Populating Global Variables and getting general data

# See if it is a Customer Tenant running the cmdlet. (They will not have access to Organization parameter)
$script:MSSupport = [Bool](Get-Help Get-Mailbox -Parameter Organization -ErrorAction SilentlyContinue)
Write-Verbose "MSSupport: $script:MSSupport"

$script:IsAdministrator = Confirm-Administrator

$script:PadCharsMessage = 40
$script:indent = "         "
$script:MessageTrackingDays = 5

CheckEXOConnection

$script:Identity = $Identity
$script:Domain = SplitDomainFromEmail $Identity -errorAction SilentlyContinue
$script:OrgConfig=""
$script:OwaMailboxPolicy = ""
$script:AcceptedDomains = ""
$script:TenantSettings = GetBookingTenantSettings -Domain $script:Domain -ErrorAction SilentlyContinue

$script:BookingMBData = GetBookingMBData -Identity $Identity -ErrorAction SilentlyContinue
if ($StaffMembershipLog -eq $true) {
    $script:BookingStaffMembershipLog = GetStaffMembershipLogs -Identity $Identity
}

$script:BookingStaffMembershipLogArray = GetMembershipLogArray  -Identity $Identity
$script:MessageTrackingLogs = GetMessageTrackingLog -identity $Identity -ErrorAction SilentlyContinue

$script:MBPermissions = Get-MBPermissions -Identity $Identity -ErrorAction SilentlyContinue
$script:MBRecipientPermissions = Get-MBRecipientPermissions -Identity $Identity -ErrorAction SilentlyContinue
$script:StaffData = Get-StaffData | Format-Table

# ===================================================================================================
# Start verifications
# ===================================================================================================
RunTenantTests
RunMBTests -Identity $Identity
if ($StaffMembershipLog -eq $true) {
    RunMBStaffLogValidation
}

if ($MessageTrace -eq $true) {
    RunMessageTrackingLogValidation
}

# Start data collection
if ($ExportToCSV -eq $true) {
    saveDataAsCSV -Identity $Identity
}

if ($ExportToExcel -eq $true) {
    ExcelWrite -identity $Identity
}
