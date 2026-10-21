# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Checks whether an Exchange Online tenant's sharing configuration can be migrated to Microsoft 365 Cross-Tenant Access Policy (XTAP), and generates the cmdlets to do it.
.DESCRIPTION
    Automates https://learn.microsoft.com/exchange/sharing/migrate-to-m365-xtap

    By default the script is an assessment only. It collects Organization Relationships, Availability Address Spaces
    and Sharing Policies, and saves the collected data and analysis to a JSON bundle. It analyzes each item, shows whether it can be
    migrated to XTAP now (and if not, why), and writes:
      - A JSON bundle with collected configuration, analysis rows, and tenant resolution data.
      - CrossTenantAccessPolicyCalendarValidation_Summary.txt with the key results and warnings.

    Optional switches add more:
      - -GenerateCommandScripts creates ready-to-review cmdlet scripts for creating the XTAP policies, disabling the old
        configuration for testing, rolling back, and cleaning up. Nothing is changed by this script itself.
      - -ProcessUsers counts the mailboxes assigned to each Sharing Policy. It queries every mailbox, so it is off by default.

    The script doesn't connect to Exchange Online. Connect with Connect-ExchangeOnline (Organization Management role)
    before running it. To analyze data collected earlier (for example by support), use -ImportData.
    Live runs check for script updates automatically; imported data is analyzed without an update check.
    Results are saved to files and displayed in the console, not returned as a PowerShell results object.
.PARAMETER OutputPath
    Folder where the results folder is created. Defaults to the current directory.
.PARAMETER RunName
    Optional label for this run, used in results folder and file names, JSON metadata, and report headers.
    Each run also has an automatic timestamp. When importing, defaults to the saved run name.
.PARAMETER ImportData
    Reads a previously saved JSON bundle instead of collecting live data. No Exchange Online connection is required.
    Automatically skips the script update check so replay can run without network access.
.PARAMETER SkipTenantResolution
    By default the Microsoft Entra tenant ID of each external domain is looked up from the public
    login.microsoftonline.com OpenID Connect metadata endpoint. Only domain names are sent.
    Use this switch to skip the lookup. The generated scripts then need the tenant IDs filled in.
.PARAMETER EntraLoginHost
    Host used for the tenant ID lookup. Use it for sovereign clouds. Defaults to login.microsoftonline.com.
.PARAMETER GenerateCommandScripts
    Also creates the cmdlet scripts for the eligible items. Without it the script only does the assessment.
.PARAMETER ProcessUsers
    Counts the mailboxes assigned to each Sharing Policy with Get-EXOMailbox -ResultSize Unlimited (or Get-Mailbox if Get-EXOMailbox isn't available).
    This can take a long time in large organizations, so it only runs when requested. The count only matters
    when more than one Sharing Policy is in use, because the generated sharing commands then need security groups.
.PARAMETER Organization
    Collects from a specific tenant by passing -Organization to Get-OrganizationRelationship, Get-AvailabilityAddressSpace,
    Get-SharingPolicy and Get-EXOMailbox/Get-Mailbox, and adds it to the Exchange cmdlets (and Connect-MgGraph -TenantId) in the generated scripts.
    Use it when your session has access to other tenants. The script stops if a cmdlet in the session doesn't support the parameter.
.EXAMPLE
    Connect-ExchangeOnline
    .\CrossTenantAccessPolicyCalendarValidation.ps1
.EXAMPLE
    .\CrossTenantAccessPolicyCalendarValidation.ps1 -GenerateCommandScripts -ProcessUsers
.EXAMPLE
    .\CrossTenantAccessPolicyCalendarValidation.ps1 -RunName BeforeMigration -OutputPath C:\Temp -SkipTenantResolution
.EXAMPLE
    .\CrossTenantAccessPolicyCalendarValidation.ps1 -ImportData .\CrossTenantAccessPolicyCalendarValidation_Data.json
#>

[CmdletBinding(DefaultParameterSetName = "Live")]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [string]$RunName,

    [Parameter(Mandatory = $true, ParameterSetName = "Offline")]
    [ValidateNotNullOrEmpty()]
    [string]$ImportData,

    [Parameter(Mandatory = $false)]
    [switch]$SkipTenantResolution,

    [Parameter(Mandatory = $false)]
    [string]$EntraLoginHost = "login.microsoftonline.com",

    [Parameter(Mandatory = $false)]
    [switch]$GenerateCommandScripts,

    [Parameter(Mandatory = $false, ParameterSetName = "Live")]
    [switch]$ProcessUsers,

    [Parameter(Mandatory = $false, ParameterSetName = "Live")]
    [string]$Organization
)

$BuildVersion = ""

. $PSScriptRoot\XtapHelpers\XtapAnalysisHelpers.ps1
. $PSScriptRoot\XtapHelpers\XtapCollectionHelpers.ps1
. $PSScriptRoot\XtapHelpers\XtapCommandHelpers.ps1
. $PSScriptRoot\XtapHelpers\XtapReportHelpers.ps1
. $PSScriptRoot\XtapHelpers\Invoke-CrossTenantAccessPolicyCalendarValidation.ps1
. $PSScriptRoot\CalendarHelpers\CalendarDiagnosticHelpers.ps1
. $PSScriptRoot\CalLogHelpers\Write-DashLineBoxColor.ps1
. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

if ($PSCmdlet.ParameterSetName -eq "Live" -and (Test-ScriptVersion -AutoUpdate)) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command." -ForegroundColor Yellow
    return
}

Write-Verbose "Script Versions: $BuildVersion"

[void](Invoke-CrossTenantAccessPolicyCalendarValidation @PSBoundParameters)
