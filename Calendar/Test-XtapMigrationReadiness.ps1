# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Checks whether an Exchange Online tenant's sharing configuration can be migrated to Microsoft 365 Cross-Tenant Access Policy (XTAP), and generates the cmdlets to do it.
.DESCRIPTION
    Automates https://learn.microsoft.com/exchange/sharing/migrate-to-m365-xtap

    By default the script is an assessment only. It collects Organization Relationships, Availability Address Spaces
    and Sharing Policies, and saves the raw output to CLIXML files. It then analyzes each item, shows whether it can be
    migrated to XTAP now (and if not, why), and writes:
      - Wide CSV files with one row per item for filtering.
      - XtapReadiness_Summary.txt with the key results and warnings.

    Optional switches add more:
      - -GenerateCommandScripts creates ready-to-review cmdlet scripts for creating the XTAP policies, disabling the old
        configuration for testing, rolling back, and cleaning up. Nothing is changed by this script itself.
      - -ProcessUsers counts the mailboxes assigned to each Sharing Policy. It queries every mailbox, so it is off by default.

    The script doesn't connect to Exchange Online. Connect with Connect-ExchangeOnline (Organization Management role)
    before running it. To analyze files that were collected earlier (for example by support), use the offline parameters.
.PARAMETER OutputPath
    Folder where the results folder is created. Defaults to the current directory.
.PARAMETER CustomerName
    Optional name used in the results folder and file names.
.PARAMETER OrganizationRelationshipXml
    Offline analysis. CLIXML file from Get-OrganizationRelationship.
.PARAMETER AvailabilityAddressSpaceXml
    Offline analysis. CLIXML file from Get-AvailabilityAddressSpace.
.PARAMETER SharingPolicyXml
    Offline analysis. CLIXML file from Get-SharingPolicy.
.PARAMETER SharingPolicyAssignmentXml
    Offline analysis. Optional CLIXML file with the mailbox count per Sharing Policy.
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
.PARAMETER PassThru
    Returns an object with the results folder path and the analysis rows.
.PARAMETER SkipVersionCheck
    Skips the automatic update check.
.EXAMPLE
    Connect-ExchangeOnline
    .\Test-XtapMigrationReadiness.ps1
.EXAMPLE
    .\Test-XtapMigrationReadiness.ps1 -GenerateCommandScripts -ProcessUsers
.EXAMPLE
    .\Test-XtapMigrationReadiness.ps1 -CustomerName Contoso -OutputPath C:\Temp -SkipTenantResolution
.EXAMPLE
    .\Test-XtapMigrationReadiness.ps1 -OrganizationRelationshipXml .\OrgRel.xml -AvailabilityAddressSpaceXml .\AAS.xml -SharingPolicyXml .\SharingPolicy.xml
#>

[CmdletBinding(DefaultParameterSetName = "Live")]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [string]$CustomerName,

    [Parameter(Mandatory = $true, ParameterSetName = "Offline")]
    [string]$OrganizationRelationshipXml,

    [Parameter(Mandatory = $true, ParameterSetName = "Offline")]
    [string]$AvailabilityAddressSpaceXml,

    [Parameter(Mandatory = $true, ParameterSetName = "Offline")]
    [string]$SharingPolicyXml,

    [Parameter(Mandatory = $false, ParameterSetName = "Offline")]
    [string]$SharingPolicyAssignmentXml,

    [Parameter(Mandatory = $false)]
    [switch]$SkipTenantResolution,

    [Parameter(Mandatory = $false)]
    [string]$EntraLoginHost = "login.microsoftonline.com",

    [Parameter(Mandatory = $false)]
    [switch]$GenerateCommandScripts,

    [Parameter(Mandatory = $false, ParameterSetName = "Live")]
    [switch]$ProcessUsers,

    [Parameter(Mandatory = $false, ParameterSetName = "Live")]
    [string]$Organization,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru,

    [Parameter(Mandatory = $false)]
    [switch]$SkipVersionCheck
)

$BuildVersion = ""

. $PSScriptRoot\XtapHelpers\XtapAnalysisHelpers.ps1
. $PSScriptRoot\XtapHelpers\XtapCollectionHelpers.ps1
. $PSScriptRoot\XtapHelpers\XtapCommandHelpers.ps1
. $PSScriptRoot\XtapHelpers\XtapReportHelpers.ps1
. $PSScriptRoot\XtapHelpers\Invoke-XtapMigrationReadiness.ps1
. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

if (-not $SkipVersionCheck -and (Test-ScriptVersion -AutoUpdate)) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command." -ForegroundColor Yellow
    return
}

Write-Verbose "Script Versions: $BuildVersion"

[void]$PSBoundParameters.Remove("SkipVersionCheck")
Invoke-XtapMigrationReadiness @PSBoundParameters
