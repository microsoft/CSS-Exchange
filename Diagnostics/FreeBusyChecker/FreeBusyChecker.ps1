# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
<#
.SYNOPSIS

.\FreeBusyChecker.ps1

.DESCRIPTION

This script can be used to validate the Availability configuration of the following Exchange Server Versions:

- Exchange Server
- Exchange Online

Required Permissions:

    - Organization Management
    - Domain Admin

Please make sure that the account used is a member of the Local Administrator group. This should be fulfilled on Exchange Servers by being a member of the Organization Management group. However, if the group membership was adjusted, or in case the script is executed on a non-Exchange system like a management Server, you need to add your account to the Local Administrator group.

How To Run:

This script must be run as Administrator in Exchange Management Shell on an Exchange Server. You can provide no parameters, and the script will just run against Exchange On-Premises and Exchange Online to query for OAuth and DAuth configuration settings. It will compare existing values with standard values and provide details of what may not be correct.
Please take note that though this script may output that a specific setting is not a standard setting, it does not mean that your configurations are incorrect. For example, DNS may be configured with specific mappings that this script cannot evaluate.

To collect information for Exchange Online a connection to Exchange Online must be established before running the script using Connection Prefix "EO".

Example:

PS C:\scripts\FreeBusyChecker> Connect-ExchangeOnline -Prefix EO

.PARAMETER Auth
Allows you to choose the authentication type to validate.
.PARAMETER Org
Allows you to choose the organization type to validate.
.PARAMETER OnPremUser
Specifies the Exchange On Premise User that will be used to test Free Busy Settings.
.PARAMETER OnlineUser
Specifies the Exchange Online User that will be used to test Free Busy Settings.
.PARAMETER OnPremDomain
Specifies the domain for on-premises Organization.
.PARAMETER OnPremEWSUrl
Specifies the EWS (Exchange Web Services) URL for on-premises Exchange Server.
.PARAMETER OnPremLocalDomain
Specifies the local AD domain for the on-premises Organization.
.PARAMETER Help
Show help for this script.

.PARAMETER ExchangeOnlineEwsEndpointUri
Specifies the Exchange Online EWS endpoint. This is the target of the OAuth connectivity test and the expected value
for the Organization Relationship TargetSharingEpr. Defaults to the worldwide endpoint.
.PARAMETER ExchangeOnlineAutoDiscoverEndpointUri
Specifies the Exchange Online AutoDiscover endpoint, without a trailing slash and without the WSSecurity suffix.
The WSSecurity and Hybrid Agent forms are derived from it. Defaults to the worldwide endpoint.
.PARAMETER ExchangeOnlineOwaUri
Specifies the standard values accepted for the Organization Relationship TargetOwAUrl. The first entry has the
Exchange Online domain appended to it, matching the documented standard value. Defaults to the worldwide values.
.PARAMETER AzureADEndpointUri
Specifies the Microsoft Entra authority used to build the expected AuthServer TokenIssuingEndpoint and
AuthMetadataUrl values. Defaults to the worldwide authority.
.PARAMETER AuthServerIssuerUri
Specifies the security token service used to build the expected AuthServer IssuerIdentifier value.
Defaults to the worldwide value.
.PARAMETER FederationTrustTokenIssuerUri
Specifies the expected Federation Trust TokenIssuerEpr. Defaults to the worldwide value.
.PARAMETER FederationTrustMetadataUri
Specifies the expected Federation Trust TokenIssuerMetadataEpr. Defaults to the worldwide value.
.PARAMETER FederationTargetApplicationUri
Specifies the expected Federation Information TargetApplicationUri. Defaults to the worldwide value.
.PARAMETER HybridAgentTargetApplicationUri
Specifies the expected Exchange Online Organization Relationship TargetApplicationUri when the Hybrid Agent is in
use. Defaults to the worldwide value.

Note on the endpoint parameters: all of them default to the current worldwide (public cloud) values, so omitting
them leaves behavior unchanged. They exist because this script compares your live configuration against expected
values. In a sovereign cloud the correct configuration differs, and without overrides a correctly configured
organization is reported as incorrect.

.EXAMPLE
.\FreeBusyChecker.ps1
This cmdlet will run the Free Busy Checker script and Check Availability OAuth and DAuth Configurations both for Exchange On-Premises and Exchange Online.
.EXAMPLE
.\FreeBusyChecker.ps1 -Auth OAuth
This cmdlet will run the Free Busy Checker Script against OAuth Availability Configurations.
.EXAMPLE
.\FreeBusyChecker.ps1 -Auth DAuth
This cmdlet will run the Free Busy Checker Script against DAuth Availability Configurations.
.EXAMPLE
.\FreeBusyChecker.ps1 -Org ExchangeOnline
This cmdlet will run the Free Busy Checker Script for Exchange Online Availability Configurations.
.EXAMPLE
.\FreeBusyChecker.ps1 -Org ExchangeOnPremise
This cmdlet will run the Free Busy Checker Script for Exchange On-Premises OAuth or DAuth Availability Configurations.
.EXAMPLE
.\FreeBusyChecker.ps1 -Org All
This cmdlet will run the Free Busy Checker Script for Exchange On-Premises and Exchange Online OAuth or DAuth Availability Configurations.
.EXAMPLE
.\FreeBusyChecker.ps1 -Org ExchangeOnPremise -Auth OAuth
This cmdlet will run the Free Busy Checker Script for Exchange On-Premises Availability OAuth Configurations
.EXAMPLE
.\FreeBusyChecker.ps1 -ExchangeOnlineEwsEndpointUri "https://<EWS host>/EWS/Exchange.asmx" -ExchangeOnlineAutoDiscoverEndpointUri "https://<AutoDiscover host>/AutoDiscover/AutoDiscover.svc" -AzureADEndpointUri "https://<Entra authority>" -AuthServerIssuerUri "https://<STS host>" -FederationTargetApplicationUri "<Federation application uri>"
This cmdlet will run the Free Busy Checker Script against a sovereign cloud, comparing your configuration against
that cloud's endpoints instead of the worldwide ones. Supply the values for your environment. Omitted parameters
keep their worldwide defaults.
#>

# Exchange On-Premises
#>
#region Properties and Parameters

#Requires -Module ExchangeOnlineManagement
#Requires -Module ActiveDirectory

[CmdletBinding(DefaultParameterSetName = "FreeBusyInfo_OP", SupportsShouldProcess)]

param(
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateSet('DAuth', 'OAuth', 'All', '')]
    [string[]]$Auth,
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateSet('ExchangeOnPremise', 'ExchangeOnline')]
    [string[]]$Org,
    [Parameter(Mandatory = $true, ParameterSetName = "Help")]
    [switch]$Help,
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [string]$OnPremisesUser,
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [string]$OnlineUser,
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [string]$OnPremDomain,
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [string]$OnPremEWSUrl,
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [string]$OnPremLocalDomain,
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateNotNullOrEmpty()]
    [string]$ExchangeOnlineEwsEndpointUri = "https://outlook.office365.com/EWS/Exchange.asmx",
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateNotNullOrEmpty()]
    [string]$ExchangeOnlineAutoDiscoverEndpointUri = "https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc",
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateNotNullOrEmpty()]
    [string[]]$ExchangeOnlineOwaUri = @("http://outlook.com/owa/", "https://outlook.office.com/mail."),
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateNotNullOrEmpty()]
    [string]$AzureADEndpointUri = "https://login.windows.net",
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateNotNullOrEmpty()]
    [string]$AuthServerIssuerUri = "https://sts.windows.net",
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateNotNullOrEmpty()]
    [string]$FederationTrustTokenIssuerUri = "https://login.microsoftonline.com/extSTS.srf",
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateNotNullOrEmpty()]
    [string]$FederationTrustMetadataUri = "https://nexus.microsoftonline-p.com/FederationMetadata/2006-12/FederationMetadata.xml",
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateNotNullOrEmpty()]
    [string]$FederationTargetApplicationUri = "Outlook.com",
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateNotNullOrEmpty()]
    [string]$HybridAgentTargetApplicationUri = "http://outlook.office.com/",
    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly", HelpMessage = "Update only script.")]
    [switch]$ScriptUpdateOnly,
    [switch]$SkipVersionCheck
)
begin {
    . $PSScriptRoot\Functions\OnPremDAuthFunctions.ps1
    . $PSScriptRoot\Functions\OnPremOAuthFunctions.ps1
    . $PSScriptRoot\Functions\ExoDAuthFunctions.ps1
    . $PSScriptRoot\Functions\ExoOAuthFunctions.ps1
    . $PSScriptRoot\Functions\htmlContent.ps1
    . $PSScriptRoot\Functions\hostOutput.ps1
    . $PSScriptRoot\Functions\CommonFunctions.ps1
    . $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
    . $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\GenericScriptUpdate.ps1
} end {
    $Script:countOrgRelIssues = (0)
    $Script:WebServicesVirtualDirectory = $null
    $Script:Server = hostname
    $Script:startingDate = (Get-Date -Format yyyyMMdd_HHmmss)
    $Script:htmlFile = "$PSScriptRoot\FBCheckerOutput_$($Script:startingDate).html"

    #region Expected endpoint values
    # Every value defaults to the worldwide endpoint, so omitting the related parameter keeps the previous behavior.
    # Overrides exist so that an organization in a sovereign cloud is not reported as misconfigured simply because
    # its correct endpoints differ from the worldwide ones.
    SetExpectedEndpointValues -ExchangeOnlineEwsEndpointUri $ExchangeOnlineEwsEndpointUri `
        -ExchangeOnlineAutoDiscoverEndpointUri $ExchangeOnlineAutoDiscoverEndpointUri `
        -ExchangeOnlineOwaUri $ExchangeOnlineOwaUri `
        -AzureADEndpointUri $AzureADEndpointUri `
        -AuthServerIssuerUri $AuthServerIssuerUri `
        -FederationTrustTokenIssuerUri $FederationTrustTokenIssuerUri `
        -FederationTrustMetadataUri $FederationTrustMetadataUri `
        -FederationTargetApplicationUri $FederationTargetApplicationUri `
        -HybridAgentTargetApplicationUri $HybridAgentTargetApplicationUri
    #endregion

    loadingParameters
    #Parameter input

    if (-not $OnlineUser) {
        $Script:UserOnline = Get-RemoteMailbox -ResultSize 1 -WarningAction SilentlyContinue
        $Script:UserOnline = $Script:UserOnline.RemoteRoutingAddress.SmtpAddress
    } else {
        $Script:UserOnline = Get-RemoteMailbox $OnlineUser -ResultSize 1 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        $Script:UserOnline = $Script:UserOnline.RemoteRoutingAddress.SmtpAddress
    }

    $Script:ExchangeOnlineDomain = ($Script:UserOnline -split "@")[1]

    if ($Script:ExchangeOnlineDomain -like "*.mail.onmicrosoft.com") {
        $Script:ExchangeOnlineAltDomain = (($Script:ExchangeOnlineDomain.Split(".")))[0] + ".onmicrosoft.com"
    } else {
        $Script:ExchangeOnlineAltDomain = (($Script:ExchangeOnlineDomain.Split(".")))[0] + ".mail.onmicrosoft.com"
    }
    $Script:temp = "*" + $Script:ExchangeOnlineDomain
    $Script:UserOnPrem = ""
    if (-not  $OnPremisesUser) {
        $Script:UserOnPrem = Get-mailbox -ResultSize 2 -WarningAction SilentlyContinue -Filter 'EmailAddresses -like $temp -and HiddenFromAddressListsEnabled -eq $false' -ErrorAction SilentlyContinue
        if ($Script:UserOnPrem) {
            $Script:UserOnPrem = $Script:UserOnPrem[1].PrimarySmtpAddress.Address
        }
    } else {
        $Script:UserOnPrem = Get-mailbox $OnPremisesUser -WarningAction SilentlyContinue -Filter 'EmailAddresses -like $temp -and HiddenFromAddressListsEnabled -eq $false' -ErrorAction SilentlyContinue
        $Script:UserOnPrem = $Script:UserOnPrem.PrimarySmtpAddress.Address
    }
    $Script:ExchangeOnPremDomain = ($Script:UserOnPrem -split "@")[1]

    if (-not $OnPremEWSUrl) {
        FetchEWSInformation
    } else {
        FetchEWSInformation
        $Script:ExchangeOnPremEWS = ($OnPremEWSUrl)
    }

    if (-not $OnPremDomain) {
        $ADDomain = Get-ADDomain
        $Script:ExchangeOnPremLocalDomain = $ADDomain.forest
    } else {
        $Script:ExchangeOnPremLocalDomain = $OnPremDomain
    }

    $Script:ExchangeOnPremLocalDomain = $ADDomain.forest
    if ([string]::IsNullOrWhitespace($ADDomain)) {
        $Script:ExchangeOnPremLocalDomain = $Script:ExchangeOnPremDomain
    }

    if ($Script:ExchangeOnPremDomain) {
        $Script:FedInfoEOP = Get-federationInformation -DomainName $Script:ExchangeOnPremDomain  -BypassAdditionalDomainValidation -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Select-Object *
    }
    #endregion

    if ($Help) {
        PrintDynamicWidthLine
        ShowHelp
        PrintDynamicWidthLine
        exit
    }
    #region Show Parameters
    $Script:IntraOrgCon = Get-IntraOrganizationConnector -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Where-Object { $_.TargetAddressDomains -contains $Script:ExchangeOnlineDomain } | Select-Object Name, TarGetAddressDomains, DiscoveryEndpoint, Enabled
    ShowParameters
    CheckParameters
    if ($Script:IntraOrgCon.enabled -eq $true) {
        $Auth = hostOutputIntraOrgConEnabled($Auth)
    }
    if ($Script:IntraOrgCon.enabled -eq $false) {
        hostOutputIntraOrgConNotEnabled
    }
    # Free busy Lookup methods
    PrintDynamicWidthLine
    $Script:OrgRel = Get-OrganizationRelationship | Where-Object { ($_.DomainNames -like $Script:ExchangeOnlineDomain) }  -WarningAction SilentlyContinue -ErrorAction SilentlyContinue  | Select-Object Enabled, Identity, DomainNames, FreeBusy*, TarGet*
    $Script:EDiscoveryEndpoint = Get-IntraOrganizationConfiguration -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object OnPremiseDiscoveryEndpoint
    $Script:SPDomainsOnprem = Get-SharingPolicy -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Format-List Domains
    $Script:SPOnprem = Get-SharingPolicy  -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object *

    if ($Org -contains 'ExchangeOnPremise' -or -not $Org) {
        #region DAuth Checks
        if ($Auth -like "DAuth" -or -not $Auth -or $Auth -like "All") {
            Write-Host "  Testing DAuth Configuration"
            OrgRelCheck -OrgRelParameter $Script:OrgRel
            PrintDynamicWidthLine
            FedInfoCheck
            FedTrustCheck
            AutoDVirtualDCheck
            PrintDynamicWidthLine
            EWSVirtualDirectoryCheck
            AvailabilityAddressSpaceCheck
            TestFedTrust
            TestOrgRel
        }
        #endregion
        #region OAuth Check
        if ($Auth -like "OAuth" -or -not $Auth -or $Auth -like "All") {
            Write-Host "  Testing OAuth Configuration"
            IntraOrgConCheck
            PrintDynamicWidthLine
            AuthServerCheck
            PrintDynamicWidthLine
            PartnerApplicationCheck
            PrintDynamicWidthLine
            ApplicationAccountCheck
            PrintDynamicWidthLine
            ManagementRoleAssignmentCheck
            PrintDynamicWidthLine
            AuthConfigCheck
            PrintDynamicWidthLine
            CurrentCertificateThumbprintCheck
            PrintDynamicWidthLine
            AutoDVirtualDCheckOAuth
            PrintDynamicWidthLine
            EWSVirtualDirectoryCheckOAuth
            PrintDynamicWidthLine
            AvailabilityAddressSpaceCheckOAuth
            PrintDynamicWidthLine
            OAuthConnectivityCheck
            PrintDynamicWidthLine
        }
        #endregion
    }
    # EXO Part
    if ($Org -contains 'ExchangeOnline' -or -not $Org) {
        #region ConnectExo
        $Exo = Test-ExchangeOnlineConnection
        if (-not ($Exo)) {
            Write-Host -ForegroundColor Red "`n Please connect to Exchange Online Using the EXO V3 module using EO as connection Prefix to collect Exchange OnLine Free Busy configuration Information."
            Write-Host -ForegroundColor Cyan "`n`n   Example: PS C:\Connect-ExchangeOnline -Prefix EO"
            Write-Host -ForegroundColor Yellow "`n   More Info at:https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps"
            exit
        }
        Write-Host " Connected to Exchange Online."
        $Script:ExoOrgRel = Get-EOOrganizationRelationship | Where-Object { ($_.DomainNames -like $Script:ExchangeOnPremDomain ) } | Select-Object Enabled, Identity, DomainNames, FreeBusy*, TarGet*
        $Script:ExoIntraOrgCon = Get-EOIntraOrganizationConnector | Select-Object Name, TarGetAddressDomains, DiscoveryEndpoint, Enabled
        $Script:tarGetAddressPr1 = ("https://AutoDiscover." + $Script:ExchangeOnPremDomain + "/AutoDiscover/AutoDiscover.svc/WSSecurity")
        $Script:tarGetAddressPr2 = ("https://" + $Script:ExchangeOnPremDomain + "/AutoDiscover/AutoDiscover.svc/WSSecurity")
        exoHeaderHtml

        #endregion

        #region ExoDAuthCheck
        if ($Auth -like "DAuth" -or -not $Auth -or $Auth -like "All") {
            PrintDynamicWidthLine
            Write-Host $TestingExoDAuthConfiguration
            ExoOrgRelCheck
            PrintDynamicWidthLine
            ExoFedOrgIdCheck
            PrintDynamicWidthLine
            ExoTestOrgRelCheck
            SharingPolicyCheck
        }
        #endregion

        #region ExoOauthCheck
        if ($Auth -like "OAuth" -or -not $Auth -or $Auth -like "All") {
            Write-Host $TestingExoOAuthConfiguration
            ExoIntraOrgConCheck
            PrintDynamicWidthLine
            EXOIntraOrgConfigCheck
            PrintDynamicWidthLine
            EXOAuthServerCheck
            PrintDynamicWidthLine
            ExoTestOAuthCheck
            PrintDynamicWidthLine
        }
        #endregion

        Write-Host -ForegroundColor Green $ThatIsAllForTheExchangeOnlineSide

        PrintDynamicWidthLine
    }

    Stop-Transcript
}
