﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
<#
.SYNOPSIS
.\FreeBusyChecker.ps1

.DESCRIPTION
This script can be used to validate the Availability configuration of the following Exchange Server Versions:
- Exchange Server 2013
- Exchange Server 2016
- Exchange Server 2019
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
#>

# Exchange On-Premises
#>
#region Properties and Parameters

#Requires -Module ExchangeOnlineManagement
#Requires -Module ActiveDirectory

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are being used')]
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
    [string]$OnPremLocalDomain
)
begin {
    . $PSScriptRoot\Functions\OnPremDAuthFunctions.ps1
    . $PSScriptRoot\Functions\OnPremOAuthFunctions.ps1
    . $PSScriptRoot\Functions\ExoDAuthFunctions.ps1
    . $PSScriptRoot\Functions\ExoOAuthFunctions.ps1
    . $PSScriptRoot\Functions\htmlContent.ps1
    . $PSScriptRoot\Functions\hostOutput.ps1
    . $PSScriptRoot\Functions\CommonFunctions.ps1
} end {
    $countOrgRelIssues = (0)
    $Script:FedTrust = $null
    $Script:AutoDiscoveryVirtualDirectory = $null
    $Script:OrgRel = $null
    $Script:SPDomainsOnprem = $null
    $AvailabilityAddressSpace = $null
    $Script:WebServicesVirtualDirectory = $null
    $ConsoleWidth = $Host.UI.RawUI.WindowSize.Width
    $BuildVersion = ""
    $Server = hostname
    $LogFile = "$PSScriptRoot\FreeBusyChecker.txt"
    $startingDate = (Get-Date -Format yyyyMMdd_HHmmss)
    $LogFileName = [System.IO.Path]::GetFileNameWithoutExtension($LogFile) + "_" + $startingDate + ([System.IO.Path]::GetExtension($LogFile))
    $htmlFile = "$PSScriptRoot\FBCheckerOutput_$($startingDate).html"

    CheckIfExchangeServer($Server)
    loadingParameters
    #Parameter input

    if (-not $OnlineUser) {
        $UserOnline = Get-RemoteMailbox -ResultSize 1 -WarningAction SilentlyContinue
        $UserOnline = $UserOnline.RemoteRoutingAddress.SmtpAddress
    } else {
        $UserOnline = Get-RemoteMailbox $OnlineUser -ResultSize 1 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        $UserOnline = $UserOnline.RemoteRoutingAddress.SmtpAddress
    }

    $ExchangeOnlineDomain = ($UserOnline -split "@")[1]

    if ($ExchangeOnlineDomain -like "*.mail.onmicrosoft.com") {
        $ExchangeOnlineAltDomain = (($ExchangeOnlineDomain.Split(".")))[0] + ".onmicrosoft.com"
    } else {
        $ExchangeOnlineAltDomain = (($ExchangeOnlineDomain.Split(".")))[0] + ".mail.onmicrosoft.com"
    }
    $temp = "*" + $ExchangeOnlineDomain
    $UserOnPrem = ""
    if (-not  $OnPremisesUser) {
        $UserOnPrem = Get-mailbox -ResultSize 2 -WarningAction SilentlyContinue -Filter 'EmailAddresses -like $temp -and HiddenFromAddressListsEnabled -eq $false' -ErrorAction SilentlyContinue
        if ($UserOnPrem) {
            $UserOnPrem = $UserOnPrem[1].PrimarySmtpAddress.Address
        }
    } else {
        $UserOnPrem = Get-mailbox $OnPremisesUser -WarningAction SilentlyContinue -Filter 'EmailAddresses -like $temp -and HiddenFromAddressListsEnabled -eq $false' -ErrorAction SilentlyContinue
        $UserOnPrem = $UserOnPrem.PrimarySmtpAddress.Address
    }
    $Script:ExchangeOnPremDomain = ($UserOnPrem -split "@")[1]

    if (-not $OnPremEWSUrl) {

        $EWSVirtualDirectory = Get-WebServicesVirtualDirectory -server $Server -ErrorAction SilentlyContinue
        if ($EWSVirtualDirectory.externalURL.AbsoluteUri.Count -gt 1) {
            $Script:ExchangeOnPremEWS = ($EWSVirtualDirectory.externalURL.AbsoluteUri)[0]
        } else {
            $Script:ExchangeOnPremEWS = ($EWSVirtualDirectory.externalURL.AbsoluteUri)
        }
    } else {
        $Script:ExchangeOnPremEWS = ($OnPremEWSUrl)
    }

    if (-not $OnPremDomain) {
        $ADDomain = Get-ADDomain
        $ExchangeOnPremLocalDomain = $ADDomain.forest
    } else {
        $ExchangeOnPremLocalDomain = $OnPremDomain
    }

    $ExchangeOnPremLocalDomain = $ADDomain.forest
    if ([string]::IsNullOrWhitespace($ADDomain)) {
        $ExchangeOnPremLocalDomain = $exchangeOnPremDomain
    }

    if ($ExchangeOnPremDomain) {
        $Script:FedInfoEOP = Get-federationInformation -DomainName $ExchangeOnPremDomain  -BypassAdditionalDomainValidation -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Select-Object *
    }
    #endregion

    if ($Help) {
        PrintDynamicWidthLine
        ShowHelp
        PrintDynamicWidthLine
        exit
    }
    #region Show Parameters
    $IntraOrgCon = Get-IntraOrganizationConnector -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object Name, TarGetAddressDomains, DiscoveryEndpoint, Enabled
    ShowParameters
    CheckParameters
    if ($IntraOrgCon.enabled -Like "True") {
        $Auth = hostOutputIntraOrgConEnabled($Auth)
    }
    if ($IntraOrgCon.enabled -Like "False") {
        hostOutputIntraOrgConNotEnabled
    }
    # Free busy Lookup methods
    PrintDynamicWidthLine
    $OrgRel = Get-OrganizationRelationship | Where-Object { ($_.DomainNames -like $ExchangeOnlineDomain) }  -WarningAction SilentlyContinue -ErrorAction SilentlyContinue  | Select-Object Enabled, Identity, DomainNames, FreeBusy*, TarGet*
    $EDiscoveryEndpoint = Get-IntraOrganizationConfiguration -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object OnPremiseDiscoveryEndpoint
    $SPDomainsOnprem = Get-SharingPolicy -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Format-List Domains
    $SPOnprem = Get-SharingPolicy  -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object *

    if ($Org -contains 'ExchangeOnPremise' -or -not $Org) {
        #region DAuth Checks
        if ($Auth -like "DAuth" -OR -not $Auth -or $Auth -like "All") {
            Write-Host $TestingDAuthConfiguration
            OrgRelCheck -OrgRelParameter $OrgRel
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
            Write-Host $TestingOAuthConfiguration
            # PrintDynamicWidthLine
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
            $AutoDiscoveryVirtualDirectoryOAuth
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
    if ($Org -contains 'ExchangeOnline' -OR -not $Org) {
        #region ConnectExo

        Write-Host -ForegroundColor Green $CollectingExoAvailabilityInformation
        Write-Host " Testing Connection to Exchange Online with EO Prefix."
        $Exo = Test-ExchangeOnlineConnection
        if (-not ($Exo)) {
            Write-Host -ForegroundColor Red "`n Please connect to Exchange Online Using the EXO V3 module using EO as connection Prefix to collect Exchange OnLine Free Busy configuration Information."
            Write-Host -ForegroundColor Cyan "`n`n   Example: PS C:\Connect-ExchangeOnline -Prefix EO"
            Write-Host -ForegroundColor Cyan "`n   Example: PS C:\Connect-ExchangeOnline -Prefix EO -Org ExchangeOnline"
            Write-Host -ForegroundColor Yellow "`n   More Info at:https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps"
            exit
        }
        Write-Host " Connected to Exchange Online."
        $Script:ExoOrgRel = Get-EOOrganizationRelationship | Where-Object { ($_.DomainNames -like $ExchangeOnPremDomain ) } | Select-Object Enabled, Identity, DomainNames, FreeBusy*, TarGet*
        $ExoIntraOrgCon = Get-EOIntraOrganizationConnector | Select-Object Name, TarGetAddressDomains, DiscoveryEndpoint, Enabled
        $tarGetAddressPr1 = ("https://AutoDiscover." + $ExchangeOnPremDomain + "/AutoDiscover/AutoDiscover.svc/WSSecurity")
        $tarGetAddressPr2 = ("https://" + $ExchangeOnPremDomain + "/AutoDiscover/AutoDiscover.svc/WSSecurity")
        exoHeaderHtml

        #endregion

        #region ExoDAuthCheck
        if ($Auth -like "DAuth" -or -not $Auth -or $Auth -like "All") {
            PrintDynamicWidthLine
            Write-Host $TestingExoDAuthConfiguration
            ExoOrgRelCheck
            PrintDynamicWidthLine
            EXOFedOrgIdCheck
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
