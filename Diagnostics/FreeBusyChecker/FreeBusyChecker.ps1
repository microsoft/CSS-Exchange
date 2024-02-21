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

.PARAMETER Auth
Allows you to choose the authentication type to validate.
.PARAMETER Org
Allows you to choose the organization type to validate.
.PARAMETER Pause
Pause after each test is done.
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
This cmdlet will run the Free Busy Checker Script against OAuth Availability Configurations only.
.EXAMPLE
.\FreeBusyChecker.ps1 -Auth DAuth
This cmdlet will run the Free Busy Checker Script against DAuth Availability Configurations only.
.EXAMPLE
.\FreeBusyChecker.ps1 -Org ExchangeOnline
This cmdlet will run the Free Busy Checker Script for Exchange Online Availability Configurations only.
.EXAMPLE
.\FreeBusyChecker.ps1 -Org ExchangeOnPremise
This cmdlet will run the Free Busy Checker Script for Exchange On-Premises OAuth and DAuth Availability Configurations only.
.EXAMPLE
.\FreeBusyChecker.ps1 -Org ExchangeOnPremise -Auth OAuth -Pause
This cmdlet will run the Free Busy Checker Script for Exchange On-Premises Availability OAuth Configurations, pausing after each test is done.
#>

# Exchange On-Premises
#>
#region Properties and Parameters

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are being used')]
[CmdletBinding(DefaultParameterSetName = "FreeBusyInfo_OP", SupportsShouldProcess)]

param(
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateSet('DAuth', 'OAuth', 'All', '')]
    [string[]]$Auth,
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [ValidateSet('ExchangeOnPremise', 'ExchangeOnline')]
    [string[]]$Org,
    [Parameter(Mandatory = $false, ParameterSetName = "Test")]
    [switch]$Pause,
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
} end {
    function InstallRequiredModules {
        try {
            Get-Command -Module ActiveDirectory -ErrorAction Stop >$null
        } catch {
            Import-Module ActiveDirectory
        }

        if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
            Disconnect-ExchangeOnline -Confirm:$False
        }
    }

    InstallRequiredModules
    $countOrgRelIssues = (0)
    $Script:FedTrust = $null
    $Script:AutoDiscoveryVirtualDirectory = $null
    $Script:OrgRel
    $Script:SPDomainsOnprem
    $AvailabilityAddressSpace = $null
    $Script:WebServicesVirtualDirectory = $null
    $ConsoleWidth = $Host.UI.RawUI.WindowSize.Width
    $BuildVersion = ""
    $Server = hostname
    $LogFile = "$PSScriptRoot\FreeBusyChecker.txt"
    $startingDate = (Get-Date -Format yyyyMMdd_HHmmss)
    $LogFileName = [System.IO.Path]::GetFileNameWithoutExtension($LogFile) + "_" + `
        $startingDate + ([System.IO.Path]::GetExtension($LogFile))
    $htmlFile = "$PSScriptRoot\FBCheckerOutput_$($startingDate).html"

    loadingParameters

    #Parameter input

    if (-not $OnlineUser) {
        $UserOnline = Get-RemoteMailbox -ResultSize 1 -WarningAction SilentlyContinue
        $UserOnline = $UserOnline.RemoteRoutingAddress.SmtpAddress
    } else {
        $UserOnline = Get-RemoteMailbox $OnlineUser -ResultSize 1 -WarningAction SilentlyContinue
        $UserOnline = $UserOnline.RemoteRoutingAddress.SmtpAddress
    }

    $ExchangeOnlineDomain = ($UserOnline -split "@")[1]

    if ($ExchangeOnlineDomain -like "*.mail.onmicrosoft.com") {
        $ExchangeOnlineAltDomain = (($ExchangeOnlineDomain.Split(".")))[0] + ".onmicrosoft.com"
    }

    else {
        $ExchangeOnlineAltDomain = (($ExchangeOnlineDomain.Split(".")))[0] + ".mail.onmicrosoft.com"
    }
    $temp = "*" + $ExchangeOnlineDomain
    $UserOnPrem = ""
    if (-not  $OnPremisesUser) {
        $UserOnPrem = Get-mailbox -ResultSize 2 -WarningAction SilentlyContinue -Filter 'EmailAddresses -like $temp -and HiddenFromAddressListsEnabled -eq $false'
        $UserOnPrem = $UserOnPrem[1].PrimarySmtpAddress.Address
    } else {
        $UserOnPrem = Get-mailbox $OnPremisesUser -WarningAction SilentlyContinue -Filter 'EmailAddresses -like $temp -and HiddenFromAddressListsEnabled -eq $false'
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
    $Script:FedInfoEOP = Get-federationInformation -DomainName $ExchangeOnPremDomain  -BypassAdditionalDomainValidation -ErrorAction SilentlyContinue | Select-Object *
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
    if ($IntraOrgCon.enabled -Like "True") {
        hostOutputIntraOrgConEnabled
    }
    if ($IntraOrgCon.enabled -Like "False") {
        hostOutputIntraOrgConNotEnabled
    }
    do {
        #do while not Y or N
        PrintDynamicWidthLine
        Write-Host " Are these values correct? Press Y for YES and N for NO"
        $key = [System.Console]::ReadKey()
        $ParamOK = $key.KeyChar.ToString().ToUpper()
    } while ($ParamOK -ne "Y" -AND $ParamOK -ne "N")
    PrintDynamicWidthLine
    if ($ParamOK -eq "N") {
        Write-Host -ForegroundColor Blue " Please call Script and Specify parameters. Available Parameters:"
        Write-Host -ForegroundColor Yellow " Example: .\FreeBusyChecker.ps1 -OnPremUser user@contoso.com "
        Write-Host " -OnPremUser:  Specifies the Exchange On Premise User that will be used to test Free Busy Settings."
        Write-Host " -OnlineUser: Specifies the Exchange Online User that will be used to test Free Busy Settings."
        Write-Host " -OnPremDomain: Specifies the domain for on-premises Organization."
        Write-Host " -OnPremEWSUrl_ Specifies the EWS (Exchange Web Services) URL for on-premises Exchange Server."
        Write-Host " -OnPremLocalDomain Specifies the local AD domain for the on-premises Organization."
        exit
    }
    # Free busy Lookup methods
    $OrgRel = Get-OrganizationRelationship | Where-Object { ($_.DomainNames -like $ExchangeOnlineDomain) } | Select-Object Enabled, Identity, DomainNames, FreeBusy*, TarGet*
    $EDiscoveryEndpoint = Get-IntraOrganizationConfiguration -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object OnPremiseDiscoveryEndpoint
    $SPDomainsOnprem = Get-SharingPolicy -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Format-List Domains
    $SPOnprem = Get-SharingPolicy  -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object *

    if ($Org -contains 'ExchangeOnPremise' -or -not $Org) {
        #region DAuth Checks
        if ($Auth -like "DAuth" -OR -not $Auth -or $Auth -like "All") {
            Write-Host $TestingDAuthConfiguration
            #  PrintDynamicWidthLine
            OrgRelCheck -OrgRelParameter $OrgRel
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressEnterToCheckFederationInfo
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            FedInfoCheck
            if ($pause) {
                Write-Host $PressEnterToCheckFederationTrust
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            FedTrustCheck

            if ($pause) {
                Write-Host $PressEnterToCheckAutoDiscoverVirtualDirectory
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            AutoDVirtualDCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressEnterToCheckEWSVirtualDirectory
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            EWSVirtualDirectoryCheck
            if ($pause) {
                PrintDynamicWidthLine
                Write-Host $PressEnterToCheckAvailabilityAddressSpace
                $RH = [System.Console]::ReadLine()
            }
            AvailabilityAddressSpaceCheck
            if ($pause) {
                PrintDynamicWidthLine
                Write-Host $PressEnterToTestFederationTrust
                $RH = [System.Console]::ReadLine()
            }
            #need to grab errors and provide alerts in error case
            TestFedTrust
            if ($pause) {
                PrintDynamicWidthLine
                Write-Host $PressEnterToTestOrganizationRelationship
                $RH = [System.Console]::ReadLine()
            }
            TestOrgRel
        }
        #endregion
        #region OAuth Check
        if ($Auth -like "OAuth" -or -not $Auth -or $Auth -like "All") {
            if ($pause) {
                Write-Host $PressEnterToCheckOAuthConfiguration
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            Write-Host $TestingOAuthConfiguration
            # PrintDynamicWidthLine
            IntraOrgConCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressEnterToCheckAuthServer
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            AuthServerCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressEnterToCheckPartnerApplication
                $RH = [System.Console]::ReadLine()
            }
            PartnerApplicationCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressAnyKeyToCheckExchangeOnlineApplicationAccount
                $RH = [System.Console]::ReadLine()
            }
            ApplicationAccountCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressEnterToCheckManagementRoleAssignments
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            ManagementRoleAssignmentCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressEnterToCheckAuthConfiguration
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            AuthConfigCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressEnterToCheckAuthCertificate
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            CurrentCertificateThumbprintCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressAnyKeyToCheckOnPremAutoDiscoverVirtualDirectory
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            AutoDVirtualDCheckOAuth
            $AutoDiscoveryVirtualDirectoryOAuth
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressAnyKeyToCheckOnPremWebServiceVirtualDirectory
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            EWSVirtualDirectoryCheckOAuth
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressAnyKeyToCheckAvailabilityAddressSpace
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            AvailabilityAddressSpaceCheckOAuth
            PrintDynamicWidthLine
            if ($pause -eq "True") {
                Write-Host $PressEnterToTestOAuthConnectivity
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            OAuthConnectivityCheck
            PrintDynamicWidthLine
        }

        #endregion
    }
    # EXO Part
    if ($Org -contains 'ExchangeOnline' -OR -not $Org) {
        #region ConnectExo

        Write-Host -ForegroundColor Green $CollectingExoAvailabilityInformation
        # Check if the ExchangeOnlineManagement module is already installed
        if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
            # If not installed, then install the module
            Write-Host -ForegroundColor Yellow $ExchangeOnlinePowershellModuleMessage
            Install-Module -Name ExchangeOnlineManagement -Force
            PrintDynamicWidthLine
        } else {
            Write-Host $ExchangeOnlineModuleAvailableMessage
            $ExoModuleVersion = Get-Module -Name ExchangeOnlineManagement -ListAvailable | Format-List name, Version
            $ExoModuleVersion
            PrintDynamicWidthLine
        }

        Connect-ExchangeOnline -ShowBanner:$false

        $Script:ExoOrgRel = Get-OrganizationRelationship | Where-Object { ($_.DomainNames -like $ExchangeOnPremDomain ) } | Select-Object Enabled, Identity, DomainNames, FreeBusy*, TarGet*
        $ExoIntraOrgCon = Get-IntraOrganizationConnector | Select-Object Name, TarGetAddressDomains, DiscoveryEndpoint, Enabled
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
            if ($pause) {
                Write-Host $PressEnterToCheckFederationOrgIdentifier
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            EXOFedOrgIdCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressEnterToCheckOrgRelationship
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            ExoTestOrgRelCheck
            if ($pause) {
                PrintDynamicWidthLine
                Write-Host $PressEnterToCheckSharingPolicy
                $RH = [System.Console]::ReadLine()
            }
            SharingPolicyCheck
        }
        #endregion

        #region ExoOauthCheck
        if ($Auth -like "OAuth" -or -not $Auth -or $Auth -like "All") {
            Write-Host $TestingExoOAuthConfiguration

            ExoIntraOrgConCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressEnterToCheckOrgConfiguration
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            EXOIntraOrgConfigCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressEnterToCheckAuthServerAuthorizationDetails
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            EXOAuthServerCheck
            PrintDynamicWidthLine
            if ($pause) {
                Write-Host $PressEnterToTestOAuthConnectivityDetails
                $RH = [System.Console]::ReadLine()
                PrintDynamicWidthLine
            }
            ExoTestOAuthCheck
            PrintDynamicWidthLine
        }
        #endregion

        Disconnect-ExchangeOnline  -Confirm:$False
        Write-Host -ForegroundColor Green $ThatIsAllForTheExchangeOnlineSide

        PrintDynamicWidthLine
    }


    Stop-Transcript
}
