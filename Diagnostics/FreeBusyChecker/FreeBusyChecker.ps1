# Copyright (c) Microsoft Corporation.
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
    - Domain Admins (only necessary for the DCCoreRatio parameter)
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
    [switch]$Help
)

function ShowHelp {
    $bar
    Write-Host -ForegroundColor Yellow "`n  Valid Input Option Parameters!"
    Write-Host -ForegroundColor White "`n  Parameter: Auth"
    Write-Host -ForegroundColor White "   Options  : DAuth; OAUth"
    Write-Host  "    DAuth             : DAuth Authentication"
    Write-Host  "    OAuth             : OAuth Authentication"
    Write-Host  "    Default Value     : No switch input means the script will collect both DAuth and OAuth Availability Configuration Detail"
    Write-Host -ForegroundColor White "`n  Parameter: Org"
    Write-Host -ForegroundColor White "   Options  : ExchangeOnPremise; Exchange Online"
    Write-Host  "    ExchangeOnPremise : Use ExchangeOnPremise parameter to collect Availability information in the Exchange On Premise Tenant"
    Write-Host  "    ExchangeOnline    : Use Exchange Online parameter to collect Availability information in the Exchange Online Tenant"
    Write-Host  "    Default Value     : No switch input means the script will collect both Exchange On Premise and Exchange OnlineAvailability configuration Detail"
    Write-Host -ForegroundColor White "`n  Parameter: Pause"
    Write-Host  "                 : Use the Pause parameter to use this script pausing after each test done."
    Write-Host -ForegroundColor White "`n  Parameter: Help"
    Write-Host  "                 : Use the Help parameter to use display valid parameter Options. `n`n"
}

if ($Help) {
    Write-Host $bar
    ShowHelp
    $bar
    exit
}

Add-PSSnapin microsoft.exchange.management.powershell.Snapin
Import-Module ActiveDirectory

#Install-Module -Name ExchangeOnlineManagement

# Check if the ExchangeOnlineManagement module is already installed
if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    # If installed Disconnect
    Disconnect-ExchangeOnline -Confirm:$False
}
#DisConnect-ExchangeOnline -Confirm:$False

[System.Console]::Clear()
$countOrgRelIssues = (0)
$Script:FedTrust = $null
$Script:AutoDiscoveryVirtualDirectory = $null
$Script:OrgRel
$Script:SPDomainsOnprem
$AvailabilityAddressSpace = $null
$Script:WebServicesVirtualDirectory = $null
$ConsoleWidth = $Host.UI.RawUI.WindowSize.Width

$bar = " =================================================================================================================="

$LogFile = "$PSScriptRoot\FreeBusyChecker.txt"
$startingDate = (Get-Date -Format yyyyMMdd_HHmmss)
$LogFileName = [System.IO.Path]::GetFileNameWithoutExtension($LogFile) + "_" + `
    $startingDate + ([System.IO.Path]::GetExtension($LogFile))
$htmlFile = "$PSScriptRoot\FBCheckerOutput_$($startingDate).html"
Write-Host " `n`n "
Start-Transcript -Path $LogFileName -Append
Write-Host $bar
Write-Host -ForegroundColor Green " `n  Free Busy Configuration Information Checker `n "
Write-Host -ForegroundColor White "   Version 1 `n "
Write-Host -ForegroundColor Green "  Loading Parameters..... `n "
#Parameter input
$UserOnline = Get-RemoteMailbox -ResultSize 1 -WarningAction SilentlyContinue
$UserOnline = $UserOnline.RemoteRoutingAddress.SmtpAddress
$ExchangeOnlineDomain = ($UserOnline -split "@")[1]

if ($ExchangeOnlineDomain -like "*.mail.onmicrosoft.com") {
    $ExchangeOnlineAltDomain = (($ExchangeOnlineDomain.Split(".")))[0] + ".onmicrosoft.com"
}

else {
    $ExchangeOnlineAltDomain = (($ExchangeOnlineDomain.Split(".")))[0] + ".mail.onmicrosoft.com"
}
# $UserOnPrem = Get-mailbox -ResultSize 1 -WarningAction SilentlyContinue | Where-Object { ($_.EmailAddresses -like "*" + $ExchangeOnlineDomain ) }
$temp = "*" + $ExchangeOnlineDomain
$UserOnPrem = ""

$UserOnPrem = Get-mailbox -ResultSize 2 -WarningAction SilentlyContinue -Filter 'EmailAddresses -like $temp -and HiddenFromAddressListsEnabled -eq $false'
$UserOnPrem = $UserOnPrem[1].PrimarySmtpAddress.Address
$Script:ExchangeOnPremDomain = ($UserOnPrem -split "@")[1]
$EWSVirtualDirectory = Get-WebServicesVirtualDirectory -ErrorAction SilentlyContinue

if ($EWSVirtualDirectory.externalURL.AbsoluteUri.Count -gt 1) {
    $Script:ExchangeOnPremEWS = ($EWSVirtualDirectory.externalURL.AbsoluteUri)[0]
}

else {
    $Script:ExchangeOnPremEWS = ($EWSVirtualDirectory.externalURL.AbsoluteUri)
}

$ADDomain = Get-ADDomain
$ExchangeOnPremLocalDomain = $ADDomain.forest

if ([string]::IsNullOrWhitespace($ADDomain)) {
    $ExchangeOnPremLocalDomain = $exchangeOnPremDomain
}
$Script:FedInfoEOP = Get-federationInformation -DomainName $ExchangeOnPremDomain  -BypassAdditionalDomainValidation -ErrorAction SilentlyContinue | Select-Object *
#endregion

#region Edit Parameters

function UserOnlineCheck {
    Write-Host -ForegroundColor Green "Online Mailbox: $UserOnline"
    Write-Host "Press the Enter key if OK or type an Exchange Online Email address and press the Enter key"
    $UserOnlineCheck = [System.Console]::ReadLine()
    if (![string]::IsNullOrWhitespace($UserOnlineCheck)) {
        $script:UserOnline = $UserOnlineCheck
    }
}

function ExchangeOnlineDomainCheck {
    #$ExchangeOnlineDomain
    Write-Host -ForegroundColor Green " Exchange Online Domain: $ExchangeOnlineDomain"
    Write-Host " Press Enter if OK or type in the Exchange Online Domain and press the Enter key."
    $ExchangeOnlineDomainCheck = [System.Console]::ReadLine()
    if (![string]::IsNullOrWhitespace($ExchangeOnlineDomainCheck)) {
        $script:ExchangeOnlineDomain = $ExchangeOnlineDomainCheck
    }
}

function UserOnPremCheck {
    Write-Host -ForegroundColor Green " On Premises Hybrid Mailbox: $UserOnPrem"
    Write-Host " Press Enter if OK or type in an Exchange OnPremises Hybrid email address and press the Enter key."
    $UserOnPremCheck = [System.Console]::ReadLine()
    if (![string]::IsNullOrWhitespace($UserOnPremCheck)) {
        $script:UserOnPrem = $UserOnPremCheck
    }
}

function ExchangeOnPremDomainCheck {
    #$exchangeOnPremDomain
    Write-Host -ForegroundColor Green " On Premises Mail Domain: $exchangeOnPremDomain"
    Write-Host " Press Enter if OK or type in the Exchange On Premises Mail Domain and press the Enter key."
    $exchangeOnPremDomainCheck = [System.Console]::ReadLine()
    if (![string]::IsNullOrWhitespace($exchangeOnPremDomainCheck)) {
        $script:exchangeOnPremDomain = $exchangeOnPremDomainCheck
    }
}

function ExchangeOnPremEWSCheck {
    Write-Host -ForegroundColor Green " On Premises EWS External URL: $exchangeOnPremEWS"
    Write-Host " Press Enter if OK or type in the Exchange On Premises EWS URL and press the Enter key."
    $exchangeOnPremEWSCheck = [System.Console]::ReadLine()
    if (![string]::IsNullOrWhitespace($exchangeOnPremEWSCheck)) {
        $exchangeOnPremEWS = $exchangeOnPremEWSCheck
    }
}

function ExchangeOnPremLocalDomainCheck {
    Write-Host -ForegroundColor Green " On Premises Root Domain: $exchangeOnPremLocalDomain  "
    Write-Host " Press Enter if OK or type in the Exchange On Premises Root Domain."
    $exchangeOnPremLocalDomain = [System.Console]::ReadLine()
    if ([string]::IsNullOrWhitespace($ADDomain)) {
        $exchangeOnPremLocalDomain = $exchangeOnPremDomain
    }
    if ([string]::IsNullOrWhitespace($exchangeOnPremLocalDomain)) {
        $exchangeOnPremLocalDomain = $exchangeOnPremLocalDomainCheck
    }
}

#endregion

#region Show Parameters
function ShowParameters {
    Write-Host $bar
    Write-Host -ForegroundColor Green "  Loading modules for AD, Exchange"
    Write-Host $bar
    Write-Host   "  Color Scheme"
    Write-Host $bar
    Write-Host -ForegroundColor Red "  Look out for Red!"
    Write-Host -ForegroundColor Yellow "  Yellow - Example information or Links"
    Write-Host -ForegroundColor Green "  Green - In Summary Sections it means OK. Anywhere else it's just a visual aid."
    Write-Host $bar
    Write-Host   "  Parameters:"
    Write-Host $bar
    Write-Host  -ForegroundColor White " Log File Path:"
    Write-Host -ForegroundColor Green "  $PSScriptRoot\$LogFile"
    Write-Host  -ForegroundColor White " Office 365 Domain:"
    Write-Host -ForegroundColor Green "  $ExchangeOnlineDomain"
    Write-Host  -ForegroundColor White " AD root Domain"
    Write-Host -ForegroundColor Green "  $exchangeOnPremLocalDomain"
    Write-Host -ForegroundColor White " Exchange On Premises Domain:  "
    Write-Host -ForegroundColor Green "  $exchangeOnPremDomain"
    Write-Host -ForegroundColor White " Exchange On Premises External EWS url:"
    Write-Host -ForegroundColor Green "  $exchangeOnPremEWS"
    Write-Host -ForegroundColor White " On Premises Hybrid Mailbox:"
    Write-Host -ForegroundColor Green "  $UserOnPrem"
    Write-Host -ForegroundColor White " Exchange Online Mailbox:"
    Write-Host -ForegroundColor Green "  $UserOnline"

    $script:html = "<!DOCTYPE html>
 <!DOCTYPE html>
<html>
<head>
  <title>Hybrid Free Busy Configuration Checker</title>
  <style>
    body {
      font-family: Arial;
      background-color: white;
    }
    table, th {
    max-width: 95%;
    margin-left: 2%;
    margin-right: 2%;
      border: 1px solid black;
      border-collapse: collapse;
      padding: 5px;
      font-family: Courier;
      background-color: white;
      table-layout: fixed;
       font-family: Arial;
    }
    td {
      border: 1px solid black;
      border-collapse: collapse;
      padding: 5px;
      font-family: Arial;
      background-color: white;
      width: 50%;
      max-width: 50%;
      word-wrap: break-word;
    }
    th {
      background-color: blue;
      text-align: left;
       font-family: Arial;
    }
    .green { color: green; }
    .red { color: red; }
    .yellow { color: yellow; }
    .white { color: white; }
    .black { color: black; }
    .orange { color: orange; }
    .Black {
      font-weight: 500;
    }
     p {
      font-weight : 548;
    }
    h1 {
      color: #00a2ed;
      padding-left: 2%;
    }
    h2 {
      color: #00a2ed;
      padding-left: 2%;
    }
    h3 {
      color: #00a2ed;
      padding-left: 2%;
    }
    ul {
      padding-left: 8%;
    }

   .microsoft {
    background-color: #f25022;
    box-shadow:
        28px 0 0 0 #7fba00,
        0 28px 0 0 #00a4ef,
        28px 28px 0 0 #ffb900;
    height: 25px;
    width: 25px;
    margin-top: 1%;
    margin-right: 1%;
}
  </style>
</head>
<body>

            <div class='Black' style='display: -webkit-box;margin-left: 2%;'>
            <div class='microsoft'></div>
            <h1 style='padding-left: 2%;'>Microsoft CSS - Exchange Hybrid Free Busy Configuration Checker</h1></div>


	       <div class='Black' style = 'padding-left: 0%;'>
              <h2><b>Parameters:</b></h2>
              <ul>
                <li>
                  <p>Log File Path:</p>
                  <span style='color:green; font-weight:500; padding-left:2%;'>$PSScriptRoot\$LogFile</span>
                </li>
                <li>
                  <p>Office 365 Domain:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$ExchangeOnlineDomain</span>
                </li>
                <li>
                  <p>AD root Domain:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$exchangeOnPremLocalDomain</span>
                </li>
                <li>
                  <p>Exchange On Premises Domain:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$exchangeOnPremDomain</span>
                </li>
                <li>
                  <p>Exchange On Premises External EWS url:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$exchangeOnPremEWS</span>
                </li>
                <li>
                  <p>On Premises Hybrid Mailbox:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$UserOnPrem</span>
                </li>
                <li>
                  <p>Exchange Online Mailbox:</p>
                  <span style='color:green; font-weight:500; padding-left:2%'>$UserOnline</span>
                </li>
              </ul>
            </div>


            <div class='Black'  style = 'padding-left: 0%;'><h2Configuration:</h2></div>

            <p style='margin-left:2%;'>TLS 1.2 should be Enabled in order for Hybrid Free Busy to work. To confirm TLS Settings please Run the HealthChecker Script</p>
              <ul>
                <li><a href='https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/'>Microsoft Exchange Health Checker Script</a></li>
              </ul>


            <h3>Useful Links</h3>
              <ul>
                <li><a href='https://techcommunity.microsoft.com/t5/exchange-team-blog/demystifying-hybrid-free-busy-finding-errors-and-troubleshooting/ba-p/607727'>Demystifying Hybrid Free Busy: Finding Errors and Troubleshooting</a></li>
                <li><a href='https://support.microsoft.com/en-us/topic/how-to-troubleshoot-free-busy-issues-in-a-hybrid-deployment-of-on-premises-exchange-Server-and-exchange-online-in-office-365-ae03e199-b439-a84f-8db6-11bc0d7fbdf0'>How to Troubleshoot Free Busy Issues in a Hybrid Deployment of On-Premises Exchange Server and Exchange Online in Office 365</a></li>
                <li><a href='https://techcommunity.microsoft.com/t5/exchange-team-blog/the-hybrid-mesh/ba-p/605910'>The Hybrid Mesh</a></li>
                <li><a href='https://techcommunity.microsoft.com/t5/exchange-team-blog/how-to-address-federation-trust-issues-in-hybrid-configuration/ba-p/1144285'>How to Address Federation Trust Issues in Hybrid Configuration</a></li>
                <li><a href='https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?redirectSourcePath=%252farticle%252fOffice-365-URLs-and-IP-address-ranges-8548a211-3fe7-47cb-abb1-355ea5aa88a2&view=o365-worldwide'>Office 365 URLs and IP Address Ranges</a></li>
                <li><a href='https://techcommunity.microsoft.com/legacyfs/online/media/2019/01/FB_Errors.FixesV6.pdf'>Free Busy Errors and Fixes</a></li>
              </ul>

              "

    $html | Out-File -FilePath $htmlFile
}
#}
#endregion

#region DAuth Functions

function OrgRelCheck {
    Write-Host $bar
    Write-Host -ForegroundColor Green " Get-OrganizationRelationship  | Where{($_.DomainNames -like $ExchangeOnlineDomain )} | Select Identity,DomainNames,FreeBusy*,TarGet*,Enabled, ArchiveAccessEnabled"
    Write-Host $bar

    $OrgRel
    Write-Host $bar
    Write-Host  -ForegroundColor Green " Summary - Get-OrganizationRelationship"
    Write-Host $bar
    #$ExchangeOnlineDomain
    Write-Host  -ForegroundColor White   " Domain Names:"
    if ($OrgRel.DomainNames -like $ExchangeOnlineDomain) {
        Write-Host -ForegroundColor Green "  Domain Names Include the $ExchangeOnlineDomain Domain"
        $tdDomainNames = "Domain Names Include the $ExchangeOnlineDomain Domain"
        $tdDomainNamesColor = "green"
        $tdDomainNamesFL = $tdDomainNames | Format-List
    } else {
        Write-Host -ForegroundColor Red "  Domain Names do Not Include the $ExchangeOnlineDomain Domain"
        $tdDomainNames = "Domain Names do Not Include the $ExchangeOnlineDomain Domain"
        $tdDomainNamesColor = "Red"
    }
    #FreeBusyAccessEnabled
    Write-Host -ForegroundColor White   " FreeBusyAccessEnabled:"
    if ($OrgRel.FreeBusyAccessEnabled -like "True" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessEnabled is set to True"
        $tdFBAccessEnabled = "FreeBusyAccessEnabled is set to True"
        $tdFBAccessEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  FreeBusyAccessEnabled : False"
        $tdFBAccessEnabled = "FreeBusyAccessEnabled is set to False"
        $tdFBAccessEnabledColor = "red"
        $countOrgRelIssues++
    }
    #FreeBusyAccessLevel
    Write-Host -ForegroundColor White   " FreeBusyAccessLevel:"
    if ($OrgRel.FreeBusyAccessLevel -like "AvailabilityOnly" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessLevel is set to AvailabilityOnly"
        $tdFBAccessLevel = "FreeBusyAccessLevel is set to AvailabilityOnly"
        $tdFBAccessLevelColor = "green"
    }
    if ($OrgRel.FreeBusyAccessLevel -like "LimitedDetails" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessLevel is set to LimitedDetails"
        $tdFBAccessLevel = "FreeBusyAccessLevel is set to  LimitedDetails"
        $tdFBAccessLevelColor = "green"
    }
    if ($OrgRel.FreeBusyAccessLevel -ne "LimitedDetails" -AND $OrgRel.FreeBusyAccessLevel -ne "AvailabilityOnly" ) {
        Write-Host -ForegroundColor Red "  FreeBusyAccessEnabled : False"
        $tdFBAccessLevel = "FreeBusyAccessEnabled : False"
        $tdFBAccessLevelColor = "Red"
        $countOrgRelIssues++
    }
    #TarGetApplicationUri
    Write-Host -ForegroundColor White   " TarGetApplicationUri:"
    if ($OrgRel.TarGetApplicationUri -like "Outlook.com" ) {
        Write-Host -ForegroundColor Green "  TarGetApplicationUri is Outlook.com"
        $tdTarGetApplicationUri = "TarGetApplicationUri is Outlook.com"
        $tdTarGetApplicationUriColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  TarGetApplicationUri should be Outlook.com"
        $tdTarGetApplicationUri = "TarGetApplicationUri should be Outlook.com"
        $tdTarGetApplicationUriColor = "red"
        $countOrgRelIssues++
    }
    #TarGetOwAUrl
    Write-Host -ForegroundColor White   " TarGetOwAUrl:"
    if ($OrgRel.TarGetOwAUrl -like "https://outlook.com/owa/$ExchangeOnlineDomain" -or $OrgRel.TarGetOwAUrl -like $Null) {
        if ($OrgRel.TarGetOwAUrl -like "http://outlook.com/owa/$ExchangeOnlineDomain") {
            Write-Host -ForegroundColor Green "  TarGetOwAUrl is http://outlook.com/owa/$ExchangeOnlineDomain. This is a possible standard value. TarGetOwAUrl can also be configured to be Blank."
            $tdOrgRelTarGetOwAUrl = " $($OrgRel.TarGetOwAUrl) - TarGetOwAUrl is http://outlook.com/owa/$ExchangeOnlineDomain. This is a possible standard value. TarGetOwAUrl can also be configured to be Blank."
            $tdOrgRelTarGetOwAUrlColor = "green"
        }
        if ($OrgRel.TarGetOwAUrl -like "https://outlook.office.com/mail") {
            Write-Host -ForegroundColor Green "  TarGetOwAUrl is https://outlook.office.com/mail. This is a possible standard value. TarGetOwAUrl can also be configured to be Blank or http://outlook.com/owa/$ExchangeOnlineDomain."
            $tdOrgRelTarGetOwAUrl = " $($OrgRel.TarGetOwAUrl) - TarGetOwAUrl is https://outlook.office.com/mail. TarGetOwAUrl can also be configured to be Blank or http://outlook.com/owa/$ExchangeOnlineDomain."
            $tdOrgRelTarGetOwAUrlColor = "green"
        }
        if ($OrgRel.TarGetOwAUrl -like $Null) {
            Write-Host -ForegroundColor Green "  TarGetOwAUrl is Blank, this is a standard value. "
            Write-Host  "  TarGetOwAUrl can also be configured to be https://outlook.com/owa/$ExchangeOnlineDomain or https://outlook.office.com/mail"
            $tdOrgRelTarGetOwAUrl = "$($OrgRel.TarGetOwAUrl) . TarGetOwAUrl is Blank, this is a standard value. TarGetOwAUrl can also be configured to be http://outlook.com/owa/$ExchangeOnlineDomain or http://outlook.office.com/mail. "
            $tdOrgRelTarGetOwAUrlColor = "green"
            if ($OrgRel.TarGetOwAUrl -like "https://outlook.com/owa/$ExchangeOnlineDomain") {
                Write-Host -ForegroundColor Green "  TarGetOwAUrl is https://outlook.com/owa/$ExchangeOnlineDomain. This is a possible standard value. TarGetOwAUrl can also be configured to be Blank or http://outlook.office.com/mail."
                $tdOrgRelTarGetOwAUrl = " $($OrgRel.TarGetOwAUrl) - TarGetOwAUrl is https://outlook.com/owa/$ExchangeOnlineDomain. This is a possible standard value. TarGetOwAUrl can also be configured to be Blank or http://outlook.office.com/mail."
                $tdOrgRelTarGetOwAUrlColor = "green"
            }
        }
    } else {
        Write-Host -ForegroundColor Red "  TarGetOwAUrl seems not to be Blank or https://outlook.com/owa/$ExchangeOnlineDomain. These are the standard values."
        $countOrgRelIssues++
        $tdOrgRelTarGetOwAUrl = "  TarGetOwAUrl seems not to be Blank or https://outlook.com/owa/$ExchangeOnlineDomain. These are the standard values."
        $tdOrgRelTarGetOwAUrlColor = "red"
    }
    #TarGetSharingEpr
    Write-Host -ForegroundColor White   " TarGetSharingEpr:"
    if ([string]::IsNullOrWhitespace($OrgRel.TarGetSharingEpr) -or $OrgRel.TarGetSharingEpr -eq "https://outlook.office365.com/EWS/Exchange.asmx ") {
        Write-Host -ForegroundColor Green "  TarGetSharingEpr is ideally blank. This is the standard Value. "
        Write-Host  "  If it is set, it should be Office 365 EWS endpoint. Example: https://outlook.office365.com/EWS/Exchange.asmx "
        $tdTarGetSharingEpr = "  TarGetSharingEpr is ideally blank. This is the standard Value.
        If it is set, it should be Office 365 EWS endpoint. Example: https://outlook.office365.com/EWS/Exchange.asmx "
        $tdTarGetSharingEprColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  TarGetSharingEpr should be blank or  https://outlook.office365.com/EWS/Exchange.asmx"
        Write-Host  "  If it is set, it should be Office 365 EWS endpoint.  Example: https://outlook.office365.com/EWS/Exchange.asmx "
        $tdTarGetSharingEpr = "  TarGetSharingEpr should be blank or  https://outlook.office365.com/EWS/Exchange.asmx
        If it is set, it should be Office 365 EWS endpoint.  Example: https://outlook.office365.com/EWS/Exchange.asmx "
        $tdTarGetSharingEprColor = "red"
        $countOrgRelIssues++
    }
    #FreeBusyAccessScope
    Write-Host -ForegroundColor White  " FreeBusyAccessScope:"
    if ([string]::IsNullOrWhitespace($OrgRel.FreeBusyAccessScope)) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessScope is blank, this is the standard Value. "
        $tdFreeBusyAccessScope = " FreeBusyAccessScope is blank, this is the standard Value."
        $tdFreeBusyAccessScopeColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  FreeBusyAccessScope is should be Blank, that is the standard Value."
        $tdFreeBusyAccessScope = " FreeBusyAccessScope is should be Blank, that is the standard Value."
        $tdFreeBusyAccessScopeColor = "red"
        $countOrgRelIssues++
    }
    #TarGetAutoDiscoverEpr:
    $OrgRelTarGetAutoDiscoverEpr = $OrgRel.TarGetAutoDiscoverEpr
    if ([string]::IsNullOrWhitespace($OrgRelTarGetAutoDiscoverEpr)) {
        $OrgRelTarGetAutoDiscoverEpr = "Blank"
    }
    Write-Host -ForegroundColor White   " TarGetAutoDiscoverEpr:"
    if ($OrgRel.TarGetAutoDiscoverEpr -like "https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity" ) {
        Write-Host -ForegroundColor Green "  TarGetAutoDiscoverEpr is correct"
        $tdTarGetAutoDiscoverEPR = " TarGetAutoDiscoverEpr is https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity"
        $tdTarGetAutoDiscoverEPRColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  TarGetAutoDiscoverEpr is not correct. Should be https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity"
        $tdTarGetAutoDiscoverEPR = " TarGetAutoDiscoverEpr is $OrgRelTarGetAutoDiscoverEpr . Should be https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity"
        $tdTarGetAutoDiscoverEPRColor = "Red"
        $countOrgRelIssues++
    }
    #Enabled
    Write-Host -ForegroundColor White   " Enabled:"
    if ($OrgRel.enabled -like "True" ) {
        Write-Host -ForegroundColor Green "  Enabled is set to True"

        $tdFreeBusyEnabled = "$($OrgRel.enabled)"
        $tdFreeBusyEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Enabled is set to False."
        $countOrgRelIssues++

        $tdFreeBusyEnabled = "$($OrgRel.enabled) - Should be True."
        $tdFreeBusyEnabledColor = "red"
    }
    #if ($countOrgRelIssues -eq '0'){
    #Write-Host -ForegroundColor Green " Configurations Seem Correct"
    #}
    #else
    #{
    #Write-Host -ForegroundColor Red "  Configurations DO NOT Seem Correct"
    #}
    $OrgRelDomainNames = ""
    $OrgRelDomainNames = ""
    foreach ($domain in $OrgRel.DomainNames.Domain) {
        if ($OrgRelDomainNames -ne "") {
            $OrgRelDomainNames += "; "
        }
        $OrgRelDomainNames += $domain
    }
    $FreeBusyAccessEnabled = $OrgRel.FreeBusyAccessEnabled
    $FreeBusyAccessLevel = $OrgRel.FreeBusyAccessLevel
    $tdTarGetOwAUrl = $OrgRel.TarGetOwAUrl
    $tdEnabled = $OrgRel.Enabled
    $script:html += "

     <div class='Black'><p></p></div>

             <div class='Black'><h2><b>`n Exchange On Premise Free Busy Configuration: `n</b></h2></div>

             <div class='Black'><p></p></div>

         <table style='width:100%'>
    <tr>
    <th ColSpan='2' style='text-align:center; color:white;'><b>Exchange On Premise DAuth Configuration</b></th>
    </tr>
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-OrganizationRelationship</th>
    </tr>
    <tr>
    <td><b>Get-OrganizationRelationship</b></td>
    <td>
        <div> <b>Domain Names: </b> <span style='color:$tdDomainNamesColor'>$tdDomainNames</span></div>
        <div> <b>FreeBusyAccessEnabled: </b> <span style='color:$tdFBAccessEnabledColor'>$tdFBAccessEnabled</span></div>
        <div> <b>FreeBusyAccessLevel: </b> <span style='color:$tdFBAccessLevelColor'>$tdFBAccessLevel</span></div>
        <div> <b>TarGetApplicationUri: </b> <span style='color:$tdTarGetApplicationUriColor'>$tdTarGetApplicationUri</span></div>
        <div> <b>TarGetAutoDiscoverEPR: </b> <span style='color:$tdTarGetAutoDiscoverEPRColor'>$tdTarGetAutoDiscoverEPR</span></div>
        <div> <b>TarGetOwAUrl: </b> <span style='color:$tdOrgRelTarGetOwAUrlColor'>$tdOrgRelTarGetOwAUrl</span></div>
        <div> <b>TarGetSharingEpr: </b> <span style='color:$tdTarGetSharingEprColor'>$tdTarGetSharingEpr</span></div>
        <div> <b>FreeBusyAccessScope: </b> <span style='color:$tdFreeBusyAccessScopeColor'>$tdFreeBusyAccessScope</span></div>
        <div> <b>Enabled:</b> <span style='color:$tdFreeBusyEnabledColor'>$tdFreeBusyEnabled</span></div>
    </td>


 </tr>
  "
    $html | Out-File -FilePath $htmlFile
    Write-Host -ForegroundColor Yellow "`n  Reference: https://learn.microsoft.com/en-us/exchange/create-an-organization-relationship-exchange-2013-help"
}

function FedInfoCheck {
    Write-Host -ForegroundColor Green " Get-FederationInformation -DomainName $ExchangeOnlineDomain  -BypassAdditionalDomainValidation | fl"
    Write-Host $bar
    $FedInfo = Get-federationInformation -DomainName $ExchangeOnlineDomain  -BypassAdditionalDomainValidation -ErrorAction SilentlyContinue | Select-Object *
    if (!$FedInfo) {
        $FedInfo = Get-federationInformation -DomainName $ExchangeOnlineDomain  -BypassAdditionalDomainValidation -ErrorAction SilentlyContinue | Select-Object *
    }

    $FedInfo

    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Federation Information"
    Write-Host $bar
    #DomainNames
    Write-Host -ForegroundColor White   "  Domain Names: "
    if ($FedInfo.DomainNames -like "*$ExchangeOnlineDomain*") {
        Write-Host -ForegroundColor Green "   Domain Names include the Exchange Online Domain "$ExchangeOnlineDomain
        $tdDomainNamesColor = "green"
        $tdDomainNamesFL = "Domain Names include the Exchange Online Domain $ExchangeOnlineDomain"
    } else {
        Write-Host -ForegroundColor Red "   Domain Names seem not to include the Exchange Online Domain "$ExchangeOnlineDomain
        Write-Host  "   Domain Names: "$FedInfo.DomainNames
        $tdDomainNamesColor = "Red"
        $tdDomainNamesFL = "Domain Names seem not to include the Exchange Online Domain: $ExchangeOnlineDomain"
    }
    #TokenIssuerUris
    Write-Host  -ForegroundColor White  "  TokenIssuerUris: "
    if ($FedInfo.TokenIssuerUris -like "*urn:federation:MicrosoftOnline*") {
        Write-Host -ForegroundColor Green "  "  $FedInfo.TokenIssuerUris
        $tdTokenIssuerUrisColor = "green"
        $tdTokenIssuerUrisFL = $FedInfo.TokenIssuerUris
    } else {
        Write-Host "   " $FedInfo.TokenIssuerUris
        Write-Host  -ForegroundColor Red "   TokenIssuerUris should be urn:federation:MicrosoftOnline"
        $tdTokenIssuerUrisColor = "red"
        $tdTokenIssuerUrisFL = "   TokenIssuerUris should be urn:federation:MicrosoftOnline"
    }
    #TarGetApplicationUri
    Write-Host -ForegroundColor White   "  TarGetApplicationUri:"
    if ($FedInfo.TarGetApplicationUri -like "Outlook.com") {
        Write-Host -ForegroundColor Green "  "$FedInfo.TarGetApplicationUri
        $tdTarGetApplicationUriColor = "green"
        $tdTarGetApplicationUriFL = $FedInfo.TarGetApplicationUri
    } else {
        Write-Host -ForegroundColor Red "   "$FedInfo.TarGetApplicationUri
        Write-Host -ForegroundColor Red   "   TarGetApplicationUri should be Outlook.com"
        $tdTarGetApplicationUriColor = "red"
        $tdTarGetApplicationUriFL = "   TarGetApplicationUri should be Outlook.com"
    }
    #TarGetAutoDiscoverEpr
    Write-Host -ForegroundColor White   "  TarGetAutoDiscoverEpr:"
    if ($FedInfo.TarGetAutoDiscoverEpr -like "https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity") {
        Write-Host -ForegroundColor Green "   "$FedInfo.TarGetAutoDiscoverEpr
        $tdTarGetAutoDiscoverEprColor = "green"
        $tdTarGetAutoDiscoverEprFL = $FedInfo.TarGetAutoDiscoverEpr
    } else {
        Write-Host -ForegroundColor Red "   "$FedInfo.TarGetAutoDiscoverEpr
        Write-Host -ForegroundColor Red   " TarGetAutoDiscoverEpr should be https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity"
        $tdTarGetAutoDiscoverEprColor = "red"
        $tdTarGetAutoDiscoverEprFL = "   TarGetAutoDiscoverEpr should be https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity"
    }
    # Federation Information TarGetApplicationUri vs Organization Relationship TarGetApplicationUri
    Write-Host -ForegroundColor White "  Federation Information TarGetApplicationUri vs Organization Relationship TarGetApplicationUri "
    if ($FedInfo.TarGetApplicationUri -like "Outlook.com") {
        if ($OrgRel.TarGetApplicationUri -like $FedInfo.TarGetApplicationUri) {
            Write-Host -ForegroundColor Green "   => Federation Information TarGetApplicationUri matches the Organization Relationship TarGetApplicationUri "
            Write-Host  "       Organization Relationship TarGetApplicationUri:"  $OrgRel.TarGetApplicationUri
            Write-Host  "       Federation Information TarGetApplicationUri:   "  $FedInfo.TarGetApplicationUri
            $tdFederationInformationTAColor = "green"
            $tdFederationInformationTA_FL = " => Federation Information TarGetApplicationUri matches the Organization Relationship TarGetApplicationUri"
        } else {
            Write-Host -ForegroundColor Red "   => Federation Information TarGetApplicationUri should be Outlook.com and match the Organization Relationship TarGetApplicationUri "
            Write-Host  "       Organization Relationship TarGetApplicationUri:"  $OrgRel.TarGetApplicationUri
            Write-Host  "       Federation Information TarGetApplicationUri:   "  $FedInfo.TarGetApplicationUri
            $tdFederationInformationTAColor = "red"
            $tdFederationInformationTA_FL = " => Federation Information TarGetApplicationUri should be Outlook.com and match the Organization Relationship TarGetApplicationUri"
        }
    }
    #TarGetAutoDiscoverEpr vs Organization Relationship TarGetAutoDiscoverEpr
    Write-Host -ForegroundColor White  "  Federation Information TarGetAutoDiscoverEpr vs Organization Relationship TarGetAutoDiscoverEpr "
    if ($OrgRel.TarGetAutoDiscoverEpr -like $FedInfo.TarGetAutoDiscoverEpr) {
        Write-Host -ForegroundColor Green "   => Federation Information TarGetAutoDiscoverEpr matches the Organization Relationship TarGetAutoDiscoverEpr "
        Write-Host  "       Organization Relationship TarGetAutoDiscoverEpr:"  $OrgRel.TarGetAutoDiscoverEpr
        Write-Host  "       Federation Information TarGetAutoDiscoverEpr:   "  $FedInfo.TarGetAutoDiscoverEpr
        $tdTarGetAutoDiscoverEprVSColor = "green"
        $tdTarGetAutoDiscoverEprVS_FL = "=> Federation Information TarGetAutoDiscoverEpr matches the Organization Relationship TarGetAutoDiscoverEpr"
    } else {
        Write-Host -ForegroundColor Red "   => Federation Information TarGetAutoDiscoverEpr should match the Organization Relationship TarGetAutoDiscoverEpr"
        Write-Host  "       Organization Relationship TarGetAutoDiscoverEpr:"  $OrgRel.TarGetAutoDiscoverEpr
        Write-Host  "       Federation Information TarGetAutoDiscoverEpr:   "  $FedInfo.TarGetAutoDiscoverEpr
        $tdTarGetAutoDiscoverEprVSColor = "red"
        $tdTarGetAutoDiscoverEprVS_FL = "=> Federation Information TarGetAutoDiscoverEpr should match the Organization Relationship TarGetAutoDiscoverEpr"
    }
    Write-Host -ForegroundColor Yellow "`n  Reference: https://learn.microsoft.com/en-us/exchange/configure-a-federation-trust-exchange-2013-help#what-do-you-need-to-know-before-you-begin"
    Write-Host $bar
    $FedInfoDomainNames = ""
    $FedInfoDomainNames = ""
    foreach ($domain in $FedInfo.DomainNames.Domain) {
        if ($FedInfoDomainNames -ne "") {
            $FedInfoDomainNames += "; "
        }
        $FedInfoDomainNames += $domain
    }
    $aux = $FedInfo.DomainNames
    $FedInfoTokenIssuerUris = $FedInfo.TokenIssuerUris
    $FedInfoTarGetAutoDiscoverEpr = $FedInfo.TarGetAutoDiscoverEpr
    $FedInfoTarGetApplicationUri = $FedInfo.TarGetApplicationUri

    $script:html += "

    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-FederationInformation</th>
    </tr>
    <tr>
    <td><b>Get-FederationInformation -Domain $ExchangeOnPremDomain</b></td>
    <td>
        <div> <b>Domain Names: </b> <span style='color:$tdDomainNamesColor'>$tdDomainNamesFL</span></div>
        <div> <b>TokenIssuerUris: </b> <span style='color:$tdTokenIssuerUrisColor'>$tdTokenIssuerUrisFL</span></div>
        <div> <b>TarGetApplicationUri: </b> <span style='color:$tdTarGetApplicationUriColor'>$tdTarGetApplicationUriFL</span></div>
        <div> <b>TarGetAutoDiscoverEpr: </b> <span style='color:$tdTarGetAutoDiscoverEprColor'>$tdTarGetAutoDiscoverEprFL</span></div>
        <div> <b>TarGetApplicationUri - Federation Information vs Organization Relationship: </b> <span style='color:$tdTarGetAutoDiscoverEprVSColor'>$tdFederationInformationTA_FL</span></div>
        <div> <b>TarGetAutoDiscoverEpr - Federation Information vs Organization Relationship:</b> <span style='color:$tdTarGetAutoDiscoverEprVSColor'>$tdTarGetAutoDiscoverEprVS_FL</span></div>

    </td>


 </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function FedTrustCheck {
    Write-Host -ForegroundColor Green " Get-FederationTrust | fl ApplicationUri,TokenIssuerUri,OrgCertificate,TokenIssuerCertificate,
    TokenIssuerPrevCertificate, TokenIssuerMetadataEpr,TokenIssuerEpr"
    Write-Host $bar
    $Script:FedTrust = Get-FederationTrust | Select-Object ApplicationUri, TokenIssuerUri, OrgCertificate, TokenIssuerCertificate, TokenIssuerPrevCertificate, TokenIssuerMetadataEpr, TokenIssuerEpr
    $FedTrust
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Federation Trust"
    Write-Host $bar
    $CurrentTime = Get-Date
    Write-Host -ForegroundColor White " Federation Trust Application Uri:"
    if ($FedTrust.ApplicationUri -like "FYDIBOHF25SPDLT.$ExchangeOnpremDomain") {
        Write-Host -ForegroundColor Green " " $FedTrust.ApplicationUri
        $tdFedTrustApplicationUriColor = "green"
        $tdFedTrustApplicationUriFL = $FedTrust.ApplicationUri
    } else {
        Write-Host -ForegroundColor Red "  Federation Trust Application Uri Should be "$FedTrust.ApplicationUri
        $tdFedTrustApplicationUriColor = "red"
        $tdFedTrustApplicationUriFL = "  Federation Trust Application Uri Should be $FedTrust.ApplicationUri"
    }
    #$FedTrust.TokenIssuerUri.AbsoluteUri
    Write-Host -ForegroundColor White " TokenIssuerUri:"
    if ($FedTrust.TokenIssuerUri.AbsoluteUri -like "urn:federation:MicrosoftOnline") {
        #Write-Host -ForegroundColor White "  TokenIssuerUri:"
        Write-Host -ForegroundColor Green " "$FedTrust.TokenIssuerUri.AbsoluteUri
        $tdFedTrustTokenIssuerUriColor = "green"
        $tdFedTrustTokenIssuerUriFL = $FedTrust.TokenIssuerUri.AbsoluteUri
    } else {
        Write-Host -ForegroundColor Red " Federation Trust TokenIssuerUri should be urn:federation:MicrosoftOnline"
        $tdFedTrustTokenIssuerUriColor = "red"
        $tdFedTrustTokenIssuerFL = " Federation Trust TokenIssuerUri is currently $FedTrust.TokenIssuerUri.AbsoluteUri but should be urn:federation:MicrosoftOnline"
    }
    Write-Host -ForegroundColor White " Federation Trust Certificate Expiry:"
    if ($FedTrust.OrgCertificate.NotAfter.Date -gt $CurrentTime) {
        Write-Host -ForegroundColor Green "  Not Expired"
        Write-Host  "   - Expires on " $FedTrust.OrgCertificate.NotAfter.DateTime
        $tdFedTrustOrgCertificateNotAfterDateColor = "green"
        $tdFedTrustOrgCertificateNotAfterDateFL = $FedTrust.OrgCertificate.NotAfter.DateTime
    } else {
        Write-Host -ForegroundColor Red " Federation Trust Certificate is Expired on " $FedTrust.OrgCertificate.NotAfter.DateTime
        $tdFedTrustOrgCertificateNotAfterDateColor = "red"
        $tdFedTrustOrgCertificateNotAfterDateFL = $FedTrust.OrgCertificate.NotAfter.DateTime
    }
    Write-Host -ForegroundColor White " `Federation Trust Token Issuer Certificate Expiry:"
    if ($FedTrust.TokenIssuerCertificate.NotAfter.DateTime -gt $CurrentTime) {
        Write-Host -ForegroundColor Green "  Not Expired"
        Write-Host  "   - Expires on " $FedTrust.TokenIssuerCertificate.NotAfter.DateTime
        $tdFedTrustTokenIssuerCertificateNotAfterDateTimeColor = "green"
        $tdFedTrustTokenIssuerCertificateNotAfterDateTimeFL = $FedTrust.TokenIssuerCertificate.NotAfter.DateTime
    } else {
        Write-Host -ForegroundColor Red "  Federation Trust TokenIssuerCertificate Expired on " $FedTrust.TokenIssuerCertificate.NotAfter.DateTime
        $tdFedTrustTokenIssuerCertificateNotAfterDateTimeColor = "red"
        $tdFedTrustTokenIssuerCertificateNotAfterDateTimeFL = $FedTrust.TokenIssuerCertificate.NotAfter.DateTime
    }
    #Write-Host -ForegroundColor White " Federation Trust Token Issuer Prev Certificate Expiry:"
    #if ($FedTrust.TokenIssuerPrevCertificate.NotAfter.Date -gt $CurrentTime) {
    #Write-Host -ForegroundColor Green "  Not Expired"
    #Write-Host  "   - Expires on " $FedTrust.TokenIssuerPrevCertificate.NotAfter.DateTime
    #$tdFedTrustTokenIssuerPrevCertificateNotAfterDateColor = "green"
    #$tdFedTrustTokenIssuerPrevCertificateNotAfterDateFL = $FedTrust.TokenIssuerPrevCertificate.NotAfter.DateTime
    #}
    #else {
    #Write-Host -ForegroundColor Red "  Federation Trust TokenIssuerPrevCertificate Expired on " $FedTrust.TokenIssuerPrevCertificate.NotAfter.DateTime
    #$tdFedTrustTokenIssuerPrevCertificateNotAfterDateColor = "red"
    #$tdFedTrustTokenIssuerPrevCertificateNotAfterDateFL = $FedTrust.TokenIssuerPrevCertificate.NotAfter.DateTime
    #}
    $FedTrustTokenIssuerMetadataEpr = "https://nexus.microsoftonline-p.com/FederationMetadata/2006-12/FederationMetadata.xml"
    Write-Host -ForegroundColor White " `Token Issuer Metadata EPR:"
    if ($FedTrust.TokenIssuerMetadataEpr.AbsoluteUri -like $FedTrustTokenIssuerMetadataEpr) {
        Write-Host -ForegroundColor Green "  Token Issuer Metadata EPR is " $FedTrust.TokenIssuerMetadataEpr.AbsoluteUri
        #test if it can be reached
        $tdFedTrustTokenIssuerMetadataEprAbsoluteUriColor = "green"
        $tdFedTrustTokenIssuerMetadataEprAbsoluteUriFL = $FedTrust.TokenIssuerMetadataEpr.AbsoluteUri
    } else {
        Write-Host -ForegroundColor Red " Token Issuer Metadata EPR is Not " $FedTrust.TokenIssuerMetadataEpr.AbsoluteUri
        $tdFedTrustTokenIssuerMetadataEprAbsoluteUriColor = "red"
        $tdFedTrustTokenIssuerMetadataEprAbsoluteUriFL = $FedTrust.TokenIssuerMetadataEpr.AbsoluteUri
    }
    $FedTrustTokenIssuerEpr = "https://login.microsoftonline.com/extSTS.srf"
    Write-Host -ForegroundColor White " Token Issuer EPR:"
    if ($FedTrust.TokenIssuerEpr.AbsoluteUri -like $FedTrustTokenIssuerEpr) {
        Write-Host -ForegroundColor Green "  Token Issuer EPR is:" $FedTrust.TokenIssuerEpr.AbsoluteUri
        #test if it can be reached
        $tdFedTrustTokenIssuerEprAbsoluteUriColor = "green"
        $tdFedTrustTokenIssuerEprAbsoluteUriFL = $FedTrust.TokenIssuerEpr.AbsoluteUri
    } else {
        Write-Host -ForegroundColor Red "  Token Issuer EPR is Not:" $FedTrust.TokenIssuerEpr.AbsoluteUri
        $tdFedTrustTokenIssuerEprAbsoluteUriColor = "red"
        $tdFedTrustTokenIssuerEprAbsoluteUriFL = $FedTrust.TokenIssuerEpr.AbsoluteUri
    }
    $FedInfoTokenIssuerUris = $FedInfo.TokenIssuerUris
    $FedInfoTarGetApplicationUri = $FedInfo.TarGetApplicationUri
    $script:FedInfoTarGetAutoDiscoverEpr = $FedInfo.TarGetAutoDiscoverEpr

    $script:html += "
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Test-FederationTrust</th>
    </tr>
    <tr>
    <td><b>Get-FederationTrust | select ApplicationUri, TokenIssuerUri, OrgCertificate, TokenIssuerCertificate, TokenIssuerPrevCertificate, TokenIssuerMetadataEpr, TokenIssuerEpr</b></td>
    <td>
        <div> <b>Application Uri: </b> <span style='color:$tdFedTrustApplicationUriColor'>$tdFedTrustApplicationUriFL</span></div>
        <div> <b>TokenIssuerUris: </b> <span style='color:$tdFedTrustTokenIssuerUriColor'>$tdFedTrustTokenIssuerUriFL</span></div>
        <div> <b>Certificate Expiry: </b> <span style='color:$tdFedTrustOrgCertificateNotAfterDateColor'>$tdFedTrustOrgCertificateNotAfterDateFL</span></div>
        <div> <b>Token Issuer Certificate Expiry: </b> <span style='color:$tdFedTrustTokenIssuerCertificateNotAfterDateTimeColor'>$tdFedTrustTokenIssuerCertificateNotAfterDateTimeFL</span></div>
        <div> <b>Token Issuer Metadata EPR:</b> <span style='color:$tdFedTrustTokenIssuerMetadataEprAbsoluteUriColor'>$tdFedTrustTokenIssuerMetadataEprAbsoluteUriFL</span></div>
        <div> <b>Token Issuer EPR: </b> <span style='color:$tdFedTrustTokenIssuerEprAbsoluteUriColor'>$tdFedTrustTokenIssuerEprAbsoluteUriFL</span></div>

    </td>
</tr>
  "

    $html | Out-File -FilePath $htmlFile
    Write-Host -ForegroundColor Yellow "`n  Reference: https://learn.microsoft.com/en-us/exchange/configure-a-federation-trust-exchange-2013-help"
}

function AutoDVirtualDCheck {

    Write-Host $bar
    Write-Host -ForegroundColor Green " Get-AutoDiscoverVirtualDirectory | Select Identity,Name,ExchangeVersion,*authentication*"
    Write-Host $bar
    $Script:AutoDiscoveryVirtualDirectory = Get-AutoDiscoverVirtualDirectory | Select-Object Identity, Name, ExchangeVersion, *authentication* -ErrorAction SilentlyContinue
    #Check if null or set
    #$AutoDiscoveryVirtualDirectory
    $Script:AutoDiscoveryVirtualDirectory
    $AutoDFL = $Script:AutoDiscoveryVirtualDirectory | Format-List
    $script:html += "<tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-AutoDiscoverVirtualDirectory</th>
    </tr>
    <tr>
    <td><b>Get-AutoDiscoverVirtualDirectory | Select Identity,Name,ExchangeVersion,*authentication*</b></td>
    <td>"
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - On-Prem Get-AutoDiscoverVirtualDirectory"
    Write-Host $bar
    Write-Host -ForegroundColor White "  WSSecurityAuthentication:"
    if ($Script:AutoDiscoveryVirtualDirectory.WSSecurityAuthentication -eq "True") {
        foreach ( $ser in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($ser.Identity) "
            Write-Host -ForegroundColor Green "  WSSecurityAuthentication: $($ser.WSSecurityAuthentication)"

            $AutoD_VD_Identity = $ser.Identity
            $AutoD_VD_Name = $ser.Name
            $AutoD_VD_InternalAuthenticationMethods = $ser.InternalAuthenticationMethods
            $AutoD_VD_ExternalAuthenticationMethods = $ser.ExternalAuthenticationMethods
            $AutoD_VD_WSAuthentication = $ser.WSSecurityAuthentication
            $AutoD_VD_WSAuthenticationColor = "green"
            $AutoD_VD_WindowsAuthentication = $ser.WindowsAuthentication
            if ($AutoD_VD_WindowsAuthentication -eq "True") {
                $AutoD_VD_WindowsAuthenticationColor = "green"
            } else {
                $AutoD_VD_WindowsAuthenticationColor = "red"
            }
            $AutoD_VD_InternalNblBypassUrl = $ser.InternalNblBypassUrl
            $AutoD_VD_InternalUrl = $ser.InternalUrl
            $AutoD_VD_ExternalUrl = $ser.ExternalUrl
            $script:html +=
            " <div><b>============================</b></div>
            <div><b>Identity:</b> $AutoD_VD_Identity</div>
            <div><b>Name:</b> $AutoD_VD_Name </div>
            <div><b>InternalAuthenticationMethods:</b> $AutoD_VD_InternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $AutoD_VD_ExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:green'>$AutoD_VD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:green'>$AutoD_VD_WindowsAuthentication</span></div>
            "

            $serWSSecurityAuthenticationColor = "Green"
        }
    } else {
        Write-Host -ForegroundColor Red " WSSecurityAuthentication is NOT correct."
        foreach ( $ser in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($ser.Identity)"
            Write-Host -ForegroundColor Red "  WSSecurityAuthentication: $($ser.WSSecurityAuthentication)"
            $serWSSecurityAuthenticationColor = "Red"
            Write-Host " $($ser.Identity) "
            $AutoD_VD_Identity = $ser.Identity
            $AutoD_VD_Name = $ser.Name
            $AutoD_VD_InternalAuthenticationMethods = $ser.InternalAuthenticationMethods
            $AutoD_VD_ExternalAuthenticationMethods = $ser.ExternalAuthenticationMethods
            $AutoD_VD_WSAuthentication = $ser.WSSecurityAuthentication
            $AutoD_VD_WSAuthenticationColor = "green"
            $AutoD_VD_WindowsAuthentication = $ser.WindowsAuthentication
            if ($AutoD_VD_WindowsAuthentication -eq "True") {
                $AutoD_VD_WindowsAuthenticationColor = "green"
            } else {
                $AutoD_VD_WindowsAuthenticationColor = "red"
            }
            $AutoD_VD_InternalNblBypassUrl = $ser.InternalNblBypassUrl
            $AutoD_VD_InternalUrl = $ser.InternalUrl
            $AutoD_VD_ExternalUrl = $ser.ExternalUrl
            $script:html +=
            " <div><b>============================</b></div>
            <div><b>Identity:</b> $AutoD_VD_Identity</div>
            <div><b>Name:</b> $AutoD_VD_Name </div>
            <div><b>InternalAuthenticationMethods:</b> $AutoD_VD_InternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $AutoD_VD_ExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:red'>$AutoD_VD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:$AutoD_VD_WindowsAuthenticationColor'>$AutoD_VD_WindowsAuthentication</span></div>
            "
            Write-Host -ForegroundColor Green "  WSSecurityAuthentication: $($ser.WSSecurityAuthentication)"
            $serWSSecurityAuthenticationColor = "Red"
        }
        Write-Host -ForegroundColor White "  Should be True "
    }
    Write-Host -ForegroundColor White "`n  WindowsAuthentication:"
    if ($Script:AutoDiscoveryVirtualDirectory.WindowsAuthentication -eq "True") {
        foreach ( $ser in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($ser.Identity) "
            Write-Host -ForegroundColor Green "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
    } else {
        Write-Host -ForegroundColor Red " WindowsAuthentication is NOT correct."
        foreach ( $ser in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($ser.Identity)"
            Write-Host -ForegroundColor Red "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
        Write-Host -ForegroundColor White "  Should be True "
    }
    Write-Host -ForegroundColor Yellow "`n  Reference: https://learn.microsoft.com/en-us/powershell/module/exchange/Get-AutoDiscovervirtualdirectory?view=exchange-ps"
    $html | Out-File -FilePath $htmlFile
}

function EWSVirtualDirectoryCheck {
    Write-Host -ForegroundColor Green " Get-WebServicesVirtualDirectory | Select Identity,Name,ExchangeVersion,*Authentication*,*url"
    Write-Host $bar
    $Script:WebServicesVirtualDirectory = Get-WebServicesVirtualDirectory | Select-Object Identity, Name, ExchangeVersion, *Authentication*, *url -ErrorAction SilentlyContinue
    $Script:WebServicesVirtualDirectory
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Get-WebServicesVirtualDirectory"
    Write-Host $bar
    $script:html += "
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-WebServicesVirtualDirectory</th>
    </tr>
    <tr>
    <td><b> Get-WebServicesVirtualDirectory | Select Identity,Name,ExchangeVersion,*Authentication*,*url</b></td>
    <td >"
    Write-Host -ForegroundColor White "  WSSecurityAuthentication:"
    if ($Script:WebServicesVirtualDirectory.WSSecurityAuthentication -like "True") {
        foreach ( $EWS in $Script:WebServicesVirtualDirectory) {
            Write-Host " $($EWS.Identity)"
            Write-Host -ForegroundColor Green "  WSSecurityAuthentication: $($EWS.WSSecurityAuthentication) "
            $EwsVDIdentity = $EWS.Identity
            $EwsVDName = $EWS.Name
            $EwsVDInternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
            $EwsVDExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
            $EwsVD_WSAuthentication = $EWS.WSSecurityAuthentication
            $EwsVD_WSAuthenticationColor = "green"
            $EwsVDWindowsAuthentication = $EWS.WindowsAuthentication
            if ($EwsVDWindowsAuthentication -eq "True") {
                $EwsVDWindowsAuthenticationColor = "green"
            } else {
                $EWS_DWindowsAuthenticationColor = "red"
            }
            $EwsVDInternalNblBypassUrl = $EWS.InternalNblBypassUrl
            $EwsVDInternalUrl = $EWS.InternalUrl
            $EwsVDExternalUrl = $EWS.ExternalUrl
            $script:html +=
            " <div><b>============================</b></div>
            <div><b>Identity:</b> $EwsVDIdentity</div>
            <div><b>Name:</b> $EwsVDName </div>
            <div><b>InternalAuthenticationMethods:</b> $EwsVDInternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $EwsVDExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:green'>$EwsVD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:$EwsVDWindowsAuthenticationColor'>$EwsVDWindowsAuthentication</span></div>
            <div><b>InternalUrl:</b> $EwsVDInternalUrl </div>
            <div><b>ExternalUrl:</b> $EwsVDExternalUrl </div>  "
        }
    } else {
        Write-Host -ForegroundColor Red " WSSecurityAuthentication should be True."
        foreach ( $EWS in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Red "  WSSecurityAuthentication: $($ser.WSSecurityAuthentication) "
            $EwsVDIdentity = $EWS.Identity
            $EwsVDName = $EWS.Name
            $EwsVDInternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
            $EwsVDExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
            $EwsVD_WSAuthentication = $EWS.WSSecurityAuthentication
            $EwsVD_WSAuthenticationColor = "green"
            $EwsVDWindowsAuthentication = $EWS.WindowsAuthentication
            if ($EwsVDWindowsAuthentication -eq "True") {
                $EwsVDWindowsAuthenticationColor = "green"
            } else {
                $EWS_DWindowsAuthenticationColor = "red"
            }
            $EwsVDInternalNblBypassUrl = $EWS.InternalNblBypassUrl
            $EwsVDInternalUrl = $EWS.InternalUrl
            $EwsVDExternalUrl = $EWS.ExternalUrl
            $script:html +=
            " <div><b>============================</b></div>
            <div><b>Identity:</b> $EwsVDIdentity</div>
            <div><b>Name:</b> $EwsVDName </div>
            <div><b>InternalAuthenticationMethods:</b> $EwsVDInternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $EwsVDExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:red'>$EwsVD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:$EwsVDWindowsAuthenticationColor'>$EwsVDWindowsAuthentication</span></div>
            <div><b>InternalUrl:</b> $EwsVDInternalUrl </div>
            <div><b>ExternalUrl:</b> $EwsVDExternalUrl </div>  "
        }
        Write-Host -ForegroundColor White "  Should be True"
    }
    Write-Host -ForegroundColor White "`n  WindowsAuthentication:"
    if ($Script:WebServicesVirtualDirectory.WindowsAuthentication -like "True") {
        foreach ( $EWS in $Script:WebServicesVirtualDirectory) {
            Write-Host " $($EWS.Identity)"
            Write-Host -ForegroundColor Green "  WindowsAuthentication: $($EWS.WindowsAuthentication) "
        }
    } else {
        Write-Host -ForegroundColor Red " WindowsAuthentication should be True."
        foreach ( $EWS in $Script:AutoDiscoveryVirtualDirectory) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Red "  WindowsAuthentication: $($ser.WindowsAuthentication) "
        }
        Write-Host -ForegroundColor White "  Should be True"
    }
    $script:html += "
    </td>
    </tr>
    "
    $html | Out-File -FilePath $htmlFile
}

function AvailabilityAddressSpaceCheck {
    $bar
    Write-Host -ForegroundColor Green " Get-AvailabilityAddressSpace $ExchangeOnlineDomain | fl ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name"
    Write-Host $bar
    $AvailabilityAddressSpace = Get-AvailabilityAddressSpace $ExchangeOnlineDomain -ErrorAction SilentlyContinue | Select-Object ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name
    if (!$AvailabilityAddressSpace) {
        $AvailabilityAddressSpace = Get-AvailabilityAddressSpace $ExchangeOnlineDomain -ErrorAction SilentlyContinue | Select-Object ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name
    }
    $AvailabilityAddressSpace
    $tdAvailabilityAddressSpaceName = $AvailabilityAddressSpace.Name
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - On-Prem Availability Address Space Check"
    Write-Host $bar
    Write-Host -ForegroundColor White " ForestName: "
    if ($AvailabilityAddressSpace.ForestName -like $ExchangeOnlineDomain) {
        Write-Host -ForegroundColor Green " " $AvailabilityAddressSpace.ForestName
        $tdAvailabilityAddressSpaceForestName = $AvailabilityAddressSpace.ForestName
        $tdAvailabilityAddressSpaceForestColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  ForestName appears not to be correct."
        Write-Host -ForegroundColor White " Should contain the " $ExchangeOnlineDomain
        $tdAvailabilityAddressSpaceForestName = $AvailabilityAddressSpace.ForestName
        $tdAvailabilityAddressSpaceForestColor = "red"
    }
    Write-Host -ForegroundColor White " UserName: "
    if ($AvailabilityAddressSpace.UserName -like "") {
        Write-Host -ForegroundColor Green "  Blank"
        $tdAvailabilityAddressSpaceUserName = " Blank"
        $tdAvailabilityAddressSpaceUserNameColor = "green"
    } else {
        Write-Host -ForegroundColor Red " UserName is NOT correct. "
        Write-Host -ForegroundColor White "  Normally it should be blank"
        $tdAvailabilityAddressSpaceUserName = $AvailabilityAddressSpace.UserName
        $tdAvailabilityAddressSpaceUserNameColor = "red"
    }
    Write-Host -ForegroundColor White " UseServiceAccount: "
    if ($AvailabilityAddressSpace.UseServiceAccount -like "True") {
        Write-Host -ForegroundColor Green "  True"
        $tdAvailabilityAddressSpaceUseServiceAccount = $AvailabilityAddressSpace.UseServiceAccount
        $tAvailabilityAddressSpaceUseServiceAccountColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  UseServiceAccount appears not to be correct."
        Write-Host -ForegroundColor White "  Should be True"
        $tdAvailabilityAddressSpaceUseServiceAccount = $AvailabilityAddressSpace.UseServiceAccount
        $tAvailabilityAddressSpaceUseServiceAccountColor = "red"
    }
    Write-Host -ForegroundColor White " AccessMethod:"
    if ($AvailabilityAddressSpace.AccessMethod -like "InternalProxy") {
        Write-Host -ForegroundColor Green "  InternalProxy"
        $tdAvailabilityAddressSpaceAccessMethod = $AvailabilityAddressSpace.AccessMethod
        $tdAvailabilityAddressSpaceAccessMethodColor = "green"
    } else {
        Write-Host -ForegroundColor Red " AccessMethod appears not to be correct."
        Write-Host -ForegroundColor White " Should be InternalProxy"
        $tdAvailabilityAddressSpaceAccessMethod = $AvailabilityAddressSpace.AccessMethod
        $tdAvailabilityAddressSpaceAccessMethodColor = "red"
    }
    Write-Host -ForegroundColor White " ProxyUrl: "
    $tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
    if ([String]::Equals($tdAvailabilityAddressSpaceProxyUrl, $Script:ExchangeOnPremEWS, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Host -ForegroundColor Green " "$AvailabilityAddressSpace.ProxyUrl
        #$tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
        $tdAvailabilityAddressSpaceProxyUrlColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  ProxyUrl appears not to be correct."
        Write-Host -ForegroundColor White "  Should be $Script:ExchangeOnPremEWS[0] and not $tdAvailabilityAddressSpaceProxyUrl"
        #$tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
        $tdAvailabilityAddressSpaceProxyUrlColor = "red"
    }
    Write-Host -ForegroundColor Yellow "`n  Reference: https://learn.microsoft.com/en-us/powershell/module/exchange/Get-availabilityaddressspace?view=exchange-ps"
    $script:html += "
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - On-Premise Get-AvailabilityAddressSpace</th>
    </tr>
    <tr>
    <td><b> Get-AvailabilityAddressSpace $ExchangeOnlineDomain | fl ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name</b></td>
    <td>
    <div> <b>Forest Name: </b> $tdAvailabilityAddressSpaceForestName</div>
    <div> <b>Name: </b> $tdAvailabilityAddressSpaceName</div>
    <div> <b>UserName: </b> <span style='color:$tdAvailabilityAddressSpaceUserNameColor'>$tdAvailabilityAddressSpaceUserName</span></div>
    <div> <b>Access Method: </b> <span style='color:$tdAvailabilityAddressSpaceAccessMethodColor'>$tdAvailabilityAddressSpaceAccessMethod</span></div>
    <div> <b>ProxyUrl: </b> <span style='color:$tdAvailabilityAddressSpaceProxyUrlColor'>$tdAvailabilityAddressSpaceProxyUrl</span></div>
    </td>
    </tr>"
    $html | Out-File -FilePath $htmlFile
}

function TestFedTrust {
    Write-Host $bar
    $TestFedTrustFail = 0
    $a = Test-FederationTrust -UserIdentity $UserOnPrem -verbose -ErrorAction SilentlyContinue #fails the first time on multiple occasions so we have a ghost FedTrustCheck
    Write-Host -ForegroundColor Green  " Test-FederationTrust -UserIdentity $UserOnPrem -verbose"
    Write-Host $bar
    $TestFedTrust = Test-FederationTrust -UserIdentity $UserOnPrem -verbose -ErrorAction SilentlyContinue
    $TestFedTrust
    $Script:html += "<tr>
    <th ColSpan='2' style='color:white;'><b>Summary - On Premise Test-FederationTrust</b></th>
    </tr>
    <tr>
    <td><b> Test-FederationTrust -UserIdentity $UserOnPrem</b></td>
    <td>"
    $i = 0
    while ($i -lt $TestFedTrust.type.Count) {
        $test = $TestFedTrust.type[$i]
        $testType = $TestFedTrust.Type[$i]
        $testMessage = $TestFedTrust.Message[$i]
        $TestFedTrustID = $($TestFedTrust.ID[$i])
        if ($test -eq "Error") {
            # Write-Host " $($TestFedTrust.ID[$i]) "
            # Write-Host -ForegroundColor Red " $($TestFedTrust.Type[$i])  "
            # Write-Host " $($TestFedTrust.Message[$i]) "
            $Script:html += "

            <div> <span style='color:red'><b>$testType :</b></span> - <div> <b>$TestFedTrustID </b> - $testMessage  </div>
            "
            $TestFedTrustFail++
        }
        if ($test -eq "Success") {
            # Write-Host " $($TestFedTrust.ID[$i]) "
            # Write-Host -ForegroundColor Green " $($TestFedTrust.Type[$i])  "
            # Write-Host " $($TestFedTrust.Message[$i])  "
            $Script:html += "

            <div> <span style='color:green'><b>$testType :</b> </span> - <b>$TestFedTrustID </b> - $testMessage</div>"
        }
        $i++
    }

    if ($TestFedTrustFail -eq 0) {
        Write-Host -ForegroundColor Green " Federation Trust Successfully tested"
        $Script:html += "
        <p></p>
        <div class=�green�> <span style='color:green'> Federation Trust Successfully tested </span></div>"
    } else {
        Write-Host -ForegroundColor Red " Federation Trust test with Errors"
        $Script:html += "
        <p></p>
        <div class=�red�> <span style='color:red'> Federation Trust tested with Errors </span></div>"
    }

    #Write-Host $bar
    #Write-Host -ForegroundColor Green " Test-FederationTrustCertificate"
    #Write-Host $bar
    $TestFederationTrustCertificate = Test-FederationTrustCertificate -ErrorAction SilentlyContinue
    #$TestFederationTrustCertificate
    #Write-Host $bar
    if ($TestFederationTrustCertificate) {

        Write-Host $bar
        Write-Host -ForegroundColor Green " Test-FederationTrustCertificate"
        Write-Host $bar
        $TestFederationTrustCertificate

        $Script:html += "<tr>
                <th ColSpan='2' style='color:white;'><b>Summary - Test-FederationTrustCertificate</b></th>
                </tr>
                <tr>
                <td><b> Test-FederationTrustCertificate</b></td>
                <td>"

        $j = 0
        while ($j -lt $TestFederationTrustCertificate.Count) {

            $TestFederationTrustCertificateJ = "<div>" + $TestFederationTrustCertificate.site[$j] + "</div><div>" + $TestFederationTrustCertificate.state[$j] + "</div><div>" + $TestFederationTrustCertificate.Thumbprint[$j] + "</div>"
            $Script:html += "
                $TestFederationTrustCertificateJ

                "
            $j++
        }
        $Script:html += "</td>"
    }
    $html | Out-File -FilePath $htmlFile
}

function TestOrgRel {
    $bar
    $TestFail = 0
    $OrgRelIdentity = $OrgRel.Identity

    $OrgRelTarGetApplicationUri = $OrgRel.TarGetApplicationUri

    if ( $OrgRelTarGetApplicationUri -like "Outlook.com" -OR $OrgRelTarGetApplicationUri -like "outlook.com") {
        $Script:html += "<tr>
        <th ColSpan='2' style='color:white;'><b>Summary - Test-OrganizationRelationship</b></th>
        </tr>
        <tr>
        <td><b>Test-OrganizationRelationship -Identity $OrgRelIdentity  -UserIdentity $UserOnPrem</b></td>
        <td>"
        Write-Host -ForegroundColor Green "Test-OrganizationRelationship -Identity $OrgRelIdentity  -UserIdentity $UserOnPrem"
        #need to grab errors and provide alerts in error case
        Write-Host $bar
        $TestOrgRel = Test-OrganizationRelationship -Identity "$($OrgRelIdentity)"  -UserIdentity $UserOnPrem -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        #$TestOrgRel
        if ($TestOrgRel[16] -like "No Significant Issues to Report") {
            Write-Host -ForegroundColor Green "`n No Significant Issues to Report"
            $Script:html += "
        <div class='green'> <b>No Significant Issues to Report</b><div>"
        } else {
            Write-Host -ForegroundColor Red "`n Test Organization Relationship Completed with errors"
            $Script:html += "
        <div class='red'> <b>Test Organization Relationship Completed with errors</b><div>"
        }
        $TestOrgRel[0]
        $TestOrgRel[1]
        $i = 0
        while ($i -lt $TestOrgRel.Length) {
            $element = $TestOrgRel[$i]
            #if ($element.Contains("RESULT: Success.")) {
            if ($element -like "*RESULT: Success.*") {
                $TestOrgRelStep = $TestOrgRel[$i - 1]
                $TestOrgRelStep
                Write-Host -ForegroundColor Green "$element"
                if (![string]::IsNullOrWhitespace($TestOrgRelStep)) {
                    $Script:html += "
            <div></b> <span style='color:black'> <b> $TestOrgRelStep :</b></span> <span style='color:green'>$element</span></div>"
                }
            }

            else {
                if ($element -like "*RESULT: Error*") {
                    $TestOrgRelStep = $TestOrgRel[$i - 1]
                    $TestOrgRelStep
                    Write-Host -ForegroundColor Red "$element"
                    if (![string]::IsNullOrWhitespace($TestOrgRelStep)) {
                        $Script:html += "
                <div></b> <span style='color:black'> <b> $TestOrgRelStep : </b></span> <span style='color:red'>$element</span></div>"
                    }
                }
            }
            $i++
        }
    } else {
        Write-Host -ForegroundColor Green " Test-OrganizationRelationship -Identity $OrgRelIdentity  -UserIdentity $UserOnPrem"
        #need to grab errors and provide alerts in error case
        Write-Host $bar
        $Script:html += "<tr>
    <th ColSpan='2' style='color:white;'><b>Summary - Test-OrganizationRelationship</b></th>
    </tr>
    <tr>
    <td><b>Test-OrganizationRelationship</b></td>
    <td>"
        Write-Host -ForegroundColor Red "`n Test-OrganizationRelationship can't be run if the Organization Relationship TarGet Application uri is not correct. Organization Relationship TarGet Application Uri should be Outlook.com"
        $Script:html += "
    <div class='red'> <b> Test-OrganizationRelationship can't be run if the Organization Relationship TarGet Application uri is not correct. Organization Relationship TarGet Application Uri should be Outlook.com</b><div>"
    }

    Write-Host -ForegroundColor Yellow "`n  Reference: https://techcommunity.microsoft.com/t5/exchange-team-blog/how-to-address-federation-trust-issues-in-hybrid-configuration/ba-p/1144285"
    Write-Host $bar
    $Script:html += "</td>
    </tr>"
    $html | Out-File -FilePath $htmlFile
}

#endregion

#region OAuth Functions

function IntraOrgConCheck {
    Write-Host $bar
    Write-Host -ForegroundColor Green " Get-IntraOrganizationConnector | Select Name,TarGetAddressDomains,DiscoveryEndpoint,Enabled"
    Write-Host $bar
    $IOC = $IntraOrgCon | Format-List
    $IOC
    $tdIntraOrgTarGetAddressDomain = $IntraOrgCon.TarGetAddressDomains
    $tdDiscoveryEndpoint = $IntraOrgCon.DiscoveryEndpoint
    $tdEnabled = $IntraOrgCon.Enabled

    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Get-IntraOrganizationConnector"
    Write-Host $bar
    $IntraOrgTarGetAddressDomain = $IntraOrgCon.TarGetAddressDomains.Domain
    $IntraOrgTarGetAddressDomain = $IntraOrgTarGetAddressDomain.ToLower()
    Write-Host -ForegroundColor White " TarGet Address Domains: "
    if ($IntraOrgCon.TarGetAddressDomains -like "*$ExchangeOnlineDomain*" -Or $IntraOrgCon.TarGetAddressDomains -like "*$ExchangeOnlineAltDomain*" ) {
        Write-Host -ForegroundColor Green " " $IntraOrgCon.TarGetAddressDomains
        $tdIntraOrgTarGetAddressDomainColor = "green"
    } else {
        Write-Host -ForegroundColor Red " TarGet Address Domains appears not to be correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnlineDomain domain or the $ExchangeOnlineAltDomain domain."
        $tdIntraOrgTarGetAddressDomainColor = "red"
    }

    Write-Host -ForegroundColor White " DiscoveryEndpoint: "
    if ($IntraOrgCon.DiscoveryEndpoint -like "https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc") {
        Write-Host -ForegroundColor Green "  https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc"
        $tdDiscoveryEndpointColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  The DiscoveryEndpoint appears not to be correct. "
        Write-Host -ForegroundColor White "  It should represent the address of EXO AutoDiscover endpoint."
        Write-Host  "  Examples: https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc; https://outlook.office365.com/AutoDiscover/AutoDiscover.svc "
        $tdDiscoveryEndpointColor = "red"
    }
    Write-Host -ForegroundColor White " Enabled: "
    if ($IntraOrgCon.Enabled -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $tdEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  On-Prem Intra Organization Connector is not Enabled"
        Write-Host -ForegroundColor White "  In order to use OAuth it Should be True."
        Write-Host "  If it is set to False, the Organization Relationship (DAuth) , if enabled, is used for the Hybrid Availability Sharing"
        $tdEnabledColor = "red"
    }

    Write-Host -ForegroundColor Yellow "https://techcommunity.microsoft.com/t5/exchange-team-blog/demystifying-hybrid-free-busy-what-are-the-moving-parts/ba-p/607704"

    # Build HTML table row
    if ($Auth -like "OAuth") {
        $Script:html += "
        <div class='Black'><p></p></div>

        <div class='Black'><h2><b>`n Exchange On Premise Free Busy Configuration: `n</b></h2></div>

        <div class='Black'><p></p></div>"
    }
    $Script:html += "

    <table style='width:100%'>

   <tr>
      <th ColSpan='2' style='text-align:center; color:white;'>Exchange On Premise OAuth Configuration</th>
    </tr>
    <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-IntraOrganizationConnector</th>
    </tr>

    <tr>
      <td><b>Get-IntraOrganizationConnector:</b></td>
      <td>
        <div><b>TarGet Address Domains:</b><span style='color: $tdIntraOrgTarGetAddressDomainColor'>$($tdIntraOrgTarGetAddressDomain)</span></div>
        <div><b>Discovery Endpoint:</b><span style='color: $tdDiscoveryEndpointColor;'>$($tdDiscoveryEndpoint)</span></div>
        <div><b>Enabled:</b><span style='color: $tdEnabledColor;'>$($tdEnabled)</span></div>
      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function AuthServerCheck {
    #Write-Host $bar
    Write-Host -ForegroundColor Green " Get-AuthServer | Select Name,IssuerIdentifier,TokenIssuingEndpoint,AuthMetadatAUrl,Enabled"
    Write-Host $bar
    $AuthServer = Get-AuthServer | Where-Object { $_.Name -like "ACS*" } | Select-Object Name, IssuerIdentifier, TokenIssuingEndpoint, AuthMetadatAUrl, Enabled
    $AuthServer
    $tDAuthServerIssuerIdentifier = $AuthServer.IssuerIdentifier
    $tDAuthServerTokenIssuingEndpoint = $AuthServer.TokenIssuingEndpoint
    $tDAuthServerAuthMetadatAUrl = $AuthServer.AuthMetadatAUrl
    $tDAuthServerEnabled = $AuthServer.Enabled
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Auth Server"
    Write-Host $bar
    Write-Host -ForegroundColor White " IssuerIdentifier: "
    if ($AuthServer.IssuerIdentifier -like "00000001-0000-0000-c000-000000000000" ) {
        Write-Host -ForegroundColor Green " " $AuthServer.IssuerIdentifier
        $tDAuthServerIssuerIdentifierColor = "green"
    } else {
        Write-Host -ForegroundColor Red " IssuerIdentifier appears not to be correct."
        Write-Host -ForegroundColor White " Should be 00000001-0000-0000-c000-000000000000"
        $tDAuthServerIssuerIdentifierColor = "red"
    }
    Write-Host -ForegroundColor White " TokenIssuingEndpoint: "
    if ($AuthServer.TokenIssuingEndpoint -like "https://accounts.accesscontrol.windows.net/*" -and $AuthServer.TokenIssuingEndpoint -like "*/tokens/OAuth/2" ) {
        Write-Host -ForegroundColor Green " " $AuthServer.TokenIssuingEndpoint
        $tDAuthServerTokenIssuingEndpointColor = "green"
    } else {
        Write-Host -ForegroundColor Red " TokenIssuingEndpoint appears not to be correct."
        Write-Host -ForegroundColor White " Should be  https://accounts.accesscontrol.windows.net/<Cloud Tenant ID>/tokens/OAuth/2"
        $tDAuthServerTokenIssuingEndpointColor = "red"
    }
    Write-Host -ForegroundColor White " AuthMetadatAUrl: "
    if ($AuthServer.AuthMetadatAUrl -like "https://accounts.accesscontrol.windows.net/*" -and $AuthServer.TokenIssuingEndpoint -like "*/tokens/OAuth/2" ) {
        Write-Host -ForegroundColor Green " " $AuthServer.AuthMetadatAUrl
        $tDAuthServerAuthMetadatAUrlColor = "green"
    } else {
        Write-Host -ForegroundColor Red " AuthMetadatAUrl appears not to be correct."
        Write-Host -ForegroundColor White " Should be  https://accounts.accesscontrol.windows.net/<Cloud Tenant ID>/metadata/json/1"
        $tDAuthServerAuthMetadatAUrlColor = "red"
    }
    Write-Host -ForegroundColor White " Enabled: "
    if ($AuthServer.Enabled -like "True" ) {
        Write-Host -ForegroundColor Green " " $AuthServer.Enabled
        $tDAuthServerEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red " Enabled: False "
        Write-Host -ForegroundColor White " Should be True"
        $tDAuthServerEnabledColor = "red"
    }

    $Script:html += "
    <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-AuthServer</th>
    </tr>

    <tr>
      <td><b> Get-AuthServer | Select Name,IssuerIdentifier,TokenIssuingEndpoint,AuthMetadatAUrl,Enabled</b></td>
      <td>
        <div><b>IssuerIdentifier:</b><span style='color: $tDAuthServerIssuerIdentifierColor'>$($tDAuthServerIssuerIdentifier)</span></div>
        <div><b>TokenIssuingEndpoint:</b><span style='color: $tDAuthServerTokenIssuingEndpointColor;'>$($tDAuthServerTokenIssuingEndpoint)</span></div>
        <div><b>AuthMetadatAUrl:</b><span style='color: $tDAuthServerAuthMetadatAUrlColor;'>$($tDAuthServerAuthMetadatAUrl)</span></div>
        <div><b>Enabled:</b><span style='color: $tDAuthServerEnabledColor;'>$($tDAuthServerEnabled)</span></div>
      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function PartnerApplicationCheck {
    #Write-Host $bar
    Write-Host -ForegroundColor Green " Get-PartnerApplication |  ?{`$_.ApplicationIdentifier -eq '00000002-0000-0ff1-ce00-000000000000'
    -and `$_.Realm -eq ''} | Select Enabled, ApplicationIdentifier, CertificateStrings, AuthMetadatAUrl, Realm, UseAuthServer,
    AcceptSecurityIdentifierInformation, LinkedAccount, IssuerIdentifier, AppOnlyPermissions, ActAsPermissions, Name"

    Write-Host $bar
    $PartnerApplication = Get-PartnerApplication | Where-Object { $_.ApplicationIdentifier -eq '00000002-0000-0ff1-ce00-000000000000' -and $_.Realm -eq '' } | Select-Object Enabled, ApplicationIdentifier, CertificateStrings, AuthMetadatAUrl, Realm, UseAuthServer, AcceptSecurityIdentifierInformation, LinkedAccount, IssuerIdentifier, AppOnlyPermissions, ActAsPermissions, Name
    $PartnerApplication
    $tdPartnerApplicationEnabled = $PartnerApplication.Enabled
    $tdPartnerApplicationApplicationIdentifier = $PartnerApplication.ApplicationIdentifier
    $tdPartnerApplicationCertificateStrings = $PartnerApplication.CertificateStrings
    $tdPartnerApplicationAuthMetadatAUrl = $PartnerApplication.AuthMetadatAUrl
    $tdPartnerApplicationRealm = $PartnerApplication.Realm
    $tdPartnerApplicationUseAuthServer = $PartnerApplication.UseAuthServer
    $tdPartnerApplicationAcceptSecurityIdentifierInformation = $PartnerApplication.AcceptSecurityIdentifierInformation
    $tdPartnerApplicationLinkedAccount = $PartnerApplication.LinkedAccount
    $tdPartnerApplicationIssuerIdentifier = $PartnerApplication.IssuerIdentifier
    $tdPartnerApplicationAppOnlyPermissions = $PartnerApplication.AppOnlyPermissions
    $tdPartnerApplicationActAsPermissions = $PartnerApplication.ActAsPermissions
    $tdPartnerApplicationName = $PartnerApplication.Name

    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Partner Application"
    Write-Host $bar
    Write-Host -ForegroundColor White " Enabled: "
    if ($PartnerApplication.Enabled -like "True" ) {
        Write-Host -ForegroundColor Green " " $PartnerApplication.Enabled
        $tdPartnerApplicationEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red " Enabled: False "
        Write-Host -ForegroundColor White " Should be True"
        $tdPartnerApplicationEnabledColor = "red"
    }
    Write-Host -ForegroundColor White " ApplicationIdentifier: "
    if ($PartnerApplication.ApplicationIdentifier -like "00000002-0000-0ff1-ce00-000000000000" ) {
        Write-Host -ForegroundColor Green " " $PartnerApplication.ApplicationIdentifier
        $tdPartnerApplicationApplicationIdentifierColor = "green"
    } else {
        Write-Host -ForegroundColor Red " ApplicationIdentifier does not appear to be correct"
        Write-Host -ForegroundColor White " Should be 00000002-0000-0ff1-ce00-000000000000"
        $tdPartnerApplicationApplicationIdentifierColor = "red"
    }
    Write-Host -ForegroundColor White " AuthMetadatAUrl: "
    if ([string]::IsNullOrWhitespace( $PartnerApplication.AuthMetadatAUrl)) {
        Write-Host -ForegroundColor Green "  Blank"
        $tdPartnerApplicationAuthMetadatAUrlColor = "green"
        $tdPartnerApplicationAuthMetadatAUrl = "Blank"
    } else {
        Write-Host -ForegroundColor Red " AuthMetadatAUrl does not seem to be correct"
        Write-Host -ForegroundColor White " Should be Blank"
        $tdPartnerApplicationAuthMetadatAUrlColor = "red"
        $tdPartnerApplicationAuthMetadatAUrl = " Should be Blank"
    }
    Write-Host -ForegroundColor White " Realm: "
    if ([string]::IsNullOrWhitespace( $PartnerApplication.Realm)) {
        Write-Host -ForegroundColor Green "  Blank"
        $tdPartnerApplicationRealmColor = "green"
        $tdPartnerApplicationRealm = "Blank"
    } else {
        Write-Host -ForegroundColor Red "  Realm does not seem to be correct"
        Write-Host -ForegroundColor White " Should be Blank"
        $tdPartnerApplicationRealmColor = "Red"
        $tdPartnerApplicationRealm = "Should be Blank"
    }
    Write-Host -ForegroundColor White " LinkedAccount: "
    if ($PartnerApplication.LinkedAccount -like "$exchangeOnPremDomain/Users/Exchange Online-ApplicationAccount" -or $PartnerApplication.LinkedAccount -like "$exchangeOnPremLocalDomain/Users/Exchange Online-ApplicationAccount"  ) {
        Write-Host -ForegroundColor Green " " $PartnerApplication.LinkedAccount
        $tdPartnerApplicationLinkedAccountColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  LinkedAccount value does not appear to be correct"
        Write-Host -ForegroundColor White "  Should be $exchangeOnPremLocalDomain/Users/Exchange Online-ApplicationAccount"
        Write-Host "  If you value is empty, set it to correspond to the Exchange Online-ApplicationAccount which is located at the root of Users container in AD. After you make the change, reboot the Servers."
        Write-Host "  Example: contoso.com/Users/Exchange Online-ApplicationAccount"
        $tdPartnerApplicationLinkedAccountColor = "red"
        $tdPartnerApplicationLinkedAccount
    }

    $Script:html += "
    <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-PartnerApplication</th>
    </tr>
    <tr>
      <td><b> Get-PartnerApplication |  ?{`$_.ApplicationIdentifier -eq '00000002-0000-0ff1-ce00-000000000000'
    -and `$_.Realm -eq ''} | Select Enabled, ApplicationIdentifier, CertificateStrings, AuthMetadatAUrl, Realm, UseAuthServer,
    AcceptSecurityIdentifierInformation, LinkedAccount, IssuerIdentifier, AppOnlyPermissions, ActAsPermissions, Name</b></td>
      <td>
        <div><b>Enabled:</b><span style='color: $tdPartnerApplicationEnabledColor'>$($tdPartnerApplicationEnabled)</span></div>
        <div><b>ApplicationIdentifier:</b><span style='color: $tdPartnerApplicationApplicationIdentifierColor;'>$($tdPartnerApplicationApplicationIdentifier)</span></div>
        <div><b>CertificateStrings:</b><span style='color: $tdPartnerApplicationCertificateStringsColor;'>$($tdPartnerApplicationCertificateStrings)</span></div>
        <div><b>AuthMetadatAUrl:</b><span style='color: $tdPartnerApplicationAuthMetadatAUrlColor;'>$($tdPartnerApplicationAuthMetadatAUrl)</span></div>
        <div><b>Realm:</b><span style='color: $tdPartnerApplicationRealmColor'>$($tdPartnerApplicationRealm)</span></div>
        <div><b>LinkedAccount:</b><span style='color: $tdPartnerApplicationLinkedAccountColor;'>$($tdPartnerApplicationLinkedAccount)</span></div>
        <div><b>IssuerIdentifier:</b><span style='color: $tdPartnerApplicationEnabledColor'>$($tdPartnerApplicationEnabled)</span></div>
        <div><b>AppOnlyPermissions:</b><span style='color: $tdPartnerApplicationApplicationIdentifierColor;'>$($tdPartnerApplicationApplicationIdentifier)</span></div>
        <div><b>ActAsPermissions:</b><span style='color: $tdPartnerApplicationCertificateStringsColor;'>$($tdPartnerApplicationCertificateStrings)</span></div>
        <div><b>Name:</b><span style='color: $tdPartnerApplicationAuthMetadatAUrlColor;'>$($tdPartnerApplicationAuthMetadatAUrl)</span></div>

      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function ApplicationAccountCheck {
    #Write-Host $bar
    Write-Host -ForegroundColor Green " Get-user '$exchangeOnPremLocalDomain/Users/Exchange Online-ApplicationAccount' | Select Name, RecipientType, RecipientTypeDetails, UserAccountControl"
    Write-Host $bar
    $ApplicationAccount = Get-user "$exchangeOnPremLocalDomain/Users/Exchange Online-ApplicationAccount" | Select-Object Name, RecipientType, RecipientTypeDetails, UserAccountControl
    $ApplicationAccount
    $tdApplicationAccountRecipientType = $ApplicationAccount.RecipientType
    $tdApplicationAccountRecipientTypeDetails = $ApplicationAccount.RecipientTypeDetails
    $tdApplicationAccountUserAccountControl = $ApplicationAccount.UserAccountControl
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Application Account"
    Write-Host $bar
    Write-Host -ForegroundColor White " RecipientType: "
    if ($ApplicationAccount.RecipientType -like "User" ) {
        Write-Host -ForegroundColor Green " " $ApplicationAccount.RecipientType
        $tdApplicationAccountRecipientTypeColor = "green"
    } else {
        Write-Host -ForegroundColor Red " RecipientType value is $ApplicationAccount.RecipientType "
        Write-Host -ForegroundColor White " Should be User"
        $tdApplicationAccountRecipientTypeColor = "red"
    }
    Write-Host -ForegroundColor White " RecipientTypeDetails: "
    if ($ApplicationAccount.RecipientTypeDetails -like "LinkedUser" ) {
        Write-Host -ForegroundColor Green " " $ApplicationAccount.RecipientTypeDetails
        $tdApplicationAccountRecipientTypeDetailsColor = "green"
    } else {
        Write-Host -ForegroundColor Red " RecipientTypeDetails value is $ApplicationAccount.RecipientTypeDetails"
        Write-Host -ForegroundColor White " Should be LinkedUser"
        $tdApplicationAccountRecipientTypeDetailsColor = "red"
    }
    Write-Host -ForegroundColor White " UserAccountControl: "
    if ($ApplicationAccount.UserAccountControl -like "AccountDisabled, PasswordNotRequired, NormalAccount" ) {
        Write-Host -ForegroundColor Green " " $ApplicationAccount.UserAccountControl
        $tdApplicationAccountUserAccountControlColor = "green"
    } else {
        Write-Host -ForegroundColor Red " UserAccountControl value does not seem correct"
        Write-Host -ForegroundColor White " Should be AccountDisabled, PasswordNotRequired, NormalAccount"
        $tdApplicationAccountUserAccountControlColor = "red"
    }

    $Script:html += "
      <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-User ApplicationAccount</th>
    </tr>
    <tr>
      <td><b>  Get-user '$exchangeOnPremLocalDomain/Users/Exchange Online-ApplicationAccount' | Select Name, RecipientType, RecipientTypeDetails, UserAccountControl':</b></td>
      <td>
        <div><b>RecipientType:</b><span style='color: $tdApplicationAccountRecipientTypeColor'>$($tdApplicationAccountRecipientType)</span></div>
        <div><b>RecipientTypeDetails:</b><span style='color: $tdApplicationAccountRecipientTypeDetailsColor;'>$($tdApplicationAccountRecipientTypeDetails)</span></div>
        <div><b>UserAccountControl:</b><span style='color: $tdApplicationAccountUserAccountControlColor;'>$($tdApplicationAccountUserAccountControl)</span></div>

      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function ManagementRoleAssignmentCheck {
    Write-Host -ForegroundColor Green " Get-ManagementRoleAssignment -RoleAssignee Exchange Online-ApplicationAccount | Select Name,Role -AutoSize"
    Write-Host $bar
    $ManagementRoleAssignment = Get-ManagementRoleAssignment -RoleAssignee "Exchange Online-ApplicationAccount" | Select-Object Name, Role
    $M = $ManagementRoleAssignment | Out-String
    $M

    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Management Role Assignment for the Exchange Online-ApplicationAccount"
    Write-Host $bar
    Write-Host -ForegroundColor White " Role: "
    if ($ManagementRoleAssignment.Role -like "*UserApplication*" ) {
        Write-Host -ForegroundColor Green "  UserApplication Role Assigned"
        $tdManagementRoleAssignmentUserApplication = " UserApplication Role Assigned"
        $tdManagementRoleAssignmentUserApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  UserApplication Role not present for the Exchange Online-ApplicationAccount"
        $tdManagementRoleAssignmentUserApplication = " UserApplication Role not present"
        $tdManagementRoleAssignmentUserApplicationColor = "red"
    }
    if ($ManagementRoleAssignment.Role -like "*ArchiveApplication*" ) {
        Write-Host -ForegroundColor Green "  ArchiveApplication Role Assigned"
        $tdManagementRoleAssignmentArchiveApplication = " ArchiveApplication Role Assigned"
        $tdManagementRoleAssignmentArchiveApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  ArchiveApplication Role not present for the Exchange Online-ApplicationAccount"
        $tdManagementRoleAssignmentArchiveApplication = " ArchiveApplication Role not Assigned"
        $tdManagementRoleAssignmentArchiveApplicationColor = "red"
    }
    if ($ManagementRoleAssignment.Role -like "*LegalHoldApplication*" ) {
        Write-Host -ForegroundColor Green "  LegalHoldApplication Role Assigned"
        $tdManagementRoleAssignmentLegalHoldApplication = " LegalHoldApplication Role Assigned"
        $tdManagementRoleAssignmentLegalHoldApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  LegalHoldApplication Role not present for the Exchange Online-ApplicationAccount"
        $tdManagementRoleAssignmentLegalHoldApplication = " LegalHoldApplication Role Assigned"
        $tdManagementRoleAssignmentLegalHoldApplicationColor = "green"
    }
    if ($ManagementRoleAssignment.Role -like "*Mailbox Search*" ) {
        Write-Host -ForegroundColor Green "  Mailbox Search Role Assigned"
        $tdManagementRoleAssignmentMailboxSearch = " Mailbox Search Role Assigned"
        $tdManagementRoleAssignmentMailboxSearchColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Mailbox Search Role not present for the Exchange Online-ApplicationAccount"
        $tdManagementRoleAssignmentMailboxSearch = " Mailbox Search Role Not Assigned"
        $tdManagementRoleAssignmentMailboxSearchColor = "red"
    }
    if ($ManagementRoleAssignment.Role -like "*TeamMailboxLifecycleApplication*" ) {
        Write-Host -ForegroundColor Green "  TeamMailboxLifecycleApplication Role Assigned"
        $tdManagementRoleAssignmentTeamMailboxLifecycleApplication = " TeamMailboxLifecycleApplication Role Assigned"
        $tdManagementRoleAssignmentTeamMailboxLifecycleApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  TeamMailboxLifecycleApplication Role not present for the Exchange Online-ApplicationAccount"
        $tdManagementRoleAssignmentTeamMailboxLifecycleApplication = " TeamMailboxLifecycleApplication Role Not Assigned"
        $tdManagementRoleAssignmentTeamMailboxLifecycleApplicationColor = "red"
    }
    if ($ManagementRoleAssignment.Role -like "*MailboxSearchApplication*" ) {
        Write-Host -ForegroundColor Green "  MailboxSearchApplication Role Assigned"
        $tdManagementRoleMailboxSearchApplication = " MailboxSearchApplication Role Assigned"
        $tdManagementRoleMailboxSearchApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  MailboxSearchApplication Role not present for the Exchange Online-ApplicationAccount"
        $tdManagementRoleMailboxSearchApplication = " MailboxSearchApplication Role Not Assigned"
        $tdManagementRoleMailboxSearchApplicationColor = "red"
    }
    if ($ManagementRoleAssignment.Role -like "*MeetingGraphApplication*" ) {
        Write-Host -ForegroundColor Green "  MeetingGraphApplication Role Assigned"
        $tdManagementRoleMeetingGraphApplication = " MeetingGraphApplication Role Assigned"
        $tdManagementRoleMeetingGraphApplicationColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  MeetingGraphApplication Role not present for the Exchange Online-ApplicationAccount"
        $tdManagementRoleMeetingGraphApplication = " MeetingGraphApplication Role Not Assigned"
        $tdManagementRoleMeetingGraphApplicationColor = "red"
    }

    $tdManagementRoleMeetingGraphApplication = " MailboxSearchApplication Role Assigned"
    $tdManagementRoleMeetingGraphApplicationColor = "green"

    $Script:html += "
      <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-ManagementRoleAssignment</th>
    </tr>
    <tr>
      <td><b>  Get-ManagementRoleAssignment -RoleAssignee Exchange Online-ApplicationAccount | Select Name,Role</b></td>
      <td>
        <div><b>UserApplication Role:</b><span style='color: $tdManagementRoleAssignmentUserApplicationColor'>$($tdManagementRoleAssignmentUserApplication)</span></div>
        <div><b>ArchiveApplication Role:</b><span style='color: $tdManagementRoleAssignmentArchiveApplicationColor;'>$($tdManagementRoleAssignmentArchiveApplication)</span></div>
        <div><b>LegalHoldApplication Role:</b><span style='color: $tdManagementRoleAssignmentLegalHoldApplicationColor;'>$($tdManagementRoleAssignmentLegalHoldApplication)</span></div>
        <div><b>Mailbox Search Role:</b><span style='color: $tdManagementRoleAssignmentMailboxSearchColor'>$($tdManagementRoleAssignmentMailboxSearch)</span></div>
        <div><b>TeamMailboxLifecycleApplication Role:</b><span style='color: $tdManagementRoleAssignmentTeamMailboxLifecycleApplicationColor;'>$($tdManagementRoleAssignmentTeamMailboxLifecycleApplication)</span></div>
        <div><b>MailboxSearchApplication Role:</b><span style='color: $tdManagementRoleMailboxSearchApplicationColor;'>$($tdManagementRoleMailboxSearchApplication)</span></div>
        <div><b>MeetingGraphApplication Role:</b><span style='color: $tdManagementRoleMeetingGraphApplicationColor;'>$($tdManagementRoleMeetingGraphApplication)</span></div>

      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function AuthConfigCheck {
    Write-Host -ForegroundColor Green " Get-AuthConfig | Select *Thumbprint, ServiceName, Realm, Name"
    Write-Host $bar
    $AuthConfig = Get-AuthConfig | Select-Object *Thumbprint, ServiceName, Realm, Name
    $AC = $AuthConfig | Format-List
    $AC

    $tDAuthConfigName = $AuthConfig.Name

    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Auth Config"
    Write-Host $bar
    if (![string]::IsNullOrWhitespace($AuthConfig.CurrentCertificateThumbprint)) {
        Write-Host " Thumbprint: "$AuthConfig.CurrentCertificateThumbprint
        Write-Host -ForegroundColor Green " Certificate is Assigned"
        $tDAuthConfigCurrentCertificateThumbprint = $AuthConfig.CurrentCertificateThumbprint
        $tDAuthConfigCurrentCertificateThumbprintColor = "green"
    } else {
        Write-Host " Thumbprint: "$AuthConfig.CurrentCertificateThumbprint
        Write-Host -ForegroundColor Red " No valid certificate Assigned "
        $tDAuthConfigCurrentCertificateThumbprintColor = "red"
        $tDAuthConfigCurrentCertificateThumbprint = "$AuthConfig.CurrentCertificateThumbprint - No valid certificate Assigned "
    }
    if ($AuthConfig.ServiceName -like "00000002-0000-0ff1-ce00-000000000000" ) {
        Write-Host " ServiceName: "$AuthConfig.ServiceName
        Write-Host -ForegroundColor Green " Service Name Seems correct"
        $tDAuthConfigServiceNameColor = "green"
        $tDAuthConfigServiceName = $AuthConfig.ServiceName
    } else {
        Write-Host " ServiceName: "$AuthConfig.ServiceName
        Write-Host -ForegroundColor Red " Service Name does not Seems correct. Should be 00000002-0000-0ff1-ce00-000000000000"
        $tDAuthConfigServiceNameColor = "red"
        $tDAuthConfigServiceName = "$AuthConfig.ServiceName  Should be 00000002-0000-0ff1-ce00-000000000000"
    }
    if ([string]::IsNullOrWhitespace($AuthConfig.Realm)) {
        Write-Host " Realm: "
        Write-Host -ForegroundColor Green " Realm is Blank"
        $tDAuthConfigRealmColor = "green"
        $tDAuthConfigRealm = " Realm is Blank"
    } else {
        Write-Host " Realm: "$AuthConfig.Realm
        Write-Host -ForegroundColor Red " Realm should be Blank"
        $tDAuthConfigRealmColor = "red"
        $tDAuthConfigRealm = "$tDAuthConfig.Realm - Realm should be Blank"
    }

    $Script:html += "
      <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-AuthConfig</th>
    </tr>
    <tr>
      <td><b>  Get-AuthConfig | Select-Object *Thumbprint, ServiceName, Realm, Name</b></td>
      <td>
        <div><b>Name:</b><span >$($tDAuthConfigName)</span></div>
        <div><b>Thumbprint:</b><span style='color: $tDAuthConfigCurrentCertificateThumbprintColor'>$($tDAuthConfigCurrentCertificateThumbprint)</span></div>
        <div><b>ServiceName:</b><span style='color:$tDAuthConfigServiceNameColor;'>$( $tDAuthConfigServiceName)</span></div>
        <div><b>Realm:</b><span style='color: $tDAuthConfigRealmColor;'>$($tDAuthConfigRealm)</span></div>


      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function CurrentCertificateThumbprintCheck {
    $thumb = Get-AuthConfig | Select-Object CurrentCertificateThumbprint
    $thumbprint = $thumb.CurrentCertificateThumbprint
    #Write-Host $bar
    Write-Host -ForegroundColor Green " Get-ExchangeCertificate -Thumbprint $thumbprint | Select FriendlyName, Issuer, Services, NotAfter, Status, HasPrivateKey, Subject, Thumb*"
    Write-Host $bar
    $CurrentCertificate = Get-ExchangeCertificate $thumb.CurrentCertificateThumbprint | Select-Object  FriendlyName, Issuer, Services, NotAfter, Status, HasPrivateKey, Subject, Thumb*
    $CC = $CurrentCertificate | Format-List
    $CC

    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Microsoft Exchange Server Auth Certificate"
    Write-Host $bar
    if ($CurrentCertificate.Issuer -like "CN=Microsoft Exchange Server Auth Certificate" ) {
        Write-Host " Issuer: " $CurrentCertificate.Issuer
        Write-Host -ForegroundColor Green " Issuer is CN=Microsoft Exchange Server Auth Certificate"
        $tdCurrentCertificateIssuer = "   $($CurrentCertificate.Issuer) - Issuer is CN=Microsoft Exchange Server Auth Certificate"
        $tdCurrentCertificateIssuerColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Issuer is not CN=Microsoft Exchange Server Auth Certificate"
        $tdCurrentCertificateIssuer = "   $($CurrentCertificate.Issuer) - Issuer is Not CN=Microsoft Exchange Server Auth Certificate"
        $tdCurrentCertificateIssuerColor = "red"
    }
    if ($CurrentCertificate.Services -like "SMTP" ) {
        Write-Host " Services: " $CurrentCertificate.Services
        Write-Host -ForegroundColor Green "  Certificate enabled for SMTP"
        $tdCurrentCertificateServices = "  $($tdCurrentCertificate.Services) - Certificate enabled for SMTP"
        $tdCurrentCertificateServicesColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Certificate Not enabled for SMTP"
        $tdCurrentCertificateServices = "  $($tdCurrentCertificate.Services) - Certificate Not enabled for SMTP"
        $tdCurrentCertificateServicesColor = "red"
    }
    if ($CurrentCertificate.Status -like "Valid" ) {
        Write-Host " Status: " $CurrentCertificate.Status
        Write-Host -ForegroundColor Green "  Certificate is valid"
        $tdCurrentCertificateStatus = "  Certificate is valid"
        $tdCurrentCertificateStatusColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Certificate is not Valid"
        $tdCurrentCertificateStatus = "  Certificate is Not Valid"
        $tdCurrentCertificateStatusColor = "red"
    }
    if ($CurrentCertificate.Subject -like "CN=Microsoft Exchange Server Auth Certificate" ) {
        Write-Host " Subject: " $CurrentCertificate.Subject
        Write-Host -ForegroundColor Green "  Subject is CN=Microsoft Exchange Server Auth Certificate"
        $tdCurrentCertificateSubject = "  Subject is CN=Microsoft Exchange Server Auth Certificate"
        $tdCurrentCertificateSubjectColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Subject is not CN=Microsoft Exchange Server Auth Certificate"
        $tdCurrentCertificateSubject = "  $($CurrentCertificate.Subject) - Subject should be CN=Microsoft Exchange Server Auth Certificate"
        $tdCurrentCertificateSubjectColor = "red"
    }
    Write-Host -ForegroundColor White "`n Checking Exchange Auth Certificate Distribution `n"
    $CheckAuthCertDistribution = foreach ($name in (Get-ExchangeServer).name) { Get-ExchangeCertificate -Thumbprint (Get-AuthConfig).CurrentCertificateThumbprint -Server $name -ErrorAction SilentlyContinue | Select-Object Identity, thumbprint, Services, subject }
    foreach ($Server in $CheckAuthCertDistribution) {
        $ServerName = ($Server -split "\.")[0]
        Write-Host -ForegroundColor White  "  Server: " $ServerName
        #Write-Host  "   Thumbprint: " $Thumbprint
        if ($Server.Thumbprint -like $thumbprint) {
            Write-Host  "   Thumbprint: "$Server.Thumbprint
            Write-Host  "   Subject: "$Server.Subject
            $ServerIdentity = $Server.Identity
            $tdCheckAuthCertDistribution = "   <div>Certificate with Thumbprint: $($Server.Thumbprint) Subject: $($Server.Subject) is present in Server $ServerIdentity</div>"
            $tdCheckAuthCertDistributionColor = "green"
        }
        if ($Server.Thumbprint -ne $thumbprint) {
            Write-Host -ForegroundColor Red "  Auth Certificate seems Not to be present in $ServerName"
            $tdCheckAuthCertDistribution = "   Auth Certificate seems Not to be present in $ServerName"
            $tdCheckAuthCertDistributionColor = "Red"
        }
    }

    $Script:html += "
      <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-ExchangeCertificate AuthCertificate</th>
    </tr>
    <tr>
      <td><b>  Get-ExchangeCertificate $thumb.CurrentCertificateThumbprint | Select-Object *</b></td>
      <td>
        <div><b>Issuer:</b><span style='color: $tdCurrentCertificateIssuerColor'>$($tdCurrentCertificateIssuer)</span></div>
        <div><b>Services:</b><span style='color: $tdCurrentCertificateServicesColor'>$($tdCurrentCertificateServices)</span></div>
        <div><b>Status:</b><span style='color:$tdCurrentCertificateStatusColor;'>$( $tdCurrentCertificateStatus)</span></div>
        <div><b>Subject:</b><span style='color: $tdCurrentCertificateSubjectColor;'>$($tdCurrentCertificateSubject)</span></div>
        <div><b>Distribution:</b><span style='color: $tdCheckAuthCertDistributionColor;'>$($tdCheckAuthCertDistribution)</span></div>


      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function AutoDVirtualDCheckOauth {
    #Write-Host -ForegroundColor Green " `n On-Prem AutoDiscover Virtual Directory `n "
    Write-Host -ForegroundColor Green " Get-AutoDiscoverVirtualDirectory | Select Identity, Name,ExchangeVersion,*authentication*"
    Write-Host $bar
    $AutoDiscoveryVirtualDirectoryOAuth = Get-AutoDiscoverVirtualDirectory | Select-Object Identity, Name, ExchangeVersion, *authentication* -ErrorAction SilentlyContinue
    #Check if null or set
    $AD = $AutoDiscoveryVirtualDirectoryOAuth | Format-List
    $AD
    $script:html += "<tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-AutoDiscoverVirtualDirectory</th>
    </tr>
    <tr>
    <td><b>Get-AutoDiscoverVirtualDirectory:</b></td>
    <td>"

    if ($Auth -contains "OAuth") {
    }
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Get-AutoDiscoverVirtualDirectory"
    Write-Host $bar
    Write-Host -ForegroundColor White "  InternalAuthenticationMethods"
    if ($AutoDiscoveryVirtualDirectoryOAuth.InternalAuthenticationMethods -like "*OAuth*") {
        foreach ( $EWS in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Green "  InternalAuthenticationMethods Include OAuth Authentication Method "

            $AutoD_VD_Identity = $EWS.Identity
            $AutoD_VD_Name = $EWS.Name
            $AutoD_VD_InternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
            $AutoD_VD_ExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
            $AutoD_VD_WSAuthentication = $EWS.WSSecurityAuthentication
            $AutoD_VD_WSAuthenticationColor = "green"
            $AutoD_VD_WindowsAuthentication = $EWS.WindowsAuthentication
            $AutoD_VD_OAuthAuthentication = $EWS.OAuthAuthentication
            if ($AutoD_VD_WindowsAuthentication -eq "True") {
                $AutoD_VD_WindowsAuthenticationColor = "green"
            } else {
                $AutoD_VD_WindowsAuthenticationColor = "red"
            }
            if ($AutoD_VD_OAuthAuthentication -eq "True") {
                $AutoD_VD_OAuthAuthenticationColor = "green"
            } else {
                $AutoD_VD_OAuthAuthenticationColor = "red"
            }
            $AutoD_VD_InternalNblBypassUrl = $EWS.InternalNblBypassUrl
            $AutoD_VD_InternalUrl = $EWS.InternalUrl
            $AutoD_VD_ExternalUrl = $EWS.ExternalUrl
            $script:html +=
            " <div><b>============================</b></div>
            <div><b>Identity:</b> $AutoD_VD_Identity</div>
            <div><b>Name:</b> $AutoD_VD_Name </div>
            <div><b>InternalAuthenticationMethods:</b> $AutoD_VD_InternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $AutoD_VD_ExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:green'>$AutoD_VD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:green'>$AutoD_VD_WindowsAuthentication</span></div>
            <div><b>OAuthAuthentication:</b> <span style='color:$AutoD_VD_OAuthAuthenticationColor'>$AutoD_VD_OAuthAuthentication</span></div>
            "
        }
    } else {
        Write-Host -ForegroundColor Red "  InternalAuthenticationMethods seems not to include OAuth Authentication Method."
        $AutoD_VD_Identity = $EWS.Identity
        $AutoD_VD_Name = $EWS.Name
        $AutoD_VD_InternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
        $AutoD_VD_ExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
        $AutoD_VD_WSAuthentication = $EWS.WSSecurityAuthentication
        $AutoD_VD_WSAuthenticationColor = "green"
        $AutoD_VD_OAuthAuthentication = $EWS.OAuthAuthentication
        $AutoD_VD_WindowsAuthentication = $EWS.WindowsAuthentication
        if ($AutoD_VD_WindowsAuthentication -eq "True") {
            $AutoD_VD_WindowsAuthenticationColor = "green"
        } else {
            $AutoD_VD_WindowsAuthenticationColor = "red"
        }
        $AutoD_VD_InternalNblBypassUrl = $EWS.InternalNblBypassUrl
        $AutoD_VD_InternalUrl = $EWS.InternalUrl
        $AutoD_VD_ExternalUrl = $EWS.ExternalUrl
        $script:html +=
        " <div><b>============================</b></div>
            <div><b>Identity:</b> $AutoD_VD_Identity</div>
            <div><b>Name:</b> $AutoD_VD_Name </div>
            <div><b>InternalAuthenticationMethods:</b> $AutoD_VD_InternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $AutoD_VD_ExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:red'>$AutoD_VD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:$AutoD_VD_WindowsAuthenticationColor'>$AutoD_VD_WindowsAuthentication</span></div>
            <div><b>OAuthAuthentication:</b> <span style='color:$AutoD_VD_OAuthAuthenticationColor'>$AutoD_VD_OAuthAuthentication</span></div>
            "
    }
    Write-Host -ForegroundColor White "`n  ExternalAuthenticationMethods"
    if ($AutoDiscoveryVirtualDirectoryOAuth.ExternalAuthenticationMethods -like "*OAuth*") {
        foreach ( $EWS in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Green "  ExternalAuthenticationMethods Include OAuth Authentication Method "
        }
    } else {
        Write-Host -ForegroundColor Red "  ExternalAuthenticationMethods seems not to include OAuth Authentication Method."
    }
    Write-Host -ForegroundColor White "`n  WSSecurityAuthentication:"
    if ($AutoDiscoveryVirtualDirectoryOAuth.WSSecurityAuthentication -like "True") {
        #Write-Host -ForegroundColor Green " `n  " $Script:AutoDiscoveryVirtualDirectory.WSSecurityAuthentication
        foreach ( $AdVd in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($AdVd.Identity) "
            Write-Host -ForegroundColor Green "  WSSecurityAuthentication: $($AdVd.WSSecurityAuthentication)"
        }
    } else {
        Write-Host -ForegroundColor Red "  WSSecurityAuthentication settings are NOT correct."
        foreach ( $AdVd in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($AdVd.Identity) "
            Write-Host -ForegroundColor Red "  WSSecurityAuthentication: $($AdVd.WSSecurityAuthentication).  WSSecurityAuthentication setting should be True."
        }
        Write-Host -ForegroundColor White "  Should be True "
    }
    Write-Host -ForegroundColor White "`n  WindowsAuthentication:"
    if ($AutoDiscoveryVirtualDirectoryOAuth.WindowsAuthentication -eq "True") {
        foreach ( $ser in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($ser.Identity) "
            Write-Host -ForegroundColor Green "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
    } else {
        Write-Host -ForegroundColor Red " WindowsAuthentication is NOT correct."
        foreach ( $ser in $AutoDiscoveryVirtualDirectoryOAuth) {
            Write-Host " $($ser.Identity)"
            Write-Host -ForegroundColor Red "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
        Write-Host -ForegroundColor White "  Should be True "
    }
    #Write-Host $bar

    $html | Out-File -FilePath $htmlFile
}

function EWSVirtualDirectoryCheckOAuth {
    Write-Host -ForegroundColor Green " Get-WebServicesVirtualDirectory | Select Identity,Name,ExchangeVersion,*Authentication*,*url"
    Write-Host $bar
    $WebServicesVirtualDirectoryOAuth = Get-WebServicesVirtualDirectory | Select-Object Identity, Name, ExchangeVersion, *Authentication*, *url
    $W = $WebServicesVirtualDirectoryOAuth | Format-List
    $W

    $script:html += "
    <tr>
    <th ColSpan='2' style='color:white;'>Summary - Get-WebServicesVirtualDirectory</th>
    </tr>
    <tr>
    <td><b>Get-WebServicesVirtualDirectory | Select Identity,Name,ExchangeVersion,*Authentication*,*url</b></td>
    <td >"

    if ($Auth -contains "OAuth") {
    }
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - On-Prem Get-WebServicesVirtualDirectory"
    Write-Host $bar
    Write-Host -ForegroundColor White "  InternalAuthenticationMethods"
    if ($WebServicesVirtualDirectoryOAuth.InternalAuthenticationMethods -like "*OAuth*") {
        foreach ( $EWS in $WebServicesVirtualDirectoryOAuth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Green "  InternalAuthenticationMethods Include OAuth Authentication Method "

            $EwsVDIdentity = $EWS.Identity
            $EwsVDName = $EWS.Name
            $EwsVDInternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
            $EwsVDExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
            $EwsVD_WSAuthentication = $EWS.WSSecurityAuthentication
            $EwsVD_WSAuthenticationColor = "green"
            $EwsVDWindowsAuthentication = $EWS.WindowsAuthentication
            $EwsVDOAuthAuthentication = $EWS.OAuthAuthentication
            if ($EwsVDWindowsAuthentication -eq "True") {
                $EwsVDWindowsAuthenticationColor = "green"
            } else {
                $EWS_DWindowsAuthenticationColor = "red"
            }
            if ($EwsVDOAuthAuthentication -eq "True") {
                $EwsVDW_OAuthAuthenticationColor = "green"
            } else {
                $EWS_DOAuthAuthenticationColor = "red"
            }
            $EwsVDInternalNblBypassUrl = $EWS.InternalNblBypassUrl
            $EwsVDInternalUrl = $EWS.InternalUrl
            $EwsVDExternalUrl = $EWS.ExternalUrl
            $script:html +=
            " <div><b>============================</b></div>
            <div><b>Identity:</b> $EwsVDIdentity</div>
            <div><b>Name:</b> $EwsVDName </div>
            <div><b>InternalAuthenticationMethods:</b> $EwsVDInternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $EwsVDExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:green'>$EwsVD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:$EwsVDWindowsAuthenticationColor'>$EwsVDWindowsAuthentication</span></div>
            <div><b>OAuthAuthentication:</b> <span style='color:$EwsVDW_OAuthAuthenticationColor'>$EwsVDOAuthAuthentication</span></div>
            <div><b>InternalUrl:</b> $EwsVDInternalUrl </div>
            <div><b>ExternalUrl:</b> $EwsVDExternalUrl </div>  "
        }
    } else {
        Write-Host -ForegroundColor Red "  InternalAuthenticationMethods seems not to include OAuth Authentication Method."
        $EwsVDIdentity = $EWS.Identity
        $EwsVDName = $EWS.Name
        $EwsVDInternalAuthenticationMethods = $EWS.InternalAuthenticationMethods
        $EwsVDExternalAuthenticationMethods = $EWS.ExternalAuthenticationMethods
        $EwsVD_WSAuthentication = $EWS.WSSecurityAuthentication
        $EwsVD_WSAuthenticationColor = "green"
        $EwsVDWindowsAuthentication = $EWS.WindowsAuthentication
        $EwsVDOAuthAuthentication = $EWS.OAuthAuthentication
        if ($EwsVDWindowsAuthentication -eq "True") {
            $EwsVDWindowsAuthenticationColor = "green"
        } else {
            $EWS_DWindowsAuthenticationColor = "red"
        }
        if ($EwsVDOAuthAuthentication -eq "True") {
            $EwsVDW_OAuthAuthenticationColor = "green"
        } else {
            $EWS_DOAuthAuthenticationColor = "red"
        }
        $EwsVDInternalNblBypassUrl = $EWS.InternalNblBypassUrl
        $EwsVDInternalUrl = $EWS.InternalUrl
        $EwsVDExternalUrl = $EWS.ExternalUrl
        $script:html +=
        " <div><b>============================</b></div>
            <div><b>Identity:</b> $EwsVDIdentity</div>
            <div><b>Name:</b> $EwsVDName </div>
            <div><b>InternalAuthenticationMethods:</b> $EwsVDInternalAuthenticationMethods </div>
            <div><b>ExternalAuthenticationMethods:</b> $EwsVDExternalAuthenticationMethods </div>
            <div><b>WSAuthentication:</b> <span style='color:red'>$EwsVD_WSAuthentication</span></div>
            <div><b>WindowsAuthentication:</b> <span style='color:$EwsVDWindowsAuthenticationColor'>$EwsVDWindowsAuthentication</span></div>
            <div><b>OAuthAuthentication:</b> <span style='color:$EwsVDW_OAuthAuthenticationColor'>$EwsVDOAuthAuthentication</span></div>
            <div><b>InternalUrl:</b> $EwsVDInternalUrl </div>
            <div><b>ExternalUrl:</b> $EwsVDExternalUrl </div>  "
    }
    Write-Host -ForegroundColor White "`n  ExternalAuthenticationMethods"
    if ($WebServicesVirtualDirectoryOAuth.ExternalAuthenticationMethods -like "*OAuth*") {
        foreach ( $EWS in $WebServicesVirtualDirectoryOAuth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Green "  ExternalAuthenticationMethods Include OAuth Authentication Method "
        }
    } else {
        Write-Host -ForegroundColor Red "  ExternalAuthenticationMethods seems not to include OAuth Authentication Method."
    }
    Write-Host -ForegroundColor White "`n  WSSecurityAuthentication:"
    if ($WebServicesVirtualDirectoryOAuth.WSSecurityAuthentication -like "True") {
        foreach ( $EWS in $WebServicesVirtualDirectoryOAuth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Green "  WSSecurityAuthentication: $($EWS.WSSecurityAuthentication) "
        }
    } else {
        Write-Host -ForegroundColor Red "  WSSecurityAuthentication is NOT correct."
        foreach ( $EWS in $WebServicesVirtualDirectoryOauth) {
            Write-Host " $($EWS.Identity) "
            Write-Host -ForegroundColor Red "  WSSecurityAuthentication: $($EWS.WSSecurityAuthentication)"
        }
        Write-Host -ForegroundColor White "  Should be True"
    }
    #Write-Host $bar
    Write-Host -ForegroundColor White "`n  WindowsAuthentication:"
    if ($WebServicesVirtualDirectoryOauth.WindowsAuthentication -eq "True") {
        foreach ( $ser in $WebServicesVirtualDirectoryOauth) {
            Write-Host " $($ser.Identity) "
            Write-Host -ForegroundColor Green "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
    } else {
        Write-Host -ForegroundColor Red " WindowsAuthentication is NOT correct."
        foreach ( $ser in $WebServicesVirtualDirectoryOauth) {
            Write-Host " $($ser.Identity)"
            Write-Host -ForegroundColor Red "  WindowsAuthentication: $($ser.WindowsAuthentication)"
        }
        Write-Host -ForegroundColor White "  Should be True "
    }
    $html | Out-File -FilePath $htmlFile
}

function AvailabilityAddressSpaceCheckOAuth {
    Write-Host -ForegroundColor Green " Get-AvailabilityAddressSpace $ExchangeOnlineDomain | Select ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name"
    Write-Host $bar
    $AvailabilityAddressSpace = Get-AvailabilityAddressSpace $ExchangeOnlineDomain | Select-Object ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name
    $AAS = $AvailabilityAddressSpace | Format-List
    $AAS
    if ($Auth -contains "OAuth") {
    }
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - On-Prem Availability Address Space"
    Write-Host $bar
    Write-Host -ForegroundColor White " ForestName: "
    if ($AvailabilityAddressSpace.ForestName -like $ExchangeOnlineDomain) {
        Write-Host -ForegroundColor Green " "$AvailabilityAddressSpace.ForestName
        $tdAvailabilityAddressSpaceForestName = $AvailabilityAddressSpace.ForestName
        $tdAvailabilityAddressSpaceForestNameColor = "green"
    } else {
        Write-Host -ForegroundColor Red " ForestName is NOT correct. "
        Write-Host -ForegroundColor White " Should be $ExchangeOnlineDomain "
        $tdAvailabilityAddressSpaceForestName = $AvailabilityAddressSpace.ForestName
        $tdAvailabilityAddressSpaceForestNameColor = "red"
    }
    Write-Host -ForegroundColor White " UserName: "
    if ($AvailabilityAddressSpace.UserName -like "") {
        Write-Host -ForegroundColor Green "  Blank "
        $tdAvailabilityAddressSpaceUserName = "  Blank. This is the correct value. "
        $tdAvailabilityAddressSpaceUserNameColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  UserName is NOT correct. "
        Write-Host -ForegroundColor White "  Should be blank "
        $tdAvailabilityAddressSpaceUserName = "  Blank. This is the correct value. "
        $tdAvailabilityAddressSpaceUserNameColor = "red"
    }
    Write-Host -ForegroundColor White " UseServiceAccount: "
    if ($AvailabilityAddressSpace.UseServiceAccount -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $tdAvailabilityAddressSpaceUseServiceAccount = $AvailabilityAddressSpace.UseServiceAccount
        $tdAvailabilityAddressSpaceUseServiceAccountColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  UseServiceAccount is NOT correct."
        Write-Host -ForegroundColor White "  Should be True "
        $tdAvailabilityAddressSpaceUseServiceAccount = "$($tAvailabilityAddressSpace.UseServiceAccount). Should be True"
        $tdAvailabilityAddressSpaceUseServiceAccountColor = "red"
    }
    Write-Host -ForegroundColor White " AccessMethod: "
    if ($AvailabilityAddressSpace.AccessMethod -like "InternalProxy") {
        Write-Host -ForegroundColor Green "  InternalProxy "
        $tdAvailabilityAddressSpaceAccessMethod = $AvailabilityAddressSpace.AccessMethod
        $tdAvailabilityAddressSpaceAccessMethodColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  AccessMethod is NOT correct. "
        Write-Host -ForegroundColor White "  Should be InternalProxy "
        $tdAvailabilityAddressSpaceAccessMethod = $AvailabilityAddressSpace.AccessMethod
        $tdAvailabilityAddressSpaceAccessMethodColor = "red"
    }
    Write-Host -ForegroundColor White " ProxyUrl: "
    if ($AvailabilityAddressSpace.ProxyUrl -like $exchangeOnPremEWS) {
        Write-Host -ForegroundColor Green " "$AvailabilityAddressSpace.ProxyUrl
        $tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
        $tdAvailabilityAddressSpaceProxyUrlColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  ProxyUrl is NOT correct. "
        Write-Host -ForegroundColor White "  Should be $exchangeOnPremEWS"
        $tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
        $tdAvailabilityAddressSpaceProxyUrlColor = "red"
    }

    $Script:html += "
      <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-AvailabilityAddressSpace</th>
    </tr>
    <tr>
      <td><b>  Get-AvailabilityAddressSpace $ExchangeOnlineDomain | Select ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name</b></td>
      <td>
        <div><b>AddressSpaceForestName:</b><span style='color: $tdAvailabilityAddressSpaceForestNameColor'>$($tdAvailabilityAddressSpaceForestName)</span></div>
        <div><b>AddressSpaceUserName:</b><span style='color: $tdAvailabilityAddressSpaceUserNameColor'>$($tdAvailabilityAddressSpaceUserName)</span></div>
        <div><b>UseServiceAccount:</b><span style='color:$tdAvailabilityAddressSpaceUseServiceAccountColor;'>$( $tdAvailabilityAddressSpaceUseServiceAccount)</span></div>
        <div><b>AccessMethod:</b><span style='color: $tdAvailabilityAddressSpaceAccessMethodColor;'>$($tdAvailabilityAddressSpaceAccessMethod)</span></div>
        <div><b>ProxyUrl:</b><span style='color: $tdAvailabilityAddressSpaceProxyUrlColor;'>$($tdAvailabilityAddressSpaceProxyUrl)</span></div>


      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function OAuthConnectivityCheck {
    Write-Host -ForegroundColor Green " Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox $UserOnPrem"
    Write-Host $bar
    #$OAuthConnectivity = Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox $UserOnPrem | fl
    #$OAuthConnectivity
    $OAuthConnectivity = Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox $UserOnPrem
    if ($OAuthConnectivity.ResultType -eq 'Success' ) {
        #$OAuthConnectivity.ResultType
    } else {
        $OAuthConnectivity
    }
    #$OAC = $OAuthConnectivity | Format-List
    #$OAC
    #$bar
    #$OAuthConnectivity.Detail.FullId
    #$bar
    if ($OAuthConnectivity.Detail.FullId -like '*(401) Unauthorized*') {
        Write-Host -ForegroundColor Red "Error: The remote Server returned an error: (401) Unauthorized"
        if ($OAuthConnectivity.Detail.FullId -like '*The user specified by the user-context in the token does not exist*') {
            Write-Host -ForegroundColor Yellow "The user specified by the user-context in the token does not exist"
            Write-Host "Please run Test-OAuthConnectivity with a different Exchange On Premises Mailbox"
        }
    }

    # Write-Host $bar
    #$OAuthConnectivity.detail.LocalizedString
    Write-Host -ForegroundColor Green " Summary - Test OAuth Connectivity"
    Write-Host $bar
    if ($OAuthConnectivity.ResultType -like "Success") {
        Write-Host -ForegroundColor Green "$($OAuthConnectivity.ResultType). OAuth Test was completed successfully "
        $OAuthConnectivityResultType = " OAuth Test was completed successfully "
        $OAuthConnectivityResultTypeColor = "green"
    } else {
        Write-Host -ForegroundColor Red " $OAuthConnectivity.ResultType - OAuth Test was completed with Error. "
        Write-Host -ForegroundColor White " Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox <On Premises Mailbox> | fl to confirm the test failure"
        $OAuthConnectivityResultType = " <div>OAuth Test was completed with Error.</div><div>Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox <On Premises Mailbox> | fl to confirm the test failure</div>"
        $OAuthConnectivityResultTypeColor = "red"
    }
    #Write-Host -ForegroundColor Green " Note:"
    #Write-Host -ForegroundColor Yellow " You can ignore the warning 'The SMTP address has no mailbox associated with it'"
    #Write-Host -ForegroundColor Yellow " when the Test-OAuthConnectivity returns a Success"
    Write-Host -ForegroundColor Green " Reference: "
    Write-Host -ForegroundColor White " Configure OAuth authentication between Exchange and Exchange Online organizations"
    Write-Host -ForegroundColor Yellow " https://technet.microsoft.com/en-us/library/dn594521(v=exchg.150).aspx"

    $Script:html += "
      <tr>
      <th ColSpan='2' style='color:white;'>Summary - Test-OAuthConnectivity</th>
    </tr>
    <tr>
      <td><b>  Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox $UserOnPrem | fl</b></td>
      <td>
        <div><b>Result:</b><span style='color: $OAuthConnectivityResultTypeColor'> $OAuthConnectivityResultType</span></div>



      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

#endregion

# EXO FUNCTIONS

#region ExoDAuthFunctions

function ExoOrgRelCheck () {
    Write-Host $bar
    Write-Host -ForegroundColor Green " Get-OrganizationRelationship  | Where{($_.DomainNames -like $ExchangeOnPremDomain )} | Select Identity,DomainNames,FreeBusy*,TarGet*,Enabled"
    Write-Host $bar
    $ExoOrgRel
    Write-Host $bar
    Write-Host  -ForegroundColor Green " Summary - Organization Relationship"
    Write-Host $bar
    Write-Host  " Domain Names:"

    if ($exoOrgRel.DomainNames -like $ExchangeOnPremDomain) {
        Write-Host -ForegroundColor Green "  Domain Names Include the $ExchangeOnPremDomain Domain"
        $tdEXOOrgRelDomainNames = $exoOrgRel.DomainNames
        $tdEXOOrgRelDomainNamesColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Domain Names do Not Include the $ExchangeOnPremDomain Domain"
        $exoOrgRel.DomainNames

        $tdEXOOrgRelDomainNames = "$($exoOrgRel.DomainNames) - Domain Names do Not Include the $ExchangeOnPremDomain Domain"
        $tdEXOOrgRelDomainNamesColor = "green"
    }
    #FreeBusyAccessEnabled
    Write-Host  " FreeBusyAccessEnabled:"
    if ($exoOrgRel.FreeBusyAccessEnabled -like "True" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessEnabled is set to True"
        $tdEXOOrgRelFreeBusyAccessEnabled = "$($exoOrgRel.FreeBusyAccessEnabled)"
        $tdEXOOrgRelFreeBusyAccessEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  FreeBusyAccessEnabled : False"
        #$countOrgRelIssues++
        $tdEXOOrgRelFreeBusyAccessEnabled = "$($exoOrgRel.FreeBusyAccessEnabled). Free busy access is not enabled for the organization Relationship"
        $tdEXOOrgRelFreeBusyAccessEnabledColor = "Red"
    }
    #FreeBusyAccessLevel
    Write-Host  " FreeBusyAccessLevel:"
    if ($exoOrgRel.FreeBusyAccessLevel -like "AvailabilityOnly" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessLevel is set to AvailabilityOnly"
        $tdEXOOrgRelFreeBusyAccessLevel = "$($exoOrgRel.FreeBusyAccessLevel)"
        $tdEXOOrgRelFreeBusyAccessLevelColor = "green"
    }
    if ($exoOrgRel.FreeBusyAccessLevel -like "LimitedDetails" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessLevel is set to LimitedDetails"
        $tdEXOOrgRelFreeBusyAccessLevel = "$($exoOrgRel.FreeBusyAccessLevel)"
        $tdEXOOrgRelFreeBusyAccessLevelColor = "green"
    }

    if ($exoOrgRel.FreeBusyAccessLevel -NE "AvailabilityOnly" -AND $exoOrgRel.FreeBusyAccessLevel -NE "LimitedDetails") {
        Write-Host -ForegroundColor Red "  FreeBusyAccessEnabled : False"
        #$countOrgRelIssues++
        $tdEXOOrgRelFreeBusyAccessLevel = "$($exoOrgRel.FreeBusyAccessLevel)"
        $tdEXOOrgRelFreeBusyAccessLevelColor = "red"
    }
    #TarGetApplicationUri
    Write-Host  " TarGetApplicationUri:"
    # Write-Host $FedInfoTarGetApplicationUri
    $a = "FYDIBOHF25SPDLT." + $ExchangeOnPremDomain
    $HybridAgentTargetSharingEpr = "http://outlook.office.com/"
    $HATargetAutodiscoverEpr = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc/"
    #Write-Host $a

    if ($exoOrgRel.TarGetSharingEpr -like "*resource.mailboxMigration.his.MSAppProxy.net/EWS/Exchange.asmx") {
        if ($exoOrgRel.TarGetApplicationUri -like $HybridAgentTargetSharingEpr) {
            Write-Host -ForegroundColor Green "  TarGetApplicationUri is $($exoOrgRel.TarGetSharingEpr) . This is correct when Hybrid Agent is in use"
            $tdEXOOrgRelTarGetApplicationUri = "  TarGetApplicationUri is $($exoOrgRel.TarGetSharingEpr) . This is correct when Hybrid Agent is in use"
            $tdEXOOrgRelTarGetApplicationUriColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetApplicationUri should be  $HybridAgentTargetSharingEpr when Hybrid Agent is used"
            #$countOrgRelIssues++
            $tdEXOOrgRelTarGetApplicationUri = "  TarGetApplicationUri should be $HybridAgentTargetSharingEpr when Hybrid Agent is used. Please Check if Exchange On Premise Federation is correctly configured."
            $tdEXOOrgRelTarGetApplicationUriColor = "red"
        }
    } else {
        if ($exoOrgRel.TarGetApplicationUri -like $FedTrust.ApplicationUri) {
            Write-Host -ForegroundColor Green "  TarGetApplicationUri is" $FedTrust.ApplicationUri.OriginalString
            $tdEXOOrgRelTarGetApplicationUri = "  TarGetApplicationUri is $($FedTrust.ApplicationUri.OriginalString)"
            $tdEXOOrgRelTarGetApplicationUriColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetApplicationUri should be " $a
            #$countOrgRelIssues++
            $tdEXOOrgRelTarGetApplicationUri = "  TarGetApplicationUri should be $a. Please Check if Exchange On Premise Federation is correctly configured."
            $tdEXOOrgRelTarGetApplicationUriColor = "red"
        }
    }

    #TarGetSharingEpr
    Write-Host  " TarGetSharingEpr:"

    if ($exoOrgRel.TarGetSharingEpr -like "*resource.mailboxMigration.his.MsAppProxy.net/EWS/Exchange.asmx") {
        Write-Host -ForegroundColor Green "  TarGetSharingEpr is points to resource.mailboxMigration.his.MsAppProxy.net/EWS/Exchange.asmx. This means Hybrid Agent is in use."
        $tdEXOOrgRelTarGetSharingEpr = "TarGetSharingEpr is points to resource.mailboxMigration.his.MsAppProxy.net/EWS/Exchange.asmx. This means Hybrid Agent is in use."
        $tdEXOOrgRelTarGetSharingEprColor = "green"
    } else {
        if ([string]::IsNullOrWhitespace($exoOrgRel.TarGetSharingEpr)) {
            Write-Host -ForegroundColor Green "  TarGetSharingEpr is blank. This is the standard Value."
            $tdEXOOrgRelTarGetSharingEpr = "TarGetSharingEpr is blank. This is the standard Value."
            $tdEXOOrgRelTarGetSharingEprColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetSharingEpr should be blank. If it is set, it should be the On-Premises Exchange Servers EWS ExternalUrl endpoint."
            #$countOrgRelIssues++
            $tdEXOOrgRelTarGetSharingEpr = "  TarGetSharingEpr should be blank. If it is set, it should be the On-Premises Exchange Servers EWS ExternalUrl endpoint."
            $tdEXOOrgRelTarGetSharingEprColor = "red"
        }
    }
    #TarGetAutoDiscoverEpr:
    Write-Host  " TarGetAutoDiscoverEpr:"
    #Write-Host  "  OrgRel: " $exoOrgRel.TarGetAutoDiscoverEpr
    #Write-Host  "  FedInfo: " $FedInfoEOP
    #Write-Host  "  FedInfoEPR: " $FedInfoEOP.TarGetAutoDiscoverEpr

    if ($exoOrgRel.TarGetSharingEpr -like "*resource.mailboxMigration.his.MSAppProxy.net/EWS/Exchange.asmx") {

        if ($exoOrgRel.TarGetAutoDiscoverEpr -like $HATargetAutodiscoverEpr) {
            Write-Host -ForegroundColor Green "  TarGetAutoDiscoverEpr is $($exoOrgRel.TarGetAutoDiscoverEpr) . This is correct when Hybrid Agent is in use"

            $tdEXOOrgRelTarGetAutoDiscoverEpr = "TarGetAutoDiscoverEpr is $($exoOrgRel.TarGetAutoDiscoverEpr) . This is correct when Hybrid Agent is in use"
            $tdEXOOrgRelTarGetAutoDiscoverEprColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetAutoDiscoverEpr is not $HATargetAutodiscoverEpr . This is the correct  value when Hybrid Agent is in use."
            #$countOrgRelIssues++
            $tdEXOOrgRelTarGetAutoDiscoverEpr = "  TarGetAutoDiscoverEpr is not $HATargetAutodiscoverEpr. This is the correct  value when Hybrid Agent is in use."
            $tdEXOOrgRelTarGetAutoDiscoverEprColor = "red"
        }
    }

    else {

        if ($exoOrgRel.TarGetAutoDiscoverEpr -like $FedInfoEOP.TarGetAutoDiscoverEpr) {
            Write-Host -ForegroundColor Green "  TarGetAutoDiscoverEpr is" $exoOrgRel.TarGetAutoDiscoverEpr

            $tdEXOOrgRelTarGetAutoDiscoverEpr = $exoOrgRel.TarGetAutoDiscoverEpr
            $tdEXOOrgRelTarGetAutoDiscoverEprColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetAutoDiscoverEpr is not" $FedInfoEOP.TarGetAutoDiscoverEpr
            #$countOrgRelIssues++
            $tdEXOOrgRelTarGetAutoDiscoverEpr = "  TarGetAutoDiscoverEpr is not $($FedInfoEOP.TarGetAutoDiscoverEpr)"
            $tdEXOOrgRelTarGetAutoDiscoverEprColor = "red"
        }
    }

    #Enabled
    Write-Host  " Enabled:"
    if ($exoOrgRel.enabled -like "True" ) {
        Write-Host -ForegroundColor Green "  Enabled is set to True"
        $tdEXOOrgRelEnabled = "  True"
        $tdEXOOrgRelEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Enabled is set to False."
        $tdEXOOrgRelEnabled = "  False"
        $tdEXOOrgRelEnabledColor = "red"
    }

    $script:html += "

    <div class='Black'><p></p></div>
    <div class='Black'><p></p></div>


     <tr>
        <th ColSpan='2' style='text-align:center; color:white;'>Exchange Online DAuth Configuration</th>
     </tr>
      <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-OrganizationRelationship</th>
    </tr>
    <tr>
      <td><b>  Get-OrganizationRelationship  | Where{($_.DomainNames -like $ExchangeOnPremDomain )} | Select Identity,DomainNames,FreeBusy*,TarGet*,Enabled</b></td>
      <td>
        <div><b>Domain Names:</b><span >$($tdEXOOrgRelDomainNames)</span></div>
        <div><b>FreeBusyAccessEnabled:</b><span style='color: $tdEXOOrgRelFreeBusyAccessEnabledColor'>$($tdEXOOrgRelFreeBusyAccessEnabled)</span></div>
        <div><b>FreeBusyAccessLevel::</b><span style='color:$tdEXOOrgRelFreeBusyAccessLevelColor;'>$( $tdEXOOrgRelFreeBusyAccessLevel)</span></div>
        <div><b>TarGetApplicationUri:</b><span style='color: $tdEXOOrgRelTarGetApplicationUriColor;'>$($tdEXOOrgRelTarGetApplicationUri)</span></div>
        <div><b>TarGetOwAUrl:</b><span >$($tdEXOOrgRelTarGetOwAUrl)</span></div>
        <div><b>TarGetSharingEpr:</b><span style='color: $tdEXOOrgRelTarGetSharingEprColor'>$($tdEXOOrgRelTarGetSharingEpr)</span></div>
        <div><b>TarGetAutoDiscoverEpr:</b><span style='color:$tdEXOOrgRelFreeBusyAccessScopeColor;'>$( $tdEXOOrgRelFreeBusyAccessScope)</span></div>
        <div><b>Enabled:</b><span style='color: $tdEXOOrgRelEnabledColor;'>$($tdEXOOrgRelEnabled)</span></div>


      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function EXOFedOrgIdCheck {
    Write-Host -ForegroundColor Green " Get-FederatedOrganizationIdentifier | select AccountNameSpace,Domains,Enabled"
    Write-Host $bar
    $exoFedOrgId = Get-FederatedOrganizationIdentifier | Select-Object AccountNameSpace, Domains, Enabled
    #$IntraOrgConCheck
    $eFedOrgID = $exoFedOrgId | Format-List
    $eFedOrgID
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Online Federated Organization Identifier"
    Write-Host $bar
    Write-Host -ForegroundColor White " Domains: "
    if ($exoFedOrgId.Domains -like "*$ExchangeOnlineDomain*") {
        Write-Host -ForegroundColor Green " " $exoFedOrgId.Domains
        $tdEXOFedOrgIdDomains = $exoFedOrgId.Domains
        $tdEXOFedOrgIdDomainsColor = "green"
    } else {
        Write-Host -ForegroundColor Red " Domains are NOT correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnlineMDomain"
        $tdEXOFedOrgIdDomains = "$($exoFedOrgId.Domains) . Domains Should contain the $ExchangeOnlineMDomain"
        $tdEXOFedOrgIdDomainsColor = "red"
    }
    Write-Host -ForegroundColor White " Enabled: "
    if ($exoFedOrgId.Enabled -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $tdEXOFedOrgIdEnabled = $exoFedOrgId.Enabled
        $tdEXOFedOrgIdEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Enabled is NOT correct."
        Write-Host -ForegroundColor White " Should be True"
        $tdEXOFedOrgIdEnabled = $exoFedOrgId.Enabled
        $tdEXOFedOrgIdEnabledColor = "green"
    }

    $script:html += "
    <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-FederatedOrganizationIdentifier</th>
    </tr>
    <tr>
      <td><b>  Get-FederatedOrganizationIdentifier | select AccountNameSpace,Domains,Enabled</b></td>
      <td>
        <div><b>Domains:</b><span style='color: $tdEXOFedOrgIdDomainsColor;'>$($tdEXOFedOrgIdDomains)</span></div>
        <div><b>Enabled:</b><span style='color: $tdEXOFedOrgIdEnabledColor;'>$($tdEXOFedOrgIdEnabled)</span></div>


      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function ExoTestOrgRelCheck {
    $exoIdentity = $ExoOrgRel.Identity

    $exoOrgRelTarGetApplicationUri = $exoOrgRel.TarGetApplicationUri
    $exoOrgRelTarGetOWAUrl = $ExoOrgRel.TarGetOwAUrl

    $script:html += "
        <tr>
            <th ColSpan='2' style='color:white;'>Summary - Test-OrganizationRelationship</th>
        </tr>
        <tr>
            <td><b>  Test-OrganizationRelationship -Identity $exoIdentity -UserIdentity $UserOnline</b></td>
        <td>"

    Write-Host -ForegroundColor Green " Test-OrganizationRelationship -Identity $exoIdentity -UserIdentity $UserOnline"
    Write-Host $bar

    if ((![string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) -and (![string]::IsNullOrWhitespace($exoOrgRelTarGetOWAUrl))) {
        $ExoTestOrgRel = Test-OrganizationRelationship -Identity $exoIdentity -UserIdentity $UserOnline -WarningAction SilentlyContinue

        $i = 2

        while ($i -lt $ExoTestOrgRel.Length) {
            $element = $ExoTestOrgRel[$i]

            $aux = "0"

            if ($element -like "*RESULT:*" -and $aux -like "0") {
                $el = $element.TrimStart()
                if ($element -like "*Success.*") {
                    Write-Host -ForegroundColor Green "  $el"
                    $Script:html += "
            <div> <b> $ExoTestOrgRelStep </b> <span style='color:green'>&EmSp;; $el</span>"
                    $aux = "1"
                } elseif ($element -like "*Error*" -or $element -like "*Unable*") {
                    $Script:html += "
                <div> <b> $ExoTestOrgRelStep </b> <span style='color:red'>&EmSp;; $el</span>"
                    Write-Host -ForegroundColor Red "  $el"
                    $aux = "1"
                }
            } elseif ($aux -like "0" ) {
                if ($element -like "*STEP*" -or $element -like "*Complete*") {
                    Write-Host -ForegroundColor White "  $element"
                    $Script:html += "
               <p></p>
                <div> <b> $ExoTestOrgRelStep </b> <span style='color:black'> $element</span></div>"
                    $aux = "1"
                } else {
                    $ID = $element.ID
                    $Status = $element.Status
                    $Description = $element.Description
                    if (![string]::IsNullOrWhitespace($ID)) {
                        Write-Host -ForegroundColor White "`n  ID         : $ID"
                        $Script:html += "<div> <b>&EmSp;; ID &EmSp;;&EmSp;;&EmSp;;&EmSp;;&EmSp;;&NbSp;:</b> <span style='color:black'> $ID</span></div>"
                        if ($Status -like "*Success*") {
                            Write-Host -ForegroundColor White "  Status     : $Status"
                            $Script:html += "<div> <b>&EmSp;; Status &EmSp;;&EmSp;;&EnSp;;&EnSp;;:</b> <span style='color:green'> $Status</span></div>"
                        }

                        if ($status -like "*error*") {
                            Write-Host -ForegroundColor White "  Status     : $Status"
                            $Script:html += "<div> <b>&EmSp;; Status &EmSp;;&EmSp;;&EnSp;;&EnSp;;:</b> <span style='color:red'> $Status</span></div>"
                        }

                        Write-Host -ForegroundColor White "  Description: $Description"
                        Write-Host -ForegroundColor yellow "  Note: Test-Organization Relationship fails on Step 3 with error MismatchedFederation if Hybrid Agent is in use"
                        $Script:html += "<div> <b>&EmSp;; Description :</b> <span style='color:black'> $Description</span></div>
                        <div><span style='color:yellow'>Note: Test-Organization Relationship fails on Step 3 with error MismatchedFederation if Hybrid Agent is in use</span></div>"
                    }
                    #$element
                    $aux = "1"
                }
            }

            $i++
        }
    }

    elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) -and ([string]::IsNullOrWhitespace($exoOrgRelTarGetOWAUrl)))) {
        <# Action when all if and elseif conditions are false #>
        Write-Host -ForegroundColor Red "  Error: Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri and TarGetOwAUrl are not set"
        $Script:html += "
    <div> <span style='color:red'>&EmSp;; Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri and TarGetOwAUrl are not set</span>"
    } elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) )) {
        <# Action when all if and elseif conditions are false #>
        Write-Host -ForegroundColor Red "  Error: Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri is not set"
        $Script:html += "
    <div> <span style='color:red'>&EmSp;; Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri is not set</span>"
    } elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) )) {
        <# Action when all if and elseif conditions are false #>
        Write-Host -ForegroundColor Red "  Error: Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetOwAUrl is not set"
        $Script:html += "
    <div> <span style='color:red'>&EmSp;; Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri is not set</span>"
    }

    $Script:html += "</td>
    </tr>"

    $html | Out-File -FilePath $htmlFile
}

function SharingPolicyCheck {
    Write-Host $bar
    Write-Host -ForegroundColor Green " Get-SharingPolicy | select Domains,Enabled,Name,Identity"
    Write-Host $bar
    $Script:SPOnline = Get-SharingPolicy | Select-Object  Domains, Enabled, Name, Identity
    $SPOnline | Format-List

    #creating variables and setting uniform variable names
    $domain1 = (($SPOnline.domains[0] -split ":") -split " ")
    $domain2 = (($SPOnline.domains[1] -split ":") -split " ")
    $SPOnpremDomain1 = $SPOnprem.Domains.Domain[0]
    $SPOnpremAction1 = $SPOnprem.Domains.Actions[0]
    $SPOnpremDomain2 = $SPOnprem.Domains.Domain[1]
    $SPOnpremAction2 = $SPOnprem.Domains.Actions[1]
    $SPOnlineDomain1 = $domain1[0]
    $SPOnlineAction1 = $domain1[1]
    $SPOnlineDomain2 = $domain2[0]
    $SPOnlineAction2 = $domain2[1]

    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Sharing Policy"
    Write-Host $bar
    Write-Host -ForegroundColor White " Exchange On Premises Sharing domains:`n"
    Write-Host -ForegroundColor White "  Domain:"
    Write-Host "   " $SPOnpremDomain1
    Write-Host -ForegroundColor White "  Action:"
    Write-Host "   " $SPOnpremAction1
    Write-Host -ForegroundColor White "  Domain:"
    Write-Host "   " $SPOnpremDomain2
    Write-Host -ForegroundColor White "  Action:"
    Write-Host "   " $SPOnpremAction2
    Write-Host -ForegroundColor White "`n  Exchange Online Sharing Domains: `n"
    Write-Host -ForegroundColor White "  Domain:"
    Write-Host "   " $SPOnlineDomain1
    Write-Host -ForegroundColor White "  Action:"
    Write-Host "   " $SPOnlineAction1
    Write-Host -ForegroundColor White "  Domain:"
    Write-Host "   " $SPOnlineDomain2
    Write-Host -ForegroundColor White "  Action:"
    Write-Host "   " $SPOnlineAction2
    #Write-Host $bar

    if ($SPOnpremDomain1 -eq $SPOnlineDomain1 -and $SPOnpremAction1 -eq $SPOnlineAction1) {
        if ($SPOnpremDomain2 -eq $SPOnlineDomain2 -and $SPOnpremAction2 -eq $SPOnlineAction2) {
            Write-Host -ForegroundColor Green "`n  Exchange Online Sharing Policy Domains match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy matches Exchange On Premise Sharing Policy Domain"
            $tdSharpingPolicyCheckColor = "green"
        }

        else {
            Write-Host -ForegroundColor Red "`n   Sharing Domains appear not to be correct."
            Write-Host -ForegroundColor White "   Exchange Online Sharing Policy Domains appear not to match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy Domains not match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheckColor = "red"
        }
    } elseif ($SPOnpremDomain1 -eq $SPOnlineDomain2 -and $SPOnpremAction1 -eq $SPOnlineAction2) {
        if ($SPOnpremDomain2 -eq $SPOnlineDomain1 -and $SPOnpremAction2 -eq $SPOnlineAction1) {
            Write-Host -ForegroundColor Green "`n  Exchange Online Sharing Policy Domains match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy matches Exchange On Premise Sharing Policy Domain"
            $tdSharpingPolicyCheckColor = "green"
        }

        else {
            Write-Host -ForegroundColor Red "`n   Sharing Domains appear not to be correct."
            Write-Host -ForegroundColor White "   Exchange Online Sharing Policy Domains appear not to match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy Domains not match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheckColor = "red"
        }
    } else {
        Write-Host -ForegroundColor Red "`n   Sharing Domains appear not to be correct."
        Write-Host -ForegroundColor White "   Exchange Online Sharing Policy Domains appear not to match Exchange On Premise Sharing Policy Domains"
        $tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy Domains not match Exchange On Premise Sharing Policy Domains"
        $tdSharpingPolicyCheckColor = "red"
    }

    $bar

    $script:html += "
    <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-SharingPolicy</th>
    </tr>
    <tr>
      <td><b>  Get-SharingPolicy | select Domains,Enabled,Name,Identity</b></td>
      <td>
        <div><b>Exchange On Premises Sharing domains:<b></div>
        <div><b>Domain:</b>$($SPOnprem.Domains.Domain[0])</div>
        <div><b>Action:</b>$($SPOnprem.Domains.Actions[0])</div>
        <div><b>Domain:</b>$($SPOnprem.Domains.Domain[1])</div>
        <div><b>Action:</b>$($SPOnprem.Domains.Actions[1])</div>
        <div><p></p></div>
        <div><b>Exchange Online Sharing domains:<b></div>
        <div><b>Domain:</b>$($domain1[0])</div>
        <div><b>Action:</b>$( $domain1[1])</div>
        <div><b>Domain:</b>$($domain2[0])</div>
        <div><b>Action:</b>$( $domain2[1])</div>
        <div><p></p></div>
        <div><b>Sharing Policy - Exchange Online vs Exchange On Premise:<b></div>
        <div><span style='color: $tdSharpingPolicyCheckColor;'>$($tdSharpingPolicyCheck)</span></div>

      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

#endregion

#region ExoOauthFunctions

function EXOIntraOrgConCheck {
    Write-Host $bar
    Write-Host -ForegroundColor Green " Get-IntraOrganizationConnector | Select TarGetAddressDomains,DiscoveryEndpoint,Enabled"
    Write-Host $bar
    $exoIntraOrgCon = Get-IntraOrganizationConnector | Select-Object TarGetAddressDomains, DiscoveryEndpoint, Enabled
    #$IntraOrgConCheck
    $IOC = $exoIntraOrgCon | Format-List
    $IOC
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Online Intra Organization Connector"
    Write-Host $bar
    Write-Host -ForegroundColor White " TarGet Address Domains: "
    if ($exoIntraOrgCon.TarGetAddressDomains -like "*$ExchangeOnpremDomain*") {
        Write-Host -ForegroundColor Green " " $exoIntraOrgCon.TarGetAddressDomains
        $tdEXOIntraOrgConTarGetAddressDomains = $exoIntraOrgCon.TarGetAddressDomains
        $tdEXOIntraOrgConTarGetAddressDomainsColor = "green"
    } else {
        Write-Host -ForegroundColor Red " TarGet Address Domains is NOT correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnpremDomain"
        $tdEXOIntraOrgConTarGetAddressDomains = " $($exoIntraOrgCon.TarGetAddressDomains) . Should contain the $ExchangeOnpremDomain"
        $tdEXOIntraOrgConTarGetAddressDomainsColor = "red"
    }
    Write-Host -ForegroundColor White " DiscoveryEndpoint: "
    if ($exoIntraOrgCon.DiscoveryEndpoint -like $EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint) {
        Write-Host -ForegroundColor Green $exoIntraOrgCon.DiscoveryEndpoint
        $tdEXOIntraOrgConDiscoveryEndpoints = $exoIntraOrgCon.DiscoveryEndpoint
        $tdEXOIntraOrgConDiscoveryEndpointsColor = "green"
    } else {
        if ($exoIntraOrgCon.DiscoveryEndpoint -like "*resource.mailboxMigration.his.MSAppProxy.net*") {
            Write-Host -ForegroundColor Green " " $exoIntraOrgCon.DiscoveryEndpoint
            Write-Host -ForegroundColor Yellow " Discovery Endpoint includes resource.mailboxMigration.his.MSAppProxy.net. Hybrid configuration is implemented using Hybrid Agent "
            $tdEXOIntraOrgConDiscoveryEndpoints = $exoIntraOrgCon.DiscoveryEndpoint
            $tdEXOIntraOrgConDiscoveryEndpointsColor = "green"
        } else {
            Write-Host -ForegroundColor Red " DiscoveryEndpoint is NOT correct. "
            Write-Host -ForegroundColor White "  Should be " $EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint
            $tdEXOIntraOrgConDiscoveryEndpoints = "$($exoIntraOrgCon.DiscoveryEndpoint) . Should be $($EDiscoveryEndpoint.OnPremiseDiscoveryEndpoint)"
            $tdEXOIntraOrgConDiscoveryEndpointsColor = "red"
        }
    }
    Write-Host -ForegroundColor White " Enabled: "
    if ($exoIntraOrgCon.Enabled -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $tdEXOIntraOrgConEnabled = "True"
        $tdEXOIntraOrgConEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  False."
        Write-Host -ForegroundColor White " Should be True"
        $tdEXOIntraOrgConEnabled = "False . Should be True"
        $tdEXOIntraOrgConEnabledColor = "red"
    }

    $script:html += "
    <tr>
      <th ColSpan='2' style='text-align:center; color:white;'><b>Exchange Online OAuth Configuration</b></th>
    </tr>
    <tr>
      <th ColSpan='2' style=' color:white;'><b>Summary - Get-IntraOrganizationConnector</b></th>
    </tr>
    <tr>
      <td><b>  Get-IntraOrganizationConnector | Select-Object TarGetAddressDomains, DiscoveryEndpoint, Enabled</b></td>
      <td>
        <div><b>TarGet Address Domains:</b><span style='color: $tdEXOIntraOrgConTarGetAddressDomainsColor;'>' $($tdEXOIntraOrgConTarGetAddressDomains)'</span></div>
        <div><b>DiscoveryEndpoint:</b><span style='color: $tdEXOIntraOrgConDiscoveryEndpointsColor;'>' $($tdEXOIntraOrgConDiscoveryEndpoints)'</span></div>
        <div><b>Enabled:</b><span style='color:$tdEXOIntraOrgConEnabledColor;'> $($tdEXOIntraOrgConEnabled)</span></div>

      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function EXOIntraOrgConfigCheck {
    Write-Host -ForegroundColor Green " Get-IntraOrganizationConfiguration | Select OnPremiseTarGetAddresses"
    Write-Host $bar
    #fix because there can be multiple on prem or guid's
    #$exoIntraOrgConfig = Get-OnPremisesOrganization | select OrganizationGuid | Get-IntraOrganizationConfiguration | Select OnPremiseTarGetAddresses
    $exoIntraOrgConfig = Get-OnPremisesOrganization | Select-Object OrganizationGuid | Get-IntraOrganizationConfiguration | Select-Object * | Where-Object { $_.OnPremiseTarGetAddresses -like "*$ExchangeOnPremDomain*" }
    #$IntraOrgConCheck
    $IOConfig = $exoIntraOrgConfig | Format-List
    $IOConfig
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Exchange Online Intra Organization Configuration"
    Write-Host $bar
    Write-Host -ForegroundColor White " OnPremiseTarGetAddresses: "
    if ($exoIntraOrgConfig.OnPremiseTarGetAddresses -like "*$ExchangeOnpremDomain*") {
        Write-Host -ForegroundColor Green " " $exoIntraOrgConfig.OnPremiseTarGetAddresses
        $tdEXOIntraOrgConfigOnPremiseTarGetAddresses = $exoIntraOrgConfig.OnPremiseTarGetAddresses
        $tdEXOIntraOrgConfigOnPremiseTarGetAddressesColor = "green"
    } else {
        Write-Host -ForegroundColor Red " OnPremise TarGet Addresses are NOT correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnpremDomain"
        $tdEXOIntraOrgConfigOnPremiseTarGetAddresses = $exoIntraOrgConfig.OnPremiseTarGetAddresses
        $tdEXOIntraOrgConfigOnPremiseTarGetAddressesColor = "red"
    }

    $script:html += "

    <tr>
      <th ColSpan='2' style=color:white;'><b>Summary - Get-IntraOrganizationConfiguration</b></th>
    </tr>
    <tr>
      <td><b>  Get-IntraOrganizationConfiguration | Select OnPremiseTarGetAddresses</b></td>
      <td>
        <div><b>OnPremiseTarGetAddresses:</b><span style='color: $tdEXOIntraOrgConfigOnPremiseTarGetAddressesColor;'>$($tdEXOIntraOrgConfigOnPremiseTarGetAddresses)</span></div>

      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function EXOAuthServerCheck {
    Write-Host -ForegroundColor Green " Get-AuthServer -Identity 00000001-0000-0000-c000-000000000000 | select name,IssuerIdentifier,enabled"
    Write-Host $bar
    $exoAuthServer = Get-AuthServer -Identity 00000001-0000-0000-c000-000000000000 | Select-Object name, IssuerIdentifier, enabled
    #$IntraOrgConCheck
    $AuthServer = $exoAuthServer | Format-List
    $AuthServer
    $tdEXOAuthServerName = $exoAuthServer.Name
    Write-Host $bar
    Write-Host -ForegroundColor Green " Summary - Exchange Online Authorization Server"
    Write-Host $bar
    Write-Host -ForegroundColor White " IssuerIdentifier: "
    if ($exoAuthServer.IssuerIdentifier -like "00000001-0000-0000-c000-000000000000") {
        Write-Host -ForegroundColor Green " " $exoAuthServer.IssuerIdentifier
        $tdEXOAuthServerIssuerIdentifier = $exoAuthServer.IssuerIdentifier
        $tdEXOAuthServerIssuerIdentifierColor = "green"
        if ($exoAuthServer.Enabled -like "True") {
            Write-Host -ForegroundColor Green "  True "
            $tdEXOAuthServerEnabled = $exoAuthServer.Enabled
            $tdEXOAuthServerEnabledColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  Enabled is NOT correct."
            Write-Host -ForegroundColor White " Should be True"
            $tdEXOAuthServerEnabled = "$($exoAuthServer.Enabled) . Should be True"
            $tdEXOAuthServerEnabledColor = "red"
        }
    } else {
        Write-Host -ForegroundColor Red " Authorization Server object is NOT correct."
        Write-Host -ForegroundColor White " Enabled: "
        $tdEXOAuthServerIssuerIdentifier = "$($exoAuthServer.IssuerIdentifier) - Authorization Server object should be 00000001-0000-0000-c000-000000000000"
        $tdEXOAuthServerIssuerIdentifierColor = "red"

        if ($exoAuthServer.Enabled -like "True") {
            Write-Host -ForegroundColor Green "  True "
            $tdEXOAuthServerEnabled = $exoAuthServer.Enabled
            $tdEXOAuthServerEnabledColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  Enabled is NOT correct."
            Write-Host -ForegroundColor White " Should be True"
            $tdEXOAuthServerEnabled = "$($exoAuthServer.Enabled) . Should be True"
            $tdEXOAuthServerEnabledColor = "red"
        }
    }

    $script:html += "

    <tr>
      <th ColSpan='2' style='color:white;'>Summary - Get-AuthServer</th>
    </tr>
    <tr>
      <td><b>  Get-AuthServer -Identity 00000001-0000-0000-c000-000000000000 | select name,IssuerIdentifier,enabled</b></td>
      <td>
        <div><b>Name:</b><span style='color: $tdEXOAuthServerNameColor;'>$($tdEXOAuthServerName)</span></div>
        <div><b>IssuerIdentifier:</b><span style='color: $tdEXOAuthServerIssuerIdentifierColor;'>$($tdEXOAuthServerIssuerIdentifier)</span></div>
        <div><b>Enabled:</b><span style='color: $tdEXOAuthServerEnabledColor;'>$($tdEXOAuthServerEnabled)</span></div>

      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

function ExoTestOAuthCheck {
    Write-Host -ForegroundColor Green " Test-OAuthConnectivity -Service EWS -TarGetUri $Script:ExchangeOnPremEWS -Mailbox $UserOnline "
    Write-Host $bar
    $ExoTestOAuth = Test-OAuthConnectivity -Service EWS -TarGetUri $Script:ExchangeOnPremEWS -Mailbox $UserOnline
    if ($ExoTestOAuth.ResultType.Value -like 'Success' ) {
        #$ExoTestOAuth.ResultType.Value

        $tdOAuthConnectivityResultType = "$($ExoTestOAuth.ResultType.Value) - OAuth Test was completed successfully"
        $tdOAuthConnectivityResultTypeColor = "green"
    } else {
        $ExoTestOAuth | Format-List
        $tdOAuthConnectivityResultType = "$($ExoTestOAuth.ResultType) - OAuth Test was completed with Error. Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri <EWS target URI> -Mailbox <On Premises Mailbox> | fl to confirm the test failure"
        $tdOAuthConnectivityResultTypeColor = "red"
    }

    if ($ExoTestOAuth.Detail.FullId -like '*(401) Unauthorized*') {
        Write-Host -ForegroundColor Red "The remote Server returned an error: (401) Unauthorized"
    }

    if ($ExoTestOAuth.Detail.FullId -like '*The user specified by the user-context in the token does not exist*') {
        Write-Host -ForegroundColor Yellow "The user specified by the user-context in the token does not exist"
        Write-Host "Please run Test-OAuthConnectivity with a different Exchange Online Mailbox"
    }

    if ($ExoTestOAuth.Detail.FullId -like '*error_category="invalid_token"*') {
        Write-Host -ForegroundColor Yellow "This token profile 'S2SAppActAs' is not applicable for the current protocol"
    }
    #Write-Host $bar
    #$OAuthConnectivity.detail.LocalizedString
    Write-Host -ForegroundColor Green " Summary - Test-OAuthConnectivity"
    Write-Host $bar
    if ($ExoTestOAuth.ResultType.value -like "Success") {
        Write-Host -ForegroundColor Green " OAuth Test was completed successfully "
        $tdOAuthConnectivityResultType = "  OAuth Test was completed successfully"
        $tdOAuthConnectivityResultTypeColor = "green"
    } else {
        Write-Host -ForegroundColor Red " OAuth Test was completed with Error. "
        Write-Host -ForegroundColor White " Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri <EWS tarGet URI> -Mailbox <On Premises Mailbox> | fl to confirm the test failure"
        $tdOAuthConnectivityResultType = "$($ExoTestOAuth.ResultType) - OAuth Test was completed with Error. Please rerun Test-OAuthConnectivity -Service EWS -TarGetUri <EWS tarGet URI> -Mailbox <On Premises Mailbox> | fl to confirm the test failure"
        $tdOAuthConnectivityResultTypeColor = "red"
    }

    #Write-Host -ForegroundColor Yellow "NOTE: You can ignore the warning 'The SMTP address has no mailbox associated with it'"
    #Write-Host -ForegroundColor Yellow " when the Test-OAuthConnectivity returns a Success"
    Write-Host -ForegroundColor Green "`n References: "
    Write-Host -ForegroundColor White " Configure OAuth authentication between Exchange and Exchange Online organizations"
    Write-Host -ForegroundColor Yellow " https://technet.microsoft.com/en-us/library/dn594521(v=exchg.150).aspx"

    $script:html += "

    <tr>
      <th ColSpan='2' style='color:white;'><b>Summary - Test-OAuthConnectivity</b></th>
    </tr>
    <tr>
      <td><b>  Test-OAuthConnectivity -Service EWS -TarGetUri $($Script:ExchangeOnPremEWS) -Mailbox $UserOnline </b></td>
      <td>
        <div><b>Result:</b><span style='color: $tdOAuthConnectivityResultTypeColor;'>$($tdOAuthConnectivityResultType)</span></div>

      </td>
    </tr>
  "

    $html | Out-File -FilePath $htmlFile
}

#endregion
#cls
$IntraOrgCon = Get-IntraOrganizationConnector -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object Name, TarGetAddressDomains, DiscoveryEndpoint, Enabled
#if($Auth -contains "DAuth" -and $IntraOrgCon.enabled -Like "True")

ShowParameters

if ($IntraOrgCon.enabled -Like "True") {
    Write-Host $bar

    if ($Auth -Like "DAuth") {
        Write-Host -ForegroundColor yellow "  Warning: Intra Organization Connector Enabled True -> Running for DAuth only as -Auth DAuth option was selected`n  "
        if ($OrgRel.enabled -Like "True") {
            Write-Host -ForegroundColor White "           Organization Relationship Enabled True `n  "
        }

        Write-Host -ForegroundColor White "      This script can be Run using the -Auth All parameter to Check for both OAuth and DAuth configuration. `n `n         Example: ./FreeBusyChecker.ps1 -Auth All"
        $Script:html += "
                        <div  style = 'padding-left: 0%;'>
                          <h3>Intra Organization Connector Enabled: <b>True</b></h3>
                          <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking DAuth only as -Auth DAuth option was selected</span></p>

                        </div>

                        <div  style = 'padding-left: 0%;'>

                          <ul>
                            <li>
                              This script can be run using the <b>-Auth OAuth</b> parameter to Check for DAuth configurations only.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth OAuth

                              </span>
                            </li>
                            <br />
                            <li>

                              This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                              <span style='padding:2%;'>
                            </li>
                          </ul>
                        </div>
    "
        $html | Out-File -FilePath $htmlFile
    }
    if ($Auth -Like "") {

        $Auth = "OAuth"
        Write-Host -ForegroundColor White "    -> Free Busy Lookup is done using OAuth when the Intra Organization Connector is Enabled"
        Write-Host -ForegroundColor White "    -> Running for OAuth only as OAuth takes precedence over DAuth;"
        Write-Host -ForegroundColor White "`n         This script can be Run using the -Auth All parameter to Check for both OAuth and DAuth configuration. `n `n         Example: ./FreeBusyChecker.ps1 -Auth All"
        Write-Host -ForegroundColor White "`n         This script can be Run using the -Auth DAuth parameter to Check for DAuth configuration only. `n `n         Example: ./FreeBusyChecker.ps1 -Auth DAuth"
        $Script:html += "
                        <div  style = 'padding-left: 0%;'>
                          <h3>Intra Organization Connector Enabled: <b>True</b></h3>
                          <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking OAuth only as Free Busy Lookup is done using OAuth when the Intra Organization Connector is Enabled</span></p>

                        </div>

                        <div  style = 'padding-left: 0%;'>

                          <ul>
                            <li>
                              This script can be run using the <b>-Auth DAuth</b> parameter to Check for DAuth configurations only.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth DAuth

                              </span>
                            </li>
                            <br />
                            <li>

                              This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                              <span style='padding:2%;'>
                            </li>
                          </ul>
                        </div>
    "
        $html | Out-File -FilePath $htmlFile
    }
    if ($Auth -Like "All") {

        $Auth = ""
        Write-Host -ForegroundColor White "    -> Free Busy Lookup is done using OAuth when the Intra Organization Connector is Enabled"
        Write-Host -ForegroundColor White "    -> Checking both OAuth and DAuth as -Auth All option was selected"

        $Script:html += "
                        <div  style = 'padding-left: 0%;'>

                          <h3>Intra Organization Connector Enabled: <b>True</b></h3>

                          <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking both OAuth and DAuth as -Auth All option was selected</span></p>

                        </div>

                        <div  style = 'padding-left: 0%;'>

                          <ul>
                            <li>
                              This script can be run using the <b>-Auth DAuth</b> parameter to Check for DAuth configurations only.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth DAuth

                              </span>
                            </li>
                            <br />
                            <li>

                              This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                              <span style='padding:2%;'>
                            </li>
                          </ul>
                        </div>
    "
        $html | Out-File -FilePath $htmlFile
    }
}

if ($IntraOrgCon.enabled -Like "False") {
    if ($Auth -like "" -or $Auth -like "DAuth") {

        Write-Host $bar
        Write-Host -ForegroundColor yellow "  Warning: Intra Organization Connector Enabled False -> Running for DAuth only as OAuth is not enabled"
        Write-Host -ForegroundColor White "`n       This script can be Run using the '-Auth OAuth' parameter to Check for OAuth configurations only. `n"
        Write-Host -ForegroundColor White "             Example: ./FreeBusyChecker.ps1 -Auth OAuth"
        Write-Host -ForegroundColor White "`n       This script can be Run using the '-Auth All' parameter to Check for both OAuth and DAuth configuration. `n"
        Write-Host -ForegroundColor White "             Example: ./FreeBusyChecker.ps1 -Auth All"

        $Script:html += "
                        <div  style = 'padding-left: 0%;'>

                          <h3>Intra Organization Connector Enabled: <b>False</b></h3>

                          <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking DAuth as OAuth is not Enabled</span></p>

                        </div>

                        <div  style = 'padding-left: 0%;'>

                          <ul>
                            <li>
                              This script can be run using the <b>-Auth OAuth</b> parameter to Check for OAuth configurations only.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth OAuth

                              </span>
                            </li>
                            <br />
                            <li>

                              This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                              <span style='padding:2%;'>
                            </li>
                          </ul>
                        </div>
    "

        $html | Out-File -FilePath $htmlFile
    }
    if ($Auth -like "OAuth") {

        Write-Host $bar
        Write-Host -ForegroundColor yellow "  Warning: Intra Organization Connector Enabled False -> Running for OAuth only as -Auth OAuth parameter was selected"
        Write-Host -ForegroundColor White "`n       This script can be Run using the '-Auth All' parameter to Check for both OAuth and DAuth configuration. `n"
        Write-Host -ForegroundColor White "             Example: ./FreeBusyChecker.ps1 -Auth All"

        $Script:html += "
                        <div  style = 'padding-left: 0%;'>

                          <h3>Intra Organization Connector Enabled: <b>False</b></h3>

                          <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking OAuth as -Auth OAuth parameter was selected</span></p>

                        </div>

                        <div  style = 'padding-left: 0%;'>

                          <ul>
                            <li>

                              This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                              <span style='padding:2%;'>
                            </li>
                          </ul>
                        </div>
    "

        $html | Out-File -FilePath $htmlFile
    }

    if ($Auth -like "All") {

        Write-Host $bar
        Write-Host -ForegroundColor yellow "  Warning: Intra Organization Connector Enabled False -> Running both for OAuth and DAuth as -Auth All parameter was selected"
        Write-Host -ForegroundColor White "`n       This script can be Run using the '-Auth OAuth' parameter to Check for OAuth configuration only. `n"
        Write-Host -ForegroundColor White "             Example: ./FreeBusyChecker.ps1 -Auth OAuth"

        $Script:html += "
                        <div  style = 'padding-left: 0%;'>

                          <h3>Intra Organization Connector Enabled: <b>False</b></h3>

                          <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking both for OAuth and DAuth as -Auth All parameter was selected</span></p>

                        </div>

                        <div  style = 'padding-left: 0%;'>

                          <ul>
                            <li>

                              This script can be run using the <b>-Auth OAuth</b> parameter to Check for OAuth only.
                              <br />
                              <span style='padding-left: 2%;'>
                                <br />
                                <b>Example:</b> ./FreeBusyChecker.ps1 -Auth OAuth
                              <span style='padding:2%;'>
                            </li>
                          </ul>
                        </div>
    "

        $html | Out-File -FilePath $htmlFile
    }
}

do {
    #do while not Y or N
    Write-Host $bar
    Write-Host " Are these values correct? Press Y for YES and N for NO"
    $ParamOK = [System.Console]::ReadLine()
    $ParamOK = $ParamOK.ToUpper()
} while ($ParamOK -ne "Y" -AND $ParamOK -ne "N")
#cls
Write-Host $bar
if ($ParamOK -eq "N") {
    UserOnlineCheck
    ExchangeOnlineDomainCheck
    UserOnPremCheck
    ExchangeOnPremDomainCheck
    ExchangeOnPremEWSCheck
    ExchangeOnPremLocalDomainCheck
}
# Free busy Lookup methods
$OrgRel = Get-OrganizationRelationship | Where-Object { ($_.DomainNames -like $ExchangeOnlineDomain) } | Select-Object Enabled, Identity, DomainNames, FreeBusy*, TarGet*

$EDiscoveryEndpoint = Get-IntraOrganizationConfiguration -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object OnPremiseDiscoveryEndpoint
$SPDomainsOnprem = Get-SharingPolicy -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Format-List Domains
$SPOnprem = Get-SharingPolicy  -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object *

if ($Org -contains 'ExchangeOnPremise' -or -not $Org) {
    #region DAuth Checks
    if ($Auth -like "DAuth" -OR -not $Auth -or $Auth -like "All") {
        Write-Host " ---------------------------------------Testing DAuth Configuration----------------------------------------------- "
        #  Write-Host $bar
        OrgRelCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to Check the Federation Information Details."
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        FedInfoCheck
        if ($pause) {
            Write-Host " Press Enter when ready to Check the Federation Trust configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        FedTrustCheck

        if ($pause) {
            Write-Host " Press Enter when ready to Check the On-Prem AutoDiscover Virtual Directory configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        AutoDVirtualDCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to Check the On-Prem Web Services Virtual Directory configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        EWSVirtualDirectoryCheck
        if ($pause) {
            Write-Host $bar
            Write-Host " Press Enter when ready to  Check the Availability Address Space configuration details. "
            $RH = [System.Console]::ReadLine()
        }
        AvailabilityAddressSpaceCheck
        if ($pause) {
            Write-Host $bar
            Write-Host " Press Enter when ready to test the Federation Trust. "
            $RH = [System.Console]::ReadLine()
        }
        #need to grab errors and provide alerts in error case
        TestFedTrust
        if ($pause) {
            Write-Host $bar
            Write-Host " Press Enter when ready to Test the Organization Relationship. "
            $RH = [System.Console]::ReadLine()
        }
        TestOrgRel
    }
    #endregion
    #region OAuth Check
    if ($Auth -like "OAuth" -or -not $Auth -or $Auth -like "All") {
        if ($pause) {
            Write-Host " Press Enter when ready to Check the OAuth configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        Write-Host " ---------------------------------------Testing OAuth Configuration----------------------------------------------- "
        # Write-Host $bar
        IntraOrgConCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to Check the Auth Server configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        AuthServerCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to Check the Partner Application configuration details. "
            $RH = [System.Console]::ReadLine()
        }
        PartnerApplicationCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press any key when ready to Check the Exchange Online-ApplicationAccount configuration details. "
            $RH = [System.Console]::ReadLine()
        }
        ApplicationAccountCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to Check the Management Role Assignments for the Exchange Online-ApplicationAccount. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        ManagementRoleAssignmentCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to Check Auth configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        AuthConfigCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to Check the Auth Certificate configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        CurrentCertificateThumbprintCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press any key when ready to  Check the On Prem AutoDiscover Virtual Directory configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        AutoDVirtualDCheckOAuth
        $AutoDiscoveryVirtualDirectoryOAuth
        Write-Host $bar
        if ($pause) {
            Write-Host " Press any key when ready to Check the On-Prem Web Services Virtual Directory configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        EWSVirtualDirectoryCheckOAuth
        Write-Host $bar
        if ($pause) {
            Write-Host " Press any key when ready to Check the AvailabilityAddressSpace configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        AvailabilityAddressSpaceCheckOAuth
        Write-Host $bar
        if ($pause -eq "True") {
            Write-Host " Press Enter when ready to test the OAuthConnectivity configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        OAuthConnectivityCheck
        Write-Host $bar
    }
    #$bar
    #endregion
}
# EXO Part
if ($Org -contains 'ExchangeOnline' -OR -not $Org) {
    #region ConnectExo
    #$bar
    Write-Host -ForegroundColor Green " Collecting Exchange Online Availability Information"
    # Check if the ExchangeOnlineManagement module is already installed
    if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
        # If not installed, then install the module
        Write-Host -ForegroundColor Yellow "`n Exchange Online Powershell Module is required to Check Free Busy Configuration on Exchange Online side. Installing Module"
        Install-Module -Name ExchangeOnlineManagement -Force
        $bar
    } else {
        Write-Host "`n ExchangeOnlineManagement module is available."
        $ExoModuleVersion = Get-Module -Name ExchangeOnlineManagement -ListAvailable | Format-List name, Version
        $ExoModuleVersion
        $bar
    }

    Connect-ExchangeOnline -ShowBanner:$false

    $Script:ExoOrgRel = Get-OrganizationRelationship | Where-Object { ($_.DomainNames -like $ExchangeOnPremDomain ) } | Select-Object Enabled, Identity, DomainNames, FreeBusy*, TarGet*
    $ExoIntraOrgCon = Get-IntraOrganizationConnector | Select-Object Name, TarGetAddressDomains, DiscoveryEndpoint, Enabled
    $tarGetAddressPr1 = ("https://AutoDiscover." + $ExchangeOnPremDomain + "/AutoDiscover/AutoDiscover.svc/WSSecurity")
    $tarGetAddressPr2 = ("https://" + $ExchangeOnPremDomain + "/AutoDiscover/AutoDiscover.svc/WSSecurity")

    ##Check why this is needed
    $ExoFedInfo = Get-federationInformation -DomainName $exchangeOnpremDomain  -BypassAdditionalDomainValidation -ErrorAction SilentlyContinue | Select-Object *

    $Script:html += "
     </table>

      <div class='Black'><p></p></div>

      <div class='Black'><p></p></div>

             <div class='Black'><h2><b>`n Exchange Online Free Busy Configuration: `n</b></h2></div>

             <div class='Black'><p></p></div>
             <div class='Black'><p></p></div>

     <table style='width:100%; margin-top:30px;'>

    "

    #endregion
    #region ExoDAuthCheck
    if ($Auth -like "DAuth" -or -not $Auth -or $Auth -like "All") {
        Write-Host $bar
        Write-Host " ---------------------------------------Testing DAuth Configuration----------------------------------------------- "

        #  Write-Host $bar
        ExoOrgRelCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to Check the Federation Organization Identifier configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        EXOFedOrgIdCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to Check the Organization Relationship configuration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        ExoTestOrgRelCheck
        if ($pause) {
            Write-Host $bar
            Write-Host " Press Enter when ready to Check the Sharing Policy configuration details. "
            $RH = [System.Console]::ReadLine()
        }
        SharingPolicyCheck
    }

    #endregion
    #region ExoOauthCheck
    if ($Auth -like "OAuth" -or -not $Auth -or $Auth -like "All") {
        Write-Host " ---------------------------------------Testing OAuth Configuration----------------------------------------------- "

        # Write-Host $bar
        ExoIntraOrgConCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to Check the OrganizationConfiguration details. "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        EXOIntraOrgConfigCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to Check the Authentication Server Authorization Details.  "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        EXOAuthServerCheck
        Write-Host $bar
        if ($pause) {
            Write-Host " Press Enter when ready to test the OAuth Connectivity Details.  "
            $RH = [System.Console]::ReadLine()
            Write-Host $bar
        }
        ExoTestOAuthCheck
        Write-Host $bar
    }
    #endregion
    Disconnect-ExchangeOnline  -Confirm:$False
    Write-Host -ForegroundColor Green " That is all for the Exchange Online Side"

    $bar
}

Stop-Transcript
