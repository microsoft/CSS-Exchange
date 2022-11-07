# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Set Antivirus Exclusions Following
# https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019 and
# https://docs.microsoft.com/en-us/exchange/anti-virus-software-in-the-operating-system-on-exchange-servers-exchange-2013-help

<#
.SYNOPSIS
The Script will assist in setting the Antivirus Exclusions according to our documentation for Microsoft Exchange Server.

.DESCRIPTION
The Script will assist in setting the Antivirus Exclusions according to our documentation for Microsoft Exchange Server.

AV Exclusions Exchange 2016/2019
https://learn.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019

AV Exclusions Exchange 2013
https://learn.microsoft.com/en-us/exchange/anti-virus-software-in-the-operating-system-on-exchange-servers-exchange-2013-help

If you use Windows Defender you can Set the exclusions executing the script without parameters but if you have any other Antivirus solution you can get the full list of Expected Exclusions.

Requirements
Supported Exchange Server Versions:
The script can be used to validate the configuration of the following Microsoft Exchange Server versions:

Microsoft Exchange Server 2013
Microsoft Exchange Server 2016
Microsoft Exchange Server 2019
The server must have Microsoft Defender to set it and enable it to be effective.

Required Permissions:
Please make sure that the account used is a member of the Local Administrator group. This should be fulfilled on Exchange servers by being a member of the Organization Management group.

How To Run
This script must be run as Administrator in Exchange Management Shell on an Exchange Server. You do not need to provide any parameters and the script will set the Windows Defender exclusions for the local Exchange server.

If you want to get the full list of expected exclusions you should use the parameter ListRecommendedExclusions

You can export the Exclusion List with the parameter FileName


.PARAMETER -ListRecommendedExclusions
Show the full list of expected exclusions.

.PARAMETER -FileName
Export the full list of expected exclusions in the definned FileName.

.INPUTS
For Set Parameter Set Identifier(Switch):
Optional Parameter   -FileName

For List Parameter Set Identifier(Switch):
Required Parameter   -ListRecommendedExclusions
Optional Parameter   -FileName


.EXAMPLE
.\Set-ExchAVExclusions.ps1
This will run Set-ExchAVExclusions Script against the local server.

.EXAMPLE
.\Set-ExchAVExclusions.ps1 -ListRecommendedExclusions
This will run Set-ExchAVExclusions Script against the local server and show in screen the expected exclusions on screen without setting them.

.EXAMPLE
.\Set-ExchAVExclusions.ps1 -ListRecommendedExclusions -FileName .\Exclusions.txt
This will run Set-ExchAVExclusions Script against the local server and show in screen the expected exclusions on screen without setting them and write them in the defined FileName.

.EXAMPLE
.\Set-ExchAVExclusions.ps1 -FileName .\Exclusions.txt
This will run Set-ExchAVExclusions Script against the local server and write them in the defined FileName.

#>


[CmdletBinding(DefaultParameterSetName = 'Set')]
param (
    [Parameter(Mandatory, ParameterSetName = 'List')]
    [switch]
    $ListRecommendedExclusions,

    [Parameter(ParameterSetName = 'Set')]
    [Parameter(ParameterSetName = 'List')]
    [string]
    $FileName
)

. $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
. $PSScriptRoot\..\..\Shared\Get-ExchAVExclusions.ps1
. $PSScriptRoot\..\..\Diagnostics\AVTester\Write-SimpleLogFile.ps1

# Log file name
$LogFile = "SetExchAvExclusions.log"

# Confirm that we are an administrator
if (-not (Confirm-Administrator)) {
    Write-Error "Please run as Administrator"
    exit
}

if (-not $ListRecommendedExclusions) {
    if ( $($host.Version.Major) -lt 5 -or ( $($host.Version.Major) -eq 5 -and $($host.Version.Minor) -lt 1) ) {
        Write-Error "This version of Windows do not have Microsoft Defender"
        exit
    }

    if (-not (Get-MpComputerStatus).AntivirusEnabled ) {
        Write-Warning "Microsoft Defender is not enabled."
        Write-Warning "We will apply the exclusions but they do not take effect until you Enabled Microsoft Defender."
    }
}

$serverExchangeInstallDirectory = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue

# Check Exchange regsitry key
if (-not  $serverExchangeInstallDirectory ) {
    Write-Warning "Failed to find the Exchage instalation Path registry key"
    exit
}

# Check the installation path
if (-not ( Test-Path $($serverExchangeInstallDirectory.MsiInstallPath) -PathType Container) ) {
    Write-Warning "Failed to find the Exchage instalation Path"
    exit
}

# Check Exchange is 2013, 2016 or 2019
if ( -not ( $($serverExchangeInstallDirectory.MsiProductMajor) -eq 15 -and `
        ($($serverExchangeInstallDirectory.MsiProductMinor) -eq 0 -or $($serverExchangeInstallDirectory.MsiProductMinor) -eq 1 -or $($serverExchangeInstallDirectory.MsiProductMinor) -eq 2 ) ) ) {
    Write-Warning "This script is desinged for Exchange 2013, 2016 or 2019"
    exit
}

if ($FileName -like '*\*') {
    if (-not (Test-Path $FileName.Substring(0, $FileName.LastIndexOf("\")))) {
        Write-Warning "FilePath does not exists"
        exit
    }
}

$ExchangePath = $serverExchangeInstallDirectory.MsiInstallPath

# Check Exchange Shell and Exchange instalation
$exchangeShell = Confirm-ExchangeShell
if (-not($exchangeShell.ShellLoaded)) {
    Write-Warning "Failed to load Exchange Shell Module..."
    exit
}

# Create the Array List
Write-Host "`r`nExclusions Paths:" -ForegroundColor DarkGreen
$BaseFolders = New-Object Collections.Generic.List[string]
$BaseFolders = Get-ExchAVExclusionsPaths -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)
if ($FileName) {
    "[Paths]" | Out-File $FileName
}
foreach ($folder in $BaseFolders) {
    if ($ListRecommendedExclusions) {
        Write-Host ("$folder")
    } else {
        Write-SimpleLogfile -String ("Adding $folder") -name $LogFile -OutHost
        Add-MpPreference -ExclusionPath $folder
    }
    if ($FileName) {
        $folder | Out-File $FileName -Append
    }
}

Write-Host "`r`nExclusions Extensions:" -ForegroundColor DarkGreen
$extensionsList = New-Object Collections.Generic.List[string]
$extensionsList = Get-ExchAVExclusionsExtensions -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)
if ($FileName) {
    "`r`n[Extensions]" | Out-File $FileName -Append
}
foreach ($extension in $extensionsList) {
    if ($ListRecommendedExclusions) {
        Write-Host ("$extension")
    } else {
        Write-SimpleLogfile -String ("Adding $extension") -name $LogFile -OutHost
        Add-MpPreference -ExclusionExtension $extension
    }
    if ($FileName) {
        $extension | Out-File $FileName -Append
    }
}

Write-Host "`r`nExclusions Processes:" -ForegroundColor DarkGreen
$processesList = New-Object Collections.Generic.List[string]
$processesList = Get-ExchAVExclusionsProcess -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)
if ($FileName) {
    "`r`n[Processes]" | Out-File $FileName -Append
}
foreach ($process in $processesList) {
    if ($ListRecommendedExclusions) {
        Write-Host ("$process")
    } else {
        Write-SimpleLogfile -String ("Adding $process") -name $LogFile -OutHost
        Add-MpPreference -ExclusionPath $process
        Add-MpPreference -ExclusionProcess $process
    }
    if ($FileName) {
        $process | Out-File $FileName -Append
    }
}

if ($ListRecommendedExclusions) {
    Write-Host ('')
}

Write-SimpleLogfile -String ("Exclusions Completed") -name $LogFile -OutHost
