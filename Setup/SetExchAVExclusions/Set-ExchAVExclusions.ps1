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


.PARAMETER ListRecommendedExclusions
Show the full list of expected exclusions.

.PARAMETER FileName
Export the full list of expected exclusions in the defined FileName.

.PARAMETER SkipVersionCheck
Skip script version verification.

.PARAMETER ScriptUpdateOnly
Just update script version to latest one.

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
    $FileName,

    [Parameter(ParameterSetName = 'Set')]
    [Parameter(ParameterSetName = 'List')]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

. $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
. $PSScriptRoot\..\..\Shared\Get-ExchAVExclusions.ps1
. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Warning.ps1

function Write-HostLog ($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $message
    }
}

$Script:HostLogger = Get-NewLoggerInstance -LogName "SetExchAvExclusions" -LogDirectory $PSScriptRoot
SetWriteHostAction ${Function:Write-HostLog}
SetWriteWarningAction ${Function:Write-HostLog}

$BuildVersion = ""

Write-Host ("Set-ExchAVExclusions.ps1 script version $($BuildVersion)") -ForegroundColor Green

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/Set-ExchAVExclusions-VersionsURL" -Confirm:$false) {
    ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
    ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
    }
    return
}

if ((-not($SkipVersionCheck)) -and
    (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/Set-ExchAVExclusions-VersionsURL" -Confirm:$false)) {
    Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
    return
}

# Confirm that we are an administrator
if (-not (Confirm-Administrator)) {
    Write-Host "[ERROR]: Please run as Administrator" -ForegroundColor Red
    exit
}

if (-not $ListRecommendedExclusions) {
    if ( $($host.Version.Major) -lt 5 -or ( $($host.Version.Major) -eq 5 -and $($host.Version.Minor) -lt 1) ) {
        Write-Host "[ERROR]: This version of Windows do not have Microsoft Defender" -ForegroundColor Red
        exit
    }

    $checkCmdLet = $null
    $checkCmdLet = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($null -eq $checkCmdLet) {
        Write-Host "[ERROR]: Get-MpComputerStatus cmdLet is not available" -ForegroundColor Red
        Write-Host "[ERROR]: This script only sets Exclusions on Microsoft Defender" -ForegroundColor Red
        Write-Host "If you have any other Antivirus you can use -ListRecommendedExclusions parameter to get the Recommended Exclusion List"
        exit
    } else {
        $mpStatus = $null
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($null -eq $mpStatus) {
            Write-Host "[ERROR]: We cannot get Microsoft Defender information" -ForegroundColor Red
            Write-Host "[ERROR]: This script only sets Exclusions on Microsoft Defender" -ForegroundColor Red
            Write-Host "If you have any other Antivirus you can use -ListRecommendedExclusions parameter to get the Recommended Exclusion List"
            exit
        } else {
            if (-not $mpStatus.AntivirusEnabled ) {
                Write-Warning "Microsoft Defender is not enabled."
                Write-Warning "We will apply the exclusions but they do not take effect until you Enabled Microsoft Defender."
                Write-Host "If you have any other Antivirus you can use -ListRecommendedExclusions parameter to get the Recommended Exclusion List"
            } else {
                if (-not $mpStatus.RealTimeProtectionEnabled) {
                    Write-Warning "RealTime protection is not enabled."
                    Write-Warning "We will apply the exclusions but they do not take effect until you Enabled RealTime Protection."
                    Write-Host "If you have any other Antivirus you can use -ListRecommendedExclusions parameter to get the Recommended Exclusion List"
                }
            }
        }
    }
}

$serverExchangeInstallDirectory = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue

# Check Exchange registry key
if (-not  $serverExchangeInstallDirectory ) {
    Write-Host "[ERROR]: Failed to find the Exchange installation Path registry key" -ForegroundColor Red
    exit
}

# Check the installation path
if (-not ( Test-Path $($serverExchangeInstallDirectory.MsiInstallPath) -PathType Container) ) {
    Write-Host "[ERROR]: Failed to find the Exchange installation Path" -ForegroundColor Red
    exit
}

# Check Exchange is 2013, 2016 or 2019
if ( -not ( $($serverExchangeInstallDirectory.MsiProductMajor) -eq 15 -and `
        ($($serverExchangeInstallDirectory.MsiProductMinor) -eq 0 -or $($serverExchangeInstallDirectory.MsiProductMinor) -eq 1 -or $($serverExchangeInstallDirectory.MsiProductMinor) -eq 2 ) ) ) {
    Write-Host "[ERROR]: This script is designed for Exchange 2013, 2016 or 2019" -ForegroundColor Red
    exit
}

$ExchangePath = $serverExchangeInstallDirectory.MsiInstallPath

#Check if the file path exists
if ($FileName -like '*\*') {
    if (-not (Test-Path $FileName.Substring(0, $FileName.LastIndexOf("\")))) {
        Write-Host "[ERROR]: FilePath does not exists" -ForegroundColor Red
        exit
    }
}

# Check Exchange Shell and Exchange installation
$exchangeShell = Confirm-ExchangeShell
if (-not($exchangeShell.ShellLoaded)) {
    Write-Host "[ERROR]: Failed to load Exchange Shell Module..." -ForegroundColor Red
    exit
}

Write-Host " "
Write-Host "Exclusions Paths:" -ForegroundColor DarkGreen
# Create the Array List
$BaseFolders = New-Object Collections.Generic.List[string]
$BaseFolders = Get-ExchAVExclusionsPaths -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)
if ($FileName) {
    "[Paths]" | Out-File $FileName
}
foreach ($folder in $BaseFolders) {
    if ($ListRecommendedExclusions) {
        Write-Host "$folder"
    } else {
        Write-Host "Adding: $folder"
        Add-MpPreference -ExclusionPath $folder
    }
    if ($FileName) {
        $folder | Out-File $FileName -Append
    }
}

Write-Host " "
Write-Host "Exclusions Extensions:" -ForegroundColor DarkGreen
$extensionsList = New-Object Collections.Generic.List[string]
$extensionsList = Get-ExchAVExclusionsExtensions -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)
if ($FileName) {
    "`r`n[Extensions]" | Out-File $FileName -Append
}
foreach ($extension in $extensionsList) {
    if ($ListRecommendedExclusions) {
        Write-Host "$extension"
    } else {
        Write-Host "Adding: $extension"
        Add-MpPreference -ExclusionExtension $extension
    }
    if ($FileName) {
        $extension | Out-File $FileName -Append
    }
}

Write-Host " "
Write-Host "Exclusions Processes:" -ForegroundColor DarkGreen
$processesList = New-Object Collections.Generic.List[string]
$processesList = Get-ExchAVExclusionsProcess -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)
if ($FileName) {
    "`r`n[Processes]" | Out-File $FileName -Append
}
foreach ($process in $processesList) {
    if ($ListRecommendedExclusions) {
        Write-Host "$process"
    } else {
        Write-Host "Adding: $process"
        Add-MpPreference -ExclusionPath $process
        Add-MpPreference -ExclusionProcess $process
    }
    if ($FileName) {
        $process | Out-File $FileName -Append
    }
}

Write-Host " "
if ($ListRecommendedExclusions) {
    Write-Host "Exclusions Detection Completed" -ForegroundColor Green
} else {
    Write-Host "Exclusions Applied" -ForegroundColor Green
}
Write-Host " "
