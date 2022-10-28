# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Set Antivirus Exclusions Following
# https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019 and
# https://docs.microsoft.com/en-us/exchange/anti-virus-software-in-the-operating-system-on-exchange-servers-exchange-2013-help

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

if ( $($host.Version.Major) -lt 5 -or ( $($host.Version.Major) -eq 5 -and $($host.Version.Minor) -lt 1) ) {
    Write-Error "This version of Windows do not have Microsoft Defender"
    exit
}

if (-not (Get-MpComputerStatus).AntivirusEnabled ) {
    Write-Warning "Microsoft Defender is not enabled."
    Write-Warning "We will apply the exclusions but they do not take effect until you Enabled Microsoft Defender."
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

$ExchangePath = $serverExchangeInstallDirectory.MsiInstallPath

# Check Exchange Shell and Exchange instalation
$exchangeShell = Confirm-ExchangeShell -Identity $env:computerName
if (-not($exchangeShell.ShellLoaded)) {
    Write-Warning "Failed to load Exchange Shell Module..."
    exit
}

# Create the Array List
$BaseFolders = New-Object Collections.Generic.List[string]
$BaseFolders = Get-ExchAVExclusionsPaths -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)
Write-Host "`nStarting Exclusions Path..."
foreach ($folder in $BaseFolders) {
    Write-SimpleLogfile -String ("Adding $folder") -name $LogFile -OutHost
    Add-MpPreference -ExclusionPath $folder
}

Write-Host "`nStarting Exclusions Extension..."
$extensionsList = New-Object Collections.Generic.List[string]
$extensionsList = Get-ExchAVExclusionsExtensions -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)
foreach ($extension in $extensionsList) {
    Write-SimpleLogfile -String ("Adding $extension") -name $LogFile -OutHost
    Add-MpPreference -ExclusionExtension $extension
}

$processesList = New-Object Collections.Generic.List[string]
$processesList = Get-ExchAVExclusionsProcess -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)

Write-Host "`nStarting Exclusions Process..."
foreach ($process in $processesList) {
    Write-SimpleLogfile -String ("Adding $process") -name $LogFile -OutHost
    Add-MpPreference -ExclusionPath $process
    Add-MpPreference -ExclusionProcess $process
}

Write-SimpleLogfile -String ("Adding Exclusions Completed") -name $LogFile -OutHost
