# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-TryCopyMissingPackages.ps1
. $PSScriptRoot\..\..\Shared\ErrorMonitorFunctions.ps1
function Invoke-IsoCopy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentCuRootDirectory,
        [Parameter(Mandatory = $false)]
        [bool]$RemoteDebug
    )

    $installedVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\AdminTools -ErrorAction SilentlyContinue).PostSetupVersion
    Write-Verbose "Installed Version of Exchange: $installedVersion"
    $filterDisplayNames = @("Microsoft Lync Server", "Exchange", "Microsoft Server Speech", "Microsoft Unified Communications")

    [IO.FileInfo]$cuExchangeMsi = "$CurrentCuRootDirectory\ExchangeServer.msi"

    if (!(Test-Path $cuExchangeMsi)) {
        #We want the root of the install directory, let the script handle the rest
        Write-Host "Failed to find the root of the Exchange Setup directory. Trying to find $cuExchangeMsi" -ForegroundColor "Red"
        exit
    }

    $cuExchangeFileInfo = Get-FileInformation -File $cuExchangeMsi

    if (!($cuExchangeFileInfo.Subject.Contains($installedVersion))) {
        Write-Host "Failed to find the correct version of the ISO" -ForegroundColor Red
        Write-Host "Looking for version $installedVersion" -ForegroundColor Red
        Write-Host "Found Version $($cuExchangeFileInfo.Subject.Substring($cuExchangeFileInfo.Subject.LastIndexOf("v")+1))" -ForegroundColor Red
        Start-Sleep 1
        Write-Host "Failed to find correct ISO version" -ForegroundColor "Red"
        exit
    }

    Write-Verbose "Found correct version of the ISO."
    $msiInstallerPackages = Get-InstallerPackages -FilterDisplayName $filterDisplayNames
    $missingPackages = $msiInstallerPackages | Where-Object { $_.ValidMsi -eq $false }
    $currentMissingPackages = $missingPackages.Count

    if ($currentMissingPackages -eq 0) {
        Write-Host "No missing packages detected."
        return
    }

    # Don't need to export out the information if 0 missing files were found
    if ($RemoteDebug) {
        Write-Verbose "Save out the Get-InstallerPackages information"
        try {
            $msiInstallerPackages | Export-Clixml -Path "$((Get-Location).Path)\$env:ComputerName-InstallerPackages.xml" -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to export the Installer Packages Information"
            Invoke-CatchActions
        }
    }

    Write-Host "Number of missing packages detected: $currentMissingPackages"
    $missingPackages |
        ForEach-Object { $_ | Select-Object DisplayName, DisplayVersion, RevisionNumber, FoundFileInCache } |
        Format-Table |
        Out-String |
        Write-Host
    $packagesInIso = Get-ChildItem -Recurse $CurrentCuRootDirectory |
        Where-Object { $_.Name.ToLower().EndsWith(".msi") } |
        ForEach-Object { return Get-FileInformation -File $_.FullName }
    $fixedFiles = 0

    if ($RemoteDebug) {
        Write-Verbose "Save out Packages Information in the ISO"
        try {
            $packagesInIso | Export-Clixml -Path "$((Get-Location).Path)\$env:ComputerName-IsoPackages.xml" -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to export the ISO Packages Information"
            Invoke-CatchActions
        }
    }

    Invoke-TryCopyMissingPackages -MissingPackages $missingPackages -PossiblePackages $packagesInIso -FixedCount ([ref]$fixedFiles)

    "Fixed $fixedFiles out of $currentMissingPackages" | Write-Host
}
