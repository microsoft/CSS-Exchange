# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-IsoCopy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentCuRootDirectory
    )

    $installedVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\AdminTools -ErrorAction SilentlyContinue).PostSetupVersion
    $filterDisplayNames = @("Microsoft Lync Server", "Exchange", "Microsoft Server Speech", "Microsoft Unified Communications")

    [IO.FileInfo]$cuExchangeMsi = "$CurrentCuRootDirectory\EXCHANGESERVER.msi"

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

    $msiInstallerPackages = Get-InstallerPackages -FilterDisplayName $filterDisplayNames
    $missingPackages = $msiInstallerPackages | Where-Object { $_.ValidMsi -eq $false }
    $currentMissingPackages = $missingPackages.Count
    $missingPackages | ForEach-Object { $_ | Select-Object DisplayName, DisplayVersion, RevisionNumber, ValidMsi, FoundFileInCache } | Write-Host
    $packagesInIso = Get-ChildItem -Recurse $CurrentCuRootDirectory |
        Where-Object { $_.Name.ToLower().EndsWith(".msi") } |
        ForEach-Object { return Get-FileInformation -File $_.FullName }
    $fixedFiles = 0

    foreach ($missingMsi in $missingPackages) {
        $fileFound = $packagesInIso | Where-Object { $_.RevisionNumber -eq $missingMsi.RevisionNumber }

        if ($null -eq $fileFound) {
            "Failed to find MSI - $($missingMsi.DisplayName) - $($missingMsi.RevisionNumber) - $($missingMsi.DisplayVersion)" | Write-Host
        } elseif ($fileFound.Count -gt 1) {
            "Found more than 1 MSI file that matched our revision number." | Write-Host
            $hashes = $fileFound |
                ForEach-Object { Get-FileHash $_.FilePath } |
                Group-Object Hash
            if ($hashes.Count -eq 1) {
                "All files have the same hash value. $($missingMsi.DisplayName) - $($missingMsi.RevisionNumber) - $($missingMsi.DisplayVersion)" | Write-Host
                $fileFound = $fileFound[0]
                "Copying file $($fileFound.FilePath) to $($missingMsi.CacheLocation)" | Write-Host
                Copy-Item $fileFound.FilePath $missingMsi.CacheLocation
                $fixedFiles++
            } else {
                "Not all found files had the same hash" | Write-Host
                $fileFound | ForEach-Object { "$($fileFound.FilePath) - $($fileFound.RevisionNumber)" | Write-Host }
            }
        } else {
            "Copying file $($fileFound.FilePath) to $($missingMsi.CacheLocation)" | Write-Host
            Copy-Item $fileFound.FilePath $missingMsi.CacheLocation
            $fixedFiles++
        }
    }

    "Fixed $fixedFiles out of $currentMissingPackages" | Write-Host
}
