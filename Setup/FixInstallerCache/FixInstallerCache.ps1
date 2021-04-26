[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameters are being used')]
[CmdletBinding(DefaultParameterSetName = "CopyFromCu")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "CopyFromCu")]
    [ValidateNotNullOrEmpty()]
    [string]$CurrentCuRootDirectory,
    [Parameter(Mandatory = $true, ParameterSetName = "CopyFromServer")]
    [ValidateNotNullOrEmpty()]
    [string[]]$MachineName
)

. $PSScriptRoot\..\Shared\Get-FileInformation.ps1
. $PSScriptRoot\..\Shared\Get-InstallerPackages.ps1

#TODO: Change to Write-Output and get rid of Write-Host with ForegroundColors
Function Receive-Output {
    param(
        [string]$ForegroundColor = "Gray"
    )
    process {
        Write-Host $_ -ForegroundColor $ForegroundColor
        $_ | Out-File -FilePath $scriptLogging -Append
    }
}

Function MainIsoCopy {
    $installedVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\AdminTools -ErrorAction SilentlyContinue).PostSetupVersion
    $filterDisplayNames = @("Microsoft Lync Server", "Exchange", "Microsoft Server Speech", "Microsoft Unified Communications")

    [IO.FileInfo]$cuExchangeMsi = "$CurrentCuRootDirectory\EXCHANGESERVER.msi"

    if (!(Test-Path $cuExchangeMsi)) {
        #We want the root of the install directory, let the script handle the rest
        Write-Error "Failed to find the root of the Exchange Setup directory. Trying to find $cuExchangeMsi"
        exit
    }

    $cuExchangeFileInfo = Get-FileInformation -File $cuExchangeMsi

    if (!($cuExchangeFileInfo.Subject.Contains($installedVersion))) {
        "Failed to find the correct version of the ISO" | Receive-Output -ForegroundColor Red
        "Looking for version $installedVersion" | Receive-Output -ForegroundColor Red
        "Found Version $($cuExchangeFileInfo.Subject.Substring($cuExchangeFileInfo.Subject.LastIndexOf("v")+1))" | Receive-Output -ForegroundColor Red
        Start-Sleep 1
        Write-Error "Failed to find correct ISO version"
        exit
    }

    $msiInstallerPackages = Get-InstallerPackages -FilterDisplayName $filterDisplayNames
    $missingPackages = $msiInstallerPackages | Where-Object { $_.ValidMsi -eq $false }
    $currentMissingPackages = $missingPackages.Count
    $missingPackages | ForEach-Object { $_ | Select-Object DisplayName, DisplayVersion, RevisionNumber, ValidMsi, FoundFileInCache } | Receive-Output
    $packagesInIso = Get-ChildItem -Recurse $CurrentCuRootDirectory |
        Where-Object { $_.Name.ToLower().EndsWith(".msi") } |
        ForEach-Object { return Get-FileInformation -File $_.FullName }
    $fixedFiles = 0

    foreach ($missingMsi in $missingPackages) {
        $fileFound = $packagesInIso | Where-Object { $_.RevisionNumber -eq $missingMsi.RevisionNumber }

        if ($null -eq $fileFound) {
            "Failed to find MSI - $($missingMsi.DisplayName) - $($missingMsi.RevisionNumber) - $($missingMsi.DisplayVersion)" | Receive-Output
        } elseif ($fileFound.Count -gt 1) {
            "Found more than 1 MSI file that matched our revision number." | Receive-Output
            $hashes = $fileFound |
                ForEach-Object { Get-FileHash $_.FilePath } |
                Group-Object Hash
            if ($hashes.Count -eq 1) {
                "All files have the same hash value. $($missingMsi.DisplayName) - $($missingMsi.RevisionNumber) - $($missingMsi.DisplayVersion)" | Receive-Output
                $fileFound = $fileFound[0]
                "Copying file $($fileFound.FilePath) to $($missingMsi.CacheLocation)" | Receive-Output
                Copy-Item $fileFound.FilePath $missingMsi.CacheLocation
                $fixedFiles++
            } else {
                "Not all found files had the same hash" | Receive-Output
                $fileFound | ForEach-Object { "$($fileFound.FilePath) - $($fileFound.RevisionNumber)" | Receive-Output }
            }
        } else {
            "Copying file $($fileFound.FilePath) to $($missingMsi.CacheLocation)" | Receive-Output
            Copy-Item $fileFound.FilePath $missingMsi.CacheLocation
            $fixedFiles++
        }
    }

    "Fixed $fixedFiles out of $currentMissingPackages" | Receive-Output
}

Function MainMachineCopy {

    $msiInstallerPackages = Get-InstallerPackages -FilterDisplayName $filterDisplayNames
    [System.Collections.Generic.List[PSObject]]$missingPackages = $msiInstallerPackages | Where-Object { $_.ValidMsi -eq $false }
    $currentMissingPackages = $missingPackages.Count

    "Current Missing Files" | Receive-Output
    #Fix later, figure out how to log this better.
    $missingPackages | ForEach-Object { $_ | Select-Object DisplayName, DisplayVersion, RevisionNumber, ValidMsi, FoundFileInCache } | Receive-Output

    $runAgain = $false

    foreach ($machine in $MachineName) {

        $remoteInstallerCache = "\\$machine\c$\Windows\Installer"

        try {
            $remoteFiles = Get-ChildItem $remoteInstallerCache -ErrorAction Stop |
                Where-Object { $_.Name.ToLower().EndsWith(".msi") } |
                ForEach-Object {
                    return Get-FileInformation -File $_.FullName
                }
        } catch {
            Write-Error "Failed to get files from the following path: $remoteInstallerCache"
            continue
        }

        if ($runAgain) {
            $msiInstallerPackages = Get-InstallerPackages -FilterDisplayName $filterDisplayNames
            [System.Collections.Generic.List[PSObject]]$missingPackages = $msiInstallerPackages | Where-Object { $_.ValidMsi -eq $false }
        }

        foreach ($missingMsi in $missingPackages) {

            $fileFound = $remoteFiles | Where-Object { $_.RevisionNumber -eq $missingMsi.RevisionNumber }

            if ($null -eq $fileFound) {
                "Failed to find MSI - $($missingMsi.DisplayName) - $($missingMsi.RevisionNumber)" | Receive-Output
            } elseif ($fileFound.Count -gt 1) {
                Write-Host "Found more than 1 MSI file that matched our revision number." | Receive-Output
            } else {
                "Copying file $($fileFound.FilePath) to $($missingMsi.CacheLocation)" | Receive-Output
                Copy-Item $fileFound.FilePath $missingMsi.CacheLocation
                $fixedFiles++
            }
        }
        $runAgain = $true
    }

    "Fixed $fixedFiles out of $currentMissingPackages" | Receive-Output
}

Function Main {

    if ($PsCmdlet.ParameterSetName -eq "CopyFromCu") {
        MainIsoCopy
        return
    } else {
        MainMachineCopy
        return
    }
}

try {
    $Script:scriptLogging = ".\InstallerCacheLogger.log"
    Main
} catch {
    Receive-Output "$($_.Exception)"
    Receive-Output "$($_.ScriptStackTrace)"
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing with the log '$($Script:scriptLogging)'")
}
