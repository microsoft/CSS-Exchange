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

Function Receive-Output {
    param(
        [string]$ForegroundColor = "Gray"
    )
    process {
        Write-Host $_ -ForegroundColor $ForegroundColor
        $_ | Out-File -FilePath $scriptLogging -Append
    }
}

#By doing it this way and looking at the registry, we get msp files as well. (Security Updates)
#Vs doing Get-CimInstance -ClassName Win32_Product
Function Get-InstallerPackages {
    param(
        [string[]]$FilterDisplayName
    )
    $localPackageChildItems = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer" -Recurse |
        Where-Object { $_.Property -eq "LocalPackage" }

    $installerList = New-Object 'System.Collections.Generic.List[PSObject]'

    foreach ($regKey in $localPackageChildItems) {

        $filePackagePath = [IO.FileInfo] $regKey.GetValue("LocalPackage")
        $item = $null

        if ($filePackagePath.Extension -eq ".msp") {
            $revisionGuid = Get-GuidProductCodeFromString -GuidString $regKey.PSChildName
        } else {
            $productRegKey = "Registry::HKEY_CLASSES_ROOT\Installer\Products\$($regKey.PSParentPath.Split("\")[-1])"

            if (Test-Path $productRegKey) {
                $item = Get-Item $productRegKey
                try {
                    $revisionGuid = Get-GuidProductCodeFromString -GuidString ($item.GetValue("PackageCode"))
                } catch {
                    "Failed to get the Revision Guid $($item.FullName)" | Receive-Output
                }
            } else {
                "Failed to find $productRegKey in order to get the revisionGuid value" | Receive-Output
            }
        }

        $displayName = $regKey.GetValue("DisplayName")
        if ($null -ne $FilterDisplayName -and
            -not ([string]::IsNullOrEmpty($displayName))) {
            $inFilter = $false

            foreach ($filter in $FilterDisplayName) {
                if ($displayName -like "*$filter*") {
                    $inFilter = $true
                    break
                }
            }

            if (!$inFilter) {
                continue
            }
        }

        #Go one more step to see if the package is set with what we want.
        $filePackageInfo = $null
        $foundFile = Test-Path $filePackagePath
        $correctRevisionValue = $false
        if ($foundFile) {
            $filePackageInfo = Get-FileInformation -File $filePackagePath
        }

        if ($foundFile -and
            $null -ne $filePackageInfo) {
            $correctRevisionValue = $filePackageInfo.RevisionNumber.Contains($revisionGuid.ToString().ToUpper())
        }

        $installerList.Add([PSCustomObject]@{
                DisplayName      = $displayName
                DisplayVersion   = $regKey.GetValue("DisplayVersion")
                CacheLocation    = $filePackagePath
                FoundFileInCache = $foundFile
                ValidMsi         = $correctRevisionValue
                UninstallString  = $regKey.GetValue("UninstallString")
                RevisionGuid     = $revisionGuid
                RevisionNumber   = "{$($revisionGuid.ToString().ToUpper())}"
                PackageInfo      = $filePackageInfo
                ProductItem      = $item
                InstallerItem    = $regKey
            })
    }

    return $installerList
}

Function Get-GuidProductCodeFromString {
    param(
        [string]$GuidString
    )
    $index = 0
    $newGuidString = [string]::Empty

    while ($index -lt $GuidString.Length) {
        $l = 2
        if ($index -lt 8) {
            $l = 8
        } elseif ($index -lt 16) {
            $l = 4
        }

        $substringArray = $GuidString.Substring($index, $l).ToCharArray()
        [Array]::Reverse($substringArray)
        $newGuidString += $substringArray -join ''
        $index += $l
    }

    return [guid]$newGuidString
}

Function Get-FileInformation {
    param(
        [IO.FileInfo]$File,
        [bool]$AllowFileSubjectOnly = $false
    )
    $installerCOM = $null
    try {

        $installerCOM = New-Object -ComObject "WindowsInstaller.Installer"

        if (-not($installerCOM) -and
            -not($AllowFileSubjectOnly)) {
            "Failed to create 'WindowsInstaller.Installer' COM object. This can lead to issues with validation of the script." | Receive-Output -ForegroundColor Red
            #If we fail doing this, we shouldn't continue.
            exit
        }

        if ($installerCOM) {
            #This would be nice to have i think. Not fully sure how to call it however.
            #https://docs.microsoft.com/en-us/windows/win32/msi/installer-fileversion

            #https://docs.microsoft.com/en-us/windows/win32/msi/installer-summaryinformation
            $summaryInformation = $installerCOM.GetType().InvokeMember("SummaryInformation", [System.Reflection.BindingFlags]::GetProperty, $null, $installerCOM, @($File.FullName, 0))
            #https://docs.microsoft.com/en-us/windows/win32/msi/summaryinfo-summaryinfo
            $subject = $summaryInformation.GetType().InvokeMember("Property", [System.Reflection.BindingFlags]::GetProperty, $null, $summaryInformation, @(3))
            $revNumber = $summaryInformation.GetType().InvokeMember("Property", [System.Reflection.BindingFlags]::GetProperty, $null, $summaryInformation, @(9))

            return [PSCustomObject]@{
                FilePath       = $File.FullName
                Subject        = $subject
                RevisionNumber = $revNumber.ToUpper()
            }
        }


        $shellApplication = New-Object -ComObject "Shell.Application"

        if (-not($shellApplication)) {
            "Failed to create 'Shell.Application' COM Object. This can lead to issues with validation of the script." | Receive-Output -ForegroundColor Red
            exit
        }

        $fileItem = Get-Item $File
        $shellFolder = $shellApplication.NameSpace($fileItem.Directory.FullName)
        $subject = $shellFolder.GetDetailsOf($shellFolder.ParseName($fileItem.Name), 22)
    } catch {
        $Error[0].Exception | Receive-Output
        $Error[0].ScriptStackTrace | Receive-Output
        Write-Error "Failed to properly process file $($File.FullName) to get required MSI information"
        exit
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
            Write-Host "Found more than 1 MSI file that matched our revision number." | Receive-Output
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
    $Script:scriptLogging = ".\InstallerCacheLogger.log"

    if ($PsCmdlet.ParameterSetName -eq "CopyFromCu") {
        MainIsoCopy
        return
    } else {
        MainMachineCopy
        return
    }
}

Main