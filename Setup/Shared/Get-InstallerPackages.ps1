# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#By doing it this way and looking at the registry, we get msp files as well. (Security Updates)
#Vs doing Get-CimInstance -ClassName Win32_Product
. $PSScriptRoot\Get-FileInformation.ps1
Function Get-InstallerPackages {
    [CmdletBinding()]
    param(
        [string[]]$FilterDisplayName
    )
    begin {
        $localPackageChildItems = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer" -Recurse |
            Where-Object { $_.Property -eq "LocalPackage" }
        $installerList = New-Object 'System.Collections.Generic.List[PSObject]'
    }
    process {

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
                        "Failed to get the Revision Guid $($item.FullName)" | Write-Host
                    }
                } else {
                    "Failed to find $productRegKey in order to get the revisionGuid value" | Write-Host
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
    }
    end {
        return $installerList
    }
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
