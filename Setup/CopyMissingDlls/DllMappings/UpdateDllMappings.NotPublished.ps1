# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[CmdletBinding()]
param(
    [string]$IsoRoot = "D:"
)


$installPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
$installedVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\AdminTools -ErrorAction SilentlyContinue).ConfiguredVersion
$isoRootItem = Get-Item "$IsoRoot\Setup.exe"

if (($isoRootItem.VersionInfo.ProductMinorPart -ne 0 -and
        $isoRootItem.VersionInfo.ProductBuildPart -eq 1497)) {

    if ($isoRootItem.VersionInfo.ProductVersionRaw.ToString() -ne $installedVersion) {
        throw "failed to determine that we are on the same version of exchange as the ISO"
    }
}
#need to have the current json mappings file in the same location of the script.
try {
    if ($installedVersion.StartsWith("15.2")) {
        $dllFileMappings = Get-Content ".\2019Mappings.json" -ErrorAction Stop | ConvertFrom-Json
    } elseif ($installedVersion.StartsWith("15.1")) {
        $dllFileMappings = Get-Content ".\2016Mappings.json" -ErrorAction Stop | ConvertFrom-Json
    } elseif ($installedVersion.StartsWith("15.0")) {
        throw "unable to do this with the 2013 file for some reason" #CopyMissingDlls does work. Not going worry about it right now.
        $dllFileMappings = Get-Content ".\2013Mappings.json" -ErrorAction Stop | ConvertFrom-Json
    } else {
        throw "unknown exchange version"
    }
} catch {
    throw "failed to load current mapped files. $_"
}

#Get the current mapped dll destinations
$mappedDllsDestination = New-Object 'System.Collections.Generic.List[string]'
foreach ($directoryMatchings in $dllFileMappings) {
    $serverInstallPath = "$installPath$($directoryMatchings.InstallDirectory)"

    foreach ($file in $directoryMatchings.DllFileNames) {
        $mappedDllsDestination.Add("$serverInstallPath\$file".ToLower())
    }
}

$installedDlls = Get-ChildItem -Recurse $installPath |
    Where-Object { $_.Name.ToLower().EndsWith(".dll") -and
        !$_.FullName.ToLower().StartsWith("$installPath`Bin\Search\Ceres\HostController\Data\Repository\".ToLower()) }

$installedDllsFullNames = $installedDlls | ForEach-Object { $_.FullName.ToLower() }

foreach ($installedDll in $installedDllsFullNames) {

    if (-not ($mappedDllsDestination.Contains($installedDll))) {
        Write-Host $installedDll
    }
}
