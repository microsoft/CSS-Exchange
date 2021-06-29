# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding(SupportsShouldProcess = $True)]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "CopyMissingDllsFromIso")]
    [ValidateNotNullOrEmpty()]
    [string]$IsoRoot
)

$2013mappingsFileBytes = Get-Content ".\DllMappings\2013Mappings.json" -AsByteStream -Raw
$2013mappingsFileContent = [System.Text.Encoding]::UTF8.GetString($2013mappingsFileBytes)

$2016mappingsFileBytes = Get-Content ".\DllMappings\2016Mappings.json" -AsByteStream -Raw
$2016mappingsFileContent = [System.Text.Encoding]::UTF8.GetString($2016mappingsFileBytes)

$2019mappingsFileBytes = Get-Content ".\DllMappings\2019Mappings.json" -AsByteStream -Raw
$2019mappingsFileContent = [System.Text.Encoding]::UTF8.GetString($2019mappingsFileBytes)

#Get Version installed on server
$installPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
$installedVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\AdminTools -ErrorAction SilentlyContinue).ConfiguredVersion
#get version of ISO, verify it is the same.
$isoItemRoot = Get-Item "$IsoRoot\Setup.exe"

if (($IsoItemRoot.VersionInfo.ProductMinorPart -ne 0 -and
        $IsoItemRoot.VersionInfo.ProductBuildPart -eq 1497)) {

    if ($isoItemRoot.VersionInfo.ProductVersionRaw.ToString() -ne $installedVersion) {
        throw "failed to determine that we are on the same version of exchange as the ISO"
    }
}

if ($isoItemRoot.VersionInfo.ProductMinorPart -eq 0) {
    $dllFileMappings = $2013mappingsFileContent | ConvertFrom-Json
} elseif ($isoItemRoot.VersionInfo.ProductMinorPart -eq 1) {
    $dllFileMappings = $2016mappingsFileContent | ConvertFrom-Json
} elseif ($isoItemRoot.VersionInfo.ProductMinorPart -eq 2) {
    $dllFileMappings = $2019mappingsFileContent | ConvertFrom-Json
} else {
    throw "Can't tell what version you are on"
}

Function Receive-Output {
    process {
        Write-Host $_
        $_ | Out-File -FilePath $scriptLogging -Append
    }
}

$scriptLogging = ".\Log_CopyingMissingDlls.log"
Out-File -FilePath $scriptLogging -Force
"Found $installedVersion on the server" | Receive-Output

foreach ($directoryMatchings in $dllFileMappings) {
    $serverInstallPath = "$installPath$($directoryMatchings.InstallDirectory)"
    $isoPath = "$IsoRoot\$($directoryMatchings.IsoDirectory)"

    foreach ($file in $directoryMatchings.DllFileNames) {
        $dest = "$serverInstallPath\$file"

        if (!(Test-Path $dest)) {
            $copyItem = "$isoPath\$file"
            "Missing Item $dest. Copying it" | Receive-Output
            Copy-Item $copyItem -Destination $dest
        }
    }
}
