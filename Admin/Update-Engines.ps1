# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$EngineDirPath,
    [string]$UpdatePathUrl = "http://forefrontdl.microsoft.com/server/scanengineupdate/",
    [string]$FailoverPathUrl = "https://amupdatedl.microsoft.com/server/scanengineupdate/",
    [string]$EngineDownloadUrlV2 = "http://amupdatedl.microsoft.com/server/amupdate/",
    [string[]]$Engines = ("Microsoft"),
    [string[]]$Platforms = ("amd64"),
    [switch]$ScriptUpdateOnly,
    [switch]$SkipVersionCheck,
    [switch]$CleanUp,
    [int]$VersionsToKeep = 10
)

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

$BuildVersion = ""

# Display Help
if (($Args[0] -eq "-?") -or ($Args[0] -eq "-help")) {
    ""
    "Usage: Update-Engines.ps1 [-EngineDirPath <string>] [[-UpdatePathUrl] <update url>] [[-Engines] <engine names>] [[-Platforms] <platform names> "
    "       [-EngineDirPath <string>]           The directory to serve as the root engines directory"
    "       [-UpdatePathUrl <update url]        The update path used to pull the updates from"
    "       [[-Engines] <engine names>[]]       The list of names of engines to update"
    "       [[-Platforms] <platform names>[]]   The list of names of platforms to update"
    ""
    "Examples: "
    "     Update-Engines.ps1 -EngineDirPath C:\Engines\"
    "     Update-Engines.ps1 -EngineDirPath C:\Engines\ -UpdatePathUrl http://forefrontdl.microsoft.com/server/scanengineupdate/ -Engines Microsoft -Platforms amd64"
    ""
    exit
}

Write-Host ("Update-Engines.ps1 script version $($BuildVersion)") -ForegroundColor Green

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion -AutoUpdate -Confirm:$false) {
        ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
        ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
    }
    return
}

if ((-not($SkipVersionCheck)) -and
    (Test-ScriptVersion -AutoUpdate -Confirm:$false)) {
    Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
    return
}

if ($EngineDirPath.Length -eq 0) {
    $(throw "The EngineDirPath is not set. Please set the EngineDirPath parameter to a valid directory.")
}

# The directory to store the engines with needs to contain
# a trailing slash.
if (!$EngineDirPath.EndsWith("\")) {
    $EngineDirPath += "\"
}

# Constants used in the script
$ShellProgId = "Shell.Application"
$DoNotDisplayProgress = 4
$YesAll = 16
$NoConfirmDirectory = 512
$NoUI = 1024

$Script:UmFileName = "UniversalManifest.cab"
$Script:EliFileName = "EngineInfo.cab"

# Checks if the specified path exists.
# If not the directory is created.
function CreatePath($path) {
    if ((Test-Path $path) -ne $true) {
        New-Item -type Directory $path
        Write-Host "Created: " $path
    }
}

function CleanUpFolder($path, $itemsToKeep) {
    Get-ChildItem $path | Where-Object { $_.PSIsContainer } | Sort-Object -Property CreationTime -Descending | Select-Object -Skip $itemsToKeep | Remove-Item -Recurse
}

# Use the Shell.Application COM object to extract the
# contents of the sourceCabPath and put the contents into
# the destinationDirectory. Support is included for cab
# files with sub directory hierarchies.
function ExtractCab($sourceCabPath, $destinationDirectory) {
    # Determine if we can call the expand.exe utility
    # if so use it, otherwise, use the Shell.Application
    # COM object to perform the expansion of the CAB
    & "expand.exe"

    if ($?) {
        & "expand.exe" "-R" $sourceCabPath "-F:*" $destinationDirectory
    } else {
        $shell = New-Object -ComObject $ShellProgId

        if (!$?) {
            $(throw "unable to create $ShellProgId object")
        }

        $source = $shell.Namespace($sourceCabPath).items()
        $destination = $shell.Namespace($destinationDirectory)
        $flags = $DoNotDisplayProgress + $YesAll + $NoConfirmDirectory + $NoUI
        $itemCount = $source.Count
        $cabNameLength = $sourceCabPath.Length
        $cachedDestDir = ""
        $relativeDest = ""

        # Process each item in the cab. Determine if the destination
        # is a sub directory and create if necessary.
        for ($i=0; $i -lt $itemCount; $i++) {
            $lastPathIndex = $source.item($i).Path.LastIndexOf("\")

            # If the file inside the zip file should be extracted
            # to a subfolder, then we need to reset the destination
            if ($lastPathIndex -gt $cabNameLength) {
                $relativePath = $source.item($i).Path.SubString(($cabNameLength + 1), ($lastPathIndex - $cabNameLength))
                $relativeDestDir = $destinationDirectory + $relativePath

                if ($relativeDestDir -ne $cachedDestDir) {
                    $relativeDest = $shell.Namespace($relativeDestDir)
                    $cachedDestDir = $relativeDestDir
                }

                $relativeDest.CopyHere($source.item($i), $flags)
            } else {
                $destination.CopyHere($source.item($i), $flags)
            }
        }
    }
}

# Downloads a URI to a destination path using the supplied WebClient.
# Extracted so tests can mock the network call without hitting the wire.
function Invoke-WebClientDownload {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.WebClient]$WebClient,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )
    $WebClient.DownloadFile($Uri, $Destination)
}

# Reads an XML manifest from disk and returns the parsed document.
# Extracted so tests can substitute synthetic XML fixtures.
function Read-Manifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    return [xml](Get-Content -Path $Path)
}

# Selects the <Platform> element matching PlatformName from the Universal Manifest.
# Throws if no matching platform is found.
function Get-PlatformElement {
    param(
        [Parameter(Mandatory = $true)]
        [xml]$UniversalManifest,

        [Parameter(Mandatory = $true)]
        [string]$PlatformName
    )
    $platform = $UniversalManifest.UniversalManifest.EngineVersions.SelectSingleNode(("Platform[@id='" + $PlatformName + "']"))
    if ($platform -isnot [System.Xml.XmlElement]) {
        $(throw "The Platform '" + $PlatformName + "' is not valid.")
    }
    return $platform
}

# Selects the <Engine> element matching EngineName from the supplied Platform.
# Writes a non-terminating error and returns $null if no matching engine is found.
function Get-EngineElement {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$PlatformElement,

        [Parameter(Mandatory = $true)]
        [string]$EngineName
    )
    $engine = $PlatformElement.SelectSingleNode(("Category/Engine[@name='" + $EngineName + "']"))
    if ($engine -isnot [System.Xml.XmlElement]) {
        $errMsg = "The engine name '" + $EngineName + "' is not valid."
        Write-Error $errMsg -Category InvalidArgument
        return $null
    }
    return $engine
}

# Downloads the Universal Manifest CAB, extracts it, and returns the parsed XML.
# Also creates the metadata and temp directories and clears stale temp files.
function Invoke-UniversalManifestDownload {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.WebClient]$WebClient,

        [Parameter(Mandatory = $true)]
        [string]$UpdatePathUrl,

        [Parameter(Mandatory = $true)]
        [string]$EngineDirPath,

        [Parameter(Mandatory = $true)]
        [string]$TempFilePath
    )

    $url = ($UpdatePathUrl + "metadata/$($Script:UmFileName)")
    $umFilePath = $EngineDirPath + "metadata\$($Script:UmFileName)"
    $metaDataDir = $EngineDirPath + "metadata\"

    CreatePath -path $metaDataDir

    Invoke-WebClientDownload -WebClient $WebClient -Uri $url -Destination $umFilePath

    CreatePath -path $TempFilePath

    # Delete any temporary files left over from
    # any previous runs of the script
    Remove-Item ($TempFilePath + "*.*")

    # Extract the xml file from the cab
    # so we can parse and read the data
    ExtractCab -sourceCabPath $umFilePath -destinationDirectory $TempFilePath

    return (Read-Manifest -Path ($TempFilePath + "UniversalManifest.xml"))
}

# Downloads the Engine License Info CAB for the version reported by the Universal Manifest,
# but only if the versioned metadata directory does not already contain it.
function Invoke-EngineLicenseInfoDownload {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.WebClient]$WebClient,

        [Parameter(Mandatory = $true)]
        [string]$UpdatePathUrl,

        [Parameter(Mandatory = $true)]
        [string]$EngineDirPath,

        [Parameter(Mandatory = $true)]
        [xml]$UniversalManifest
    )

    $engineInfoVersion = $UniversalManifest.UniversalManifest.licenseInfoVersion
    Write-Host "The current Engine License Info version: " $engineInfoVersion

    $engineInfoFilePath = $EngineDirPath + "metadata\" + $engineInfoVersion

    CreatePath -path $engineInfoFilePath

    $engineInfoFilePath += "\" + $Script:EliFileName

    # If the versioned directory does not exists
    # download the new version of the Engine License Info
    if ((Test-Path $engineInfoFilePath) -ne $true) {
        Write-Host "The current version of the Engine License Info needs to be downloaded."

        $engineInfoURL = ($UpdatePathUrl + "\metadata\" + $engineInfoVersion + "/" + $Script:EliFileName)
        Invoke-WebClientDownload -WebClient $WebClient -Uri $engineInfoURL -Destination $engineInfoFilePath

        Write-Host "The Engine License Info download is complete."
    }
}

# Performs the full download flow for a single engine on a single platform:
# downloads the per-engine manifest CAB, extracts it, reads the version and full
# package name, downloads the full package if missing or size-mismatched,
# creates any subdirectories the manifest declares, extracts the package, and
# copies the manifest into the versioned package directory. Optionally prunes
# older versioned directories when CleanUp is specified.
function Invoke-EngineUpdate {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.WebClient]$WebClient,

        [Parameter(Mandatory = $true)]
        [string]$UpdatePathUrl,

        [Parameter(Mandatory = $true)]
        [string]$EngineDirPath,

        [Parameter(Mandatory = $true)]
        [string]$TempFilePath,

        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$Platform,

        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$Engine,

        [Parameter(Mandatory = $false)]
        [switch]$CleanUp,

        [Parameter(Mandatory = $false)]
        [int]$VersionsToKeep = 10
    )

    Write-Host "Engine: $($Engine.Name) UpdateVersion: $($Engine.Package.version)"

    $manifestFileNameRoot = "manifest." + $Engine.Default
    $manifestFileName = $manifestFileNameRoot + ".cab"
    $engineUrl = $UpdatePathUrl + $Platform.id + "/" + $Engine.Name + "/" + "Package/"
    $manifestUrl = ($engineUrl + $manifestFileName)
    $enginePath = $EngineDirPath + $Platform.id + "\" + $Engine.Name + "\Package\"

    Write-Host "Begin download: $($Engine.Name) Url: $($manifestUrl)"

    CreatePath -path $enginePath

    $manifestPath = $enginePath + $manifestFileName

    Invoke-WebClientDownload -WebClient $WebClient -Uri $manifestUrl -Destination $manifestPath

    # Delete any temporary files left over from
    # any previous runs of the script
    Remove-Item ($TempFilePath + "*.*")

    ExtractCab -sourceCabPath $manifestPath -destinationDirectory $TempFilePath

    $manifest = Read-Manifest -Path ($TempFilePath + "manifest.xml")

    $fullPkgDir = $enginePath + $manifest.ManifestFile.Package.version + "\"

    CreatePath -path $fullPkgDir

    $fullPkgUrl = $engineUrl + $manifest.ManifestFile.Package.version + "/" + $manifest.ManifestFile.Package.FullPackage.name
    $fullPkgPath = ($fullPkgDir + $manifest.ManifestFile.Package.FullPackage.name)

    if (((Test-Path $fullPkgPath) -ne $true) -or ((Get-Item $fullPkgPath).Length -ne $manifest.ManifestFile.Package.FullPackage.Size)) {
        Invoke-WebClientDownload -WebClient $WebClient -Uri $fullPkgUrl -Destination $fullPkgPath

        # Detect if there are any subdirectories
        # needed for this engine
        $subDirCount = $manifest.ManifestFile.Package.Files.Dir.Count

        for ($i = 0; $i -lt $subDirCount; $i++) {
            CreatePath -path ($fullPkgDir + $manifest.ManifestFile.Package.Files.Dir[$i].name)
        }

        ExtractCab -sourceCabPath $fullPkgPath -destinationDirectory $fullPkgDir

        # Copy the downloaded manifest to the package directory
        Copy-Item $manifestPath -Destination $fullPkgDir

        Write-Host "Download Complete: " $Engine.Name
    } else {
        Write-Host "Engine already up to date: " $Engine.Name
    }

    # Clean up
    if ($CleanUp) {
        CleanUpFolder -path $enginePath -itemsToKeep $VersionsToKeep
    }
}

#---------------------------------------------------------------------------------------
# Main Script
#---------------------------------------------------------------------------------------
Write-Host "Update Path: " $UpdatePathUrl
Write-Host "Engine Directory: " $EngineDirPath
Write-Host "Engines: " $Engines
Write-Host "Platforms: " $Platforms
Write-Host "CleanUp: " $CleanUp
Write-Host "VersionsToKeep: " $VersionsToKeep

if ((Test-Path $EngineDirPath) -ne $true) {
    $(throw "The directory specified to store the engines does not exist or the user this script is running as does not have permissions to access it. " + $EngineDirPath)
}

$tempFilePath = $EngineDirPath + "temp\"

$wc = New-Object System.Net.WebClient

$umFile = Invoke-UniversalManifestDownload -WebClient $wc -UpdatePathUrl $UpdatePathUrl -EngineDirPath $EngineDirPath -TempFilePath $tempFilePath

Invoke-EngineLicenseInfoDownload -WebClient $wc -UpdatePathUrl $UpdatePathUrl -EngineDirPath $EngineDirPath -UniversalManifest $umFile

Write-Host "Begin Processing Engine Updates"

# Process each engine in the Universal Manifest
# and download all applicable engines
foreach ($p in $Platforms) {
    $platform = Get-PlatformElement -UniversalManifest $umFile -PlatformName $p

    Write-Host "Platform: " $platform.id

    foreach ($e in $Engines) {
        $engine = Get-EngineElement -PlatformElement $platform -EngineName $e

        if ($null -eq $engine) {
            continue
        }

        Invoke-EngineUpdate -WebClient $wc -UpdatePathUrl $UpdatePathUrl -EngineDirPath $EngineDirPath -TempFilePath $tempFilePath -Platform $platform -Engine $engine -CleanUp:$CleanUp -VersionsToKeep $VersionsToKeep
    }
}

Write-Host "Engine Update processing completed."

# Clean up the temporary directory
# that is used during the update
Remove-Item $tempFilePath -Recurse
