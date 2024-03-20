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
    [switch]$SkipVersionCheck
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

$UmFileName = "UniversalManifest.cab"
$EliFileName = "EngineInfo.cab"

# Checks if the specified path exists.
# If not the directory is created.
function CreatePath($path) {
    if ((Test-Path $path) -ne $true) {
        New-Item -type Directory $path
        Write-Host "Created: " $path
    }
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

#---------------------------------------------------------------------------------------
# Main Script
#---------------------------------------------------------------------------------------
Write-Host "Update Path: " $UpdatePathUrl
Write-Host "Engine Directory: " $EngineDirPath
Write-Host "Engines: " $Engines
Write-Host "Platforms: " $Platforms

if ((Test-Path $EngineDirPath) -ne $true) {
    $(throw "The directory specified to store the engines does not exist or the user this script is running as does not have permissions to access it. " + $EngineDirPath)
}

$tempFilePath = $EngineDirPath + "temp\"

$wc = New-Object System.Net.WebClient

# Download the Universal Manifest file
$url = ($UpdatePathUrl + "metadata/$($UmFileName)")
$umFilePath = $EngineDirPath + "metadata\$($UmFileName)"

$metaDataDir = $EngineDirPath + "metadata\"

CreatePath $metaDataDir

$wc.DownloadFile($url, $umFilePath)

CreatePath $tempFilePath

# Delete any temporary files left over from
# any previous runs of the script
Remove-Item ($tempFilePath + "*.*")

# Extract the xml file from the cab
# so we can parse and read the data
ExtractCab $umFilePath $tempFilePath

# Read in and process the contents of the
# Universal Manifest file.
[xml]$umFile = Get-Content($tempFilePath + "UniversalManifest.xml")

# Check if we need to download a new Engine License Info file
$engineInfoVersion = $umFile.UniversalManifest.licenseInfoVersion
Write-Host "The current Engine License Info version: " $engineInfoVersion

$engineInfoFilePath = $EngineDirPath + "metadata\" + $engineInfoVersion

CreatePath $engineInfoFilePath

$engineInfoFilePath += "\" + $EliFileName

# If the versioned directory does not exists
# download the new version of the Engine License Info
if ((Test-Path $engineInfoFilePath) -ne $true) {
    Write-Host "The current version of the Engine License Info needs to be downloaded."

    $engineInfoURL = ($UpdatePathUrl + "\metadata\" + $engineInfoVersion + "/" + $EliFileName)
    $wc.DownloadFile($engineInfoURL, $engineInfoFilePath)

    Write-Host "The Engine License Info download is complete."
}

Write-Host "Begin Processing Engine Updates"

# Process each engine in the Universal Manifest
# and download all applicable engines
foreach ($p in $Platforms) {
    $platform = $umFile.UniversalManifest.EngineVersions.SelectSingleNode(("Platform[@id='" + $p + "']"))

    if ($platform -isnot [System.Xml.XmlElement]) {
        $(throw "The Platform '" + $p + "' is not valid.")
    }

    Write-Host "Platform: " $platform.id

    foreach ($e in $Engines) {
        $engine = $platform.SelectSingleNode(("Category/Engine[@name='" + $e + "']"))

        if ($engine -isnot [System.Xml.XmlElement]) {
            $errMsg = "The engine name '" + $e + "' is not valid."
            Write-Error $errMsg -Category InvalidArgument
        } else {
            Write-Host "Engine: $($engine.Name) UpdateVersion: $($engine.Package.version)"

            $manifestFileNameRoot = "manifest." + $engine.Default
            $manifestFileName = $manifestFileNameRoot + ".cab"
            $engineUrl = $UpdatePathUrl + $platform.id + "/" + $engine.Name + "/" + "Package/"
            $manifestUrl =  ($engineUrl + $manifestFileName)
            $enginePath = $EngineDirPath + $platform.id + "\" + $engine.Name + "\Package\"

            Write-Host "Begin download: $($engine.Name) Url: $($manifestUrl)"

            CreatePath $enginePath

            $manifestPath = $enginePath + $manifestFileName

            $wc.DownloadFile($manifestUrl, $manifestPath)

            # Delete any temporary files left over from
            # any previous runs of the script
            Remove-Item ($tempFilePath + "*.*")

            ExtractCab $manifestPath $tempFilePath

            [xml]$manifest = Get-Content($tempFilePath + "manifest.xml")

            $fullPkgDir = $enginePath + $manifest.ManifestFile.Package.version + "\"

            CreatePath $fullPkgDir

            $fullPkgUrl = $engineUrl + $manifest.ManifestFile.Package.version + "/" + $manifest.ManifestFile.Package.FullPackage.name
            $fullPkgPath = ($fullPkgDir + $manifest.ManifestFile.Package.FullPackage.name)

            $wc.DownloadFile($fullPkgUrl, $fullPkgPath)

            # Detect if there are any subdirectories
            # needed for this engine
            $subDirCount = $manifest.ManifestFile.Package.Files.Dir.Count

            for ($i=0; $i -lt $subDirCount; $i++) {
                CreatePath ($fullPkgDir + $manifest.ManifestFile.Package.Files.Dir[$i].name)
            }

            ExtractCab $fullPkgPath $fullPkgDir

            # Copy the downloaded manifest to the package directory
            Copy-Item $manifestPath -Destination $fullPkgDir

            Write-Host "Download Complete: " $engine.Name
        }
    }
}

Write-Host "Engine Update processing completed."

# Clean up the temporary directory
# that is used during the update
Remove-Item $tempFilePath -Recurse
