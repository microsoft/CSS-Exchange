# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: Test-ExchAVExclusions.ps1
	Requires: Administrator rights
    Major Release History:
        06/16/2021 - Initial Release

.SYNOPSIS
Uses EICA7 files to verify that all Exchange paths that should be excluded from AV scanning are excluded.

.DESCRIPTION
Writes an EICAR test file https://en.wikipedia.org/wiki/EICAR_test_file to all paths specified by
https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019 and
https://docs.microsoft.com/en-us/exchange/anti-virus-software-in-the-operating-system-on-exchange-servers-exchange-2013-help


If the file is removed then the path is not properly excluded from AV Scanning.
IF the file is not removed then it should be properly excluded.

Once the files are created it will wait 60 seconds for AV to "see" and remove the file.

.PARAMETER Recurse
Will test not just the root folders but all subfolders.
Generally should not be needed unless all folders pass without -Recuse but AV is still suspected.

.OUTPUTS
Log file:
$env:LOCALAPPDATA\ExchAvExclusions.log

List of Scanned Folders:
$env:LOCALAPPDATA\BadExclusions.txt

.EXAMPLE
.\Test-ExchAVExclusions.ps1

Puts and removes an EICAR file in all test paths.

.EXAMPLE
.\Test-ExchAVExclusions.ps1 -Recurse

Puts and Remove an EICAR file in all test paths + all subfolders.

#>
[CmdletBinding()]
param (

    [Parameter()]
    [switch]
    $Recurse,

    [Parameter()]
    [switch]
    $OpenLog
)

. $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
. $PSScriptRoot\..\..\Shared\Get-ExchAVExclusions.ps1
. $PSScriptRoot\Write-SimpleLogFile.ps1
. $PSScriptRoot\Start-SleepWithProgress.ps1

# Log file name
$LogFile = "ExchAvExclusions.log"

# Open log file if switched
if ($OpenLog) { Write-SimpleLogFile -OpenLog -String " " -Name $LogFile }

# Confirm that we are an administrator
if (-not (Confirm-Administrator)) {
    Write-Error "Please run as Administrator"
    exit
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
$exchangeShell = Confirm-ExchangeShell
if (-not($exchangeShell.ShellLoaded)) {
    Write-Warning "Failed to load Exchange Shell Module..."
    exit
}

# Create the Array List
$BaseFolders = Get-ExchAVExclusionsPaths -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)

if ( $BaseFolders.count -eq 0 ) {
    Write-Warning "We do not detect folders to analyze"
    exit
}

# Create list object to hold all Folders we are going to test
$FolderList = New-Object Collections.Generic.List[string]

# Make sure each folders in our list resolve
foreach ($path in $BaseFolders) {
    try {
        # Resolve path only returns a bool so we have to manually throw to catch
        if (!(Resolve-Path -Path $path -ErrorAction SilentlyContinue)) {
            throw "Failed to resolve"
        }
        # If -recurse then we need to find all subfolders and Add them to the list to be tested
        if ($Recurse) {

            # Add the root folder
            $FolderList.Add($path.tolower())

            # Get the Folder and all subFolders and just return the fullname value as a string
            Get-ChildItem $path -Recurse -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName | ForEach-Object { $FolderList.Add($_.tolower()) }
        }
        # Just Add the root folder
        else { $FolderList.Add($path.tolower()) }
    } catch { Write-SimpleLogfile -string ("[ERROR] - Failed to resolve folder " + $path) -Name $LogFile }
}

# Remove any Duplicates
$FolderList = $FolderList | Select-Object -Unique

Write-SimpleLogfile -String "Creating EICAR Files" -name $LogFile -OutHost

# Create the EICAR file in each path
$EicarFileName = "eicar"
$EicarFileExt = "com"
$EicarFullFileName = "$EicarFileName.$EicarFileExt"

#Base64 of Eicar string
[string] $EncodedEicar = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='

foreach ($Folder in $FolderList) {

    [string] $FilePath = (Join-Path $Folder $EicarFullFileName)
    Write-SimpleLogfile -String ("Creating $EicarFullFileName file " + $FilePath) -name $LogFile

    if (!(Test-Path -Path $FilePath)) {

        # Try writing the encoded string to a the file
        try {
            [byte[]] $EicarBytes = [System.Convert]::FromBase64String($EncodedEicar)
            [string] $Eicar = [System.Text.Encoding]::UTF8.GetString($EicarBytes)
            [IO.File]::WriteAllText($FilePath, $Eicar)
        }

        catch {
            Write-Warning "$Folder $EicarFullFileName file couldn't be created. Either permissions or AV prevented file creation."
        }
    }

    else {
        Write-SimpleLogfile -string ("[WARNING] - $EicarFullFileName already exists!: " + $FilePath) -name $LogFile -OutHost
    }
}

# Create a random folder in root path
$randomString = -join ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object { [char]$_ })
$randomFolder = New-Item -Path (Join-Path (Join-Path $env:SystemDrive '\') "TestExchAVExclusions-$randomString") -ItemType Directory
$extensionsList = New-Object Collections.Generic.List[string]
$extensionsList = Get-ExchAVExclusionsExtensions -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)

if ($randomFolder) {
    foreach ($extension in $extensionsList) {
        $filepath = Join-Path $randomFolder "$EicarFileName.$extension"
        Write-SimpleLogfile -String ("Creating $EicarFileName.$extension file " + $FilePath) -name $LogFile

        if (!(Test-Path -Path $FilePath)) {

            # Try writing the encoded string to a the file
            try {
                [byte[]] $EicarBytes = [System.Convert]::FromBase64String($EncodedEicar)
                [string] $Eicar = [System.Text.Encoding]::UTF8.GetString($EicarBytes)
                [IO.File]::WriteAllText($FilePath, $Eicar)
            } catch {
                Write-Warning "$randomFolder $EicarFileName.$extension file couldn't be created. Either permissions or AV prevented file creation."
            }
        } else {
            Write-SimpleLogfile -string ("[WARNING] - $randomFolder $EicarFileName.$extension  already exists!: ") -name $LogFile -OutHost
        }
    }
} else {
    Write-Warning "We cannot create a folder in root path to test extension exclusions."
}

Write-SimpleLogfile -String "EICAR Files Created" -name $LogFile -OutHost

Write-SimpleLogfile -String "Accessing EICAR Files" -name $LogFile -OutHost
# Try to open each EICAR file to force detection in paths
$i = 0
foreach ($Folder in $FolderList) {
    $FilePath = (Join-Path $Folder $EicarFullFileName)
    if (Test-Path $FilePath -PathType Leaf) {
        Write-SimpleLogfile -String ("Opening $EicarFullFileName file " + $FilePath) -name $LogFile
        Start-Process -FilePath more -ArgumentList """$FilePath""" -ErrorAction SilentlyContinue -WindowStyle Hidden | Out-Null
    }
    $i++
}

# Try to open extensions:
$i = 0
foreach ($extension in $extensionsList) {
    $FilePath = Join-Path $randomFolder "$EicarFileName.$extension"
    if (Test-Path $FilePath -PathType Leaf) {
        Write-SimpleLogfile -String ("Opening $EicarFileName.$extension file " + $FilePath) -name $LogFile
        Start-Process -FilePath more -ArgumentList """$FilePath""" -ErrorAction SilentlyContinue -WindowStyle Hidden | Out-Null
    }
    $i++
}

Write-SimpleLogfile -String "Access EICAR Files Finished" -name $LogFile -OutHost

# Sleeping 5 minutes for AV to "find" the files
Start-SleepWithProgress -sleeptime 300 -message "Allowing time for AV to Scan"

# Create a list of folders that are probably being scanned by AV
$BadFolderList = New-Object Collections.Generic.List[string]

Write-SimpleLogfile -string "Testing for EICAR files" -name $LogFile -OutHost

# Test each location for the EICAR file
foreach ($Folder in $FolderList) {

    $FilePath = (Join-Path $Folder $EicarFullFileName)

    # If the file exists delete it -- this means the folder is not being scanned
    if (Test-Path $FilePath ) {
        #Get content to confirm that the file is not blocked by AV
        $output = Get-Content $FilePath -ErrorAction SilentlyContinue
        if ($output -eq $Eicar) {
            Write-SimpleLogfile -String ("Removing " + $FilePath) -name $LogFile
            Remove-Item $FilePath -Confirm:$false -Force
        } else {
            Write-SimpleLogfile -String ("[FAIL] - Possible AV Scanning on Path: " + $Folder) -name $LogFile -OutHost
            $BadFolderList.Add($Folder)
        }
    }
    # If the file doesn't exist Add that to the bad folder list -- means the folder is being scanned
    else {
        Write-SimpleLogfile -String ("[FAIL] - Possible AV Scanning on Path: " + $Folder) -name $LogFile -OutHost
        $BadFolderList.Add($Folder)
    }
}

$BadExtensionList = New-Object Collections.Generic.List[string]
# Test each extension for the EICAR file
foreach ($extension in $extensionsList) {

    $filepath = Join-Path $randomFolder "$EicarFileName.$extension"

    # If the file exists delete it -- this means the extension is not being scanned
    if (Test-Path $filepath ) {
        #Get content to confirm that the file is not blocked by AV
        $output = Get-Content $FilePath -ErrorAction SilentlyContinue
        if ($output -eq $Eicar) {
            Write-SimpleLogfile -String ("Removing " + $FilePath) -name $LogFile
            Remove-Item $FilePath -Confirm:$false -Force
        } else {
            Write-SimpleLogfile -String ("[FAIL] - Possible AV Scanning on Extension: " + $extension) -name $LogFile -OutHost
            $BadExtensionList.Add($extension)
        }
    }
    # If the file doesn't exist Add that to the bad extension list -- means the extension is being scanned
    else {
        Write-SimpleLogfile -String ("[FAIL] - Possible AV Scanning on Extension: " + $extension) -name $LogFile -OutHost
        $BadExtensionList.Add($extension)
    }
}

#Delete randon Folder
Remove-Item $randomFolder

# Report what we found
if ($BadFolderList.count -gt 0 -or $BadExtensionList.Count -gt 0 ) {
    $OutputPath = Join-Path $env:LOCALAPPDATA BadExclusions.txt
    $BadFolderList | Out-File $OutputPath
    $BadExtensionList | Out-File $OutputPath -Append

    Write-SimpleLogfile -String "Possbile AV Scanning found" -name $LogFile
    if ($BadFolderList.count -gt 0 ) {
        Write-Warning ("Found $($BadFolderList.count) of $($FolderList.Count) folders that are possibly being scanned! ")
    }
    if ($BadExtensionList.count -gt 0 ) {
        Write-Warning ("Found $($BadExtensionList.count) of $($extensionsList.Count) extensions that are possibly being scanned! ")
    }
    Write-Warning ("Review " + $OutputPath + " For the full list.")
} else {
    Write-SimpleLogfile -String "All EICAR files found; Exclusions appear to be set properly" -Name $LogFile -OutHost
}
