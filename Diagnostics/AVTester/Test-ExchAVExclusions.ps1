﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: Test-ExchAVExclusions.ps1
	Requires: Administrator rights
    Major Release History:
        06/16/2021 - Initial Release
        06/26/2023 - Added ability to scan processes

.SYNOPSIS
Uses EICAR files to verify that all Exchange paths that should be excluded from AV scanning are excluded.
Checks Exchange processes for Non-Default modules being loaded into them.

.DESCRIPTION
Writes an EICAR test file https://en.wikipedia.org/wiki/EICAR_test_file to all paths specified by
https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019 and
https://docs.microsoft.com/en-us/exchange/anti-virus-software-in-the-operating-system-on-exchange-servers-exchange-2013-help


If the file is removed then the path is not properly excluded from AV Scanning.
IF the file is not removed then it should be properly excluded.

Once the files are created it will wait 300 seconds for AV to "see" and remove the file.

Pulls all Exchange processes and their modules.
Excludes known modules and reports all Non-Default modules.

Non-Default modules should be reviewed to ensure they are expected.
AV Modules loaded into Exchange Processes may indicate that AV Process Exclusions are NOT properly configured.

.PARAMETER Recurse
Will test not just the root folders but all SubFolders.
Generally should not be needed unless all folders pass without -Recuse but AV is still suspected.

.OUTPUTS
Log file:
$env:LOCALAPPDATA\ExchAvExclusions.log

List of Scanned Folders:
$env:LOCALAPPDATA\BadExclusions.txt

List of Non-Default Processes
$env:LOCALAPPDATA NonDefaultModules.txt

.EXAMPLE
.\Test-ExchAVExclusions.ps1

Puts and removes an EICAR file in all test paths.

.EXAMPLE
.\Test-ExchAVExclusions.ps1 -Recurse

Puts and Remove an EICAR file in all test paths + all SubFolders.

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
. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

# Log file name
$LogFile = "ExchAvExclusions.log"

# Open log file if switched
if ($OpenLog) { Write-SimpleLogFile -OpenLog -String " " -Name $LogFile }

# Autoupdate script
if (Test-ScriptVersion -AutoUpdate) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command."
    return
}

# Confirm that we are an administrator
if (-not (Confirm-Administrator)) {
    Write-Error "Please run as Administrator"
    exit
}

$serverExchangeInstallDirectory = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue

# Check Exchange registry key
if (-not  $serverExchangeInstallDirectory ) {
    Write-Warning "Failed to find the Exchange installation Path registry key"
    exit
}

# Check the installation path
if (-not ( Test-Path $($serverExchangeInstallDirectory.MsiInstallPath) -PathType Container) ) {
    Write-Warning "Failed to find the Exchange installation Path"
    exit
}

# Check Exchange is 2013, 2016 or 2019
if ( -not ( $($serverExchangeInstallDirectory.MsiProductMajor) -eq 15 -and `
        ($($serverExchangeInstallDirectory.MsiProductMinor) -eq 0 -or $($serverExchangeInstallDirectory.MsiProductMinor) -eq 1 -or $($serverExchangeInstallDirectory.MsiProductMinor) -eq 2 ) ) ) {
    Write-Warning "This script is designed for Exchange 2013, 2016 or 2019"
    exit
}

$ExchangePath = $serverExchangeInstallDirectory.MsiInstallPath

# Check Exchange Shell and Exchange installation
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
        # If -recurse then we need to find all SubFolders and Add them to the list to be tested
        if ($Recurse) {

            # Add the root folder
            $FolderList.Add($path.ToLower())

            # Get the Folder and all subFolders and just return the fullName value as a string
            Get-ChildItem $path -Recurse -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName | ForEach-Object { $FolderList.Add($_.ToLower()) }
        }
        # Just Add the root folder
        else { $FolderList.Add($path.ToLower()) }
    } catch { Write-SimpleLogFile -string ("[ERROR] - Failed to resolve folder " + $path) -Name $LogFile }
}

# Remove any Duplicates
$FolderList = $FolderList | Select-Object -Unique

Write-SimpleLogFile -String "Creating EICAR Files" -name $LogFile -OutHost

# Create the EICAR file in each path
$eicarFileName = "eicar"
$eicarFileExt = "com"
$eicarFullFileName = "$eicarFileName.$eicarFileExt"

#Base64 of eicar string
[string] $EncodedEicar = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='

foreach ($Folder in $FolderList) {

    [string] $FilePath = (Join-Path $Folder $eicarFullFileName)
    Write-SimpleLogFile -String ("Creating $eicarFullFileName file " + $FilePath) -name $LogFile

    if (!(Test-Path -Path $FilePath)) {

        # Try writing the encoded string to a the file
        try {
            [byte[]] $eicarBytes = [System.Convert]::FromBase64String($EncodedEicar)
            [string] $eicar = [System.Text.Encoding]::UTF8.GetString($eicarBytes)
            [IO.File]::WriteAllText($FilePath, $eicar)
        }

        catch {
            Write-Warning "$Folder $eicarFullFileName file couldn't be created. Either permissions or AV prevented file creation."
        }
    }

    else {
        Write-SimpleLogFile -string ("[WARNING] - $eicarFullFileName already exists!: " + $FilePath) -name $LogFile -OutHost
    }
}

# Create a random folder in root path
$randomString = -join ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object { [char]$_ })
$randomFolder = New-Item -Path (Join-Path (Join-Path $env:SystemDrive '\') "TestExchAVExclusions-$randomString") -ItemType Directory
$extensionsList = New-Object Collections.Generic.List[string]
$extensionsList = Get-ExchAVExclusionsExtensions -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)

if ($randomFolder) {
    foreach ($extension in $extensionsList) {
        $filepath = Join-Path $randomFolder "$eicarFileName.$extension"
        Write-SimpleLogFile -String ("Creating $eicarFileName.$extension file " + $FilePath) -name $LogFile

        if (!(Test-Path -Path $FilePath)) {

            # Try writing the encoded string to a the file
            try {
                [byte[]] $eicarBytes = [System.Convert]::FromBase64String($EncodedEicar)
                [string] $eicar = [System.Text.Encoding]::UTF8.GetString($eicarBytes)
                [IO.File]::WriteAllText($FilePath, $eicar)
            } catch {
                Write-Warning "$randomFolder $eicarFileName.$extension file couldn't be created. Either permissions or AV prevented file creation."
            }
        } else {
            Write-SimpleLogFile -string ("[WARNING] - $randomFolder $eicarFileName.$extension  already exists!: ") -name $LogFile -OutHost
        }
    }
} else {
    Write-Warning "We cannot create a folder in root path to test extension exclusions."
}

Write-SimpleLogFile -String "EICAR Files Created" -name $LogFile -OutHost

Write-SimpleLogFile -String "Accessing EICAR Files" -name $LogFile -OutHost
# Try to open each EICAR file to force detection in paths
$i = 0
foreach ($Folder in $FolderList) {
    $FilePath = (Join-Path $Folder $eicarFullFileName)
    if (Test-Path $FilePath -PathType Leaf) {
        Write-SimpleLogFile -String ("Opening $eicarFullFileName file " + $FilePath) -name $LogFile
        Start-Process -FilePath more -ArgumentList """$FilePath""" -ErrorAction SilentlyContinue -WindowStyle Hidden | Out-Null
    }
    $i++
}

# Try to open extensions:
$i = 0
foreach ($extension in $extensionsList) {
    $FilePath = Join-Path $randomFolder "$eicarFileName.$extension"
    if (Test-Path $FilePath -PathType Leaf) {
        Write-SimpleLogFile -String ("Opening $eicarFileName.$extension file " + $FilePath) -name $LogFile
        Start-Process -FilePath more -ArgumentList """$FilePath""" -ErrorAction SilentlyContinue -WindowStyle Hidden | Out-Null
    }
    $i++
}

Write-SimpleLogFile -String "Access EICAR Files Finished" -name $LogFile -OutHost

# Sleeping 5 minutes for AV to "find" the files
Start-SleepWithProgress -SleepTime 300 -message "Allowing time for AV to Scan"

# Create a list of folders that are probably being scanned by AV
$BadFolderList = New-Object Collections.Generic.List[string]

Write-SimpleLogFile -string "Testing for EICAR files" -name $LogFile -OutHost

# Test each location for the EICAR file
foreach ($Folder in $FolderList) {

    $FilePath = (Join-Path $Folder $eicarFullFileName)

    # If the file exists delete it -- this means the folder is not being scanned
    if (Test-Path $FilePath ) {
        #Get content to confirm that the file is not blocked by AV
        $output = Get-Content $FilePath -ErrorAction SilentlyContinue
        if ($output -eq $eicar) {
            Write-SimpleLogFile -String ("Removing " + $FilePath) -name $LogFile
            Remove-Item $FilePath -Confirm:$false -Force
        } else {
            Write-SimpleLogFile -String ("[FAIL] - Possible AV Scanning on Path: " + $Folder) -name $LogFile -OutHost
            $BadFolderList.Add($Folder)
        }
    }
    # If the file doesn't exist Add that to the bad folder list -- means the folder is being scanned
    else {
        Write-SimpleLogFile -String ("[FAIL] - Possible AV Scanning on Path: " + $Folder) -name $LogFile -OutHost
        $BadFolderList.Add($Folder)
    }
}

$BadExtensionList = New-Object Collections.Generic.List[string]
# Test each extension for the EICAR file
foreach ($extension in $extensionsList) {

    $filepath = Join-Path $randomFolder "$eicarFileName.$extension"

    # If the file exists delete it -- this means the extension is not being scanned
    if (Test-Path $filepath ) {
        #Get content to confirm that the file is not blocked by AV
        $output = Get-Content $FilePath -ErrorAction SilentlyContinue
        if ($output -eq $eicar) {
            Write-SimpleLogFile -String ("Removing " + $FilePath) -name $LogFile
            Remove-Item $FilePath -Confirm:$false -Force
        } else {
            Write-SimpleLogFile -String ("[FAIL] - Possible AV Scanning on Extension: " + $extension) -name $LogFile -OutHost
            $BadExtensionList.Add($extension)
        }
    }
    # If the file doesn't exist Add that to the bad extension list -- means the extension is being scanned
    else {
        Write-SimpleLogFile -String ("[FAIL] - Possible AV Scanning on Extension: " + $extension) -name $LogFile -OutHost
        $BadExtensionList.Add($extension)
    }
}

#Delete Random Folder
Remove-Item $randomFolder

# Report what we found
if ($BadFolderList.count -gt 0 -or $BadExtensionList.Count -gt 0 ) {
    $OutputPath = Join-Path $env:LOCALAPPDATA BadExclusions.txt
    $BadFolderList | Out-File $OutputPath
    $BadExtensionList | Out-File $OutputPath -Append

    Write-SimpleLogFile -String "Possible AV Scanning found" -name $LogFile
    if ($BadFolderList.count -gt 0 ) {
        Write-Warning ("Found $($BadFolderList.count) of $($FolderList.Count) folders that are possibly being scanned! ")
    }
    if ($BadExtensionList.count -gt 0 ) {
        Write-Warning ("Found $($BadExtensionList.count) of $($extensionsList.Count) extensions that are possibly being scanned! ")
    }
    Write-Warning ("Review " + $OutputPath + " For the full list.")
} else {
    Write-SimpleLogFile -String "All EICAR files found; File Exclusions appear to be set properly" -Name $LogFile -OutHost
}

Write-SimpleLogFile -string "Testing for AV loaded in processes" -name $LogFile -OutHost

# Test Exchange Processes for unexpected modules
$ProcessList = Get-ExchAVExclusionsProcess -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)

# Gather all processes on the computer
$ServerProcess = Get-Process

# Module allow list
$ModuleAllowList = New-Object Collections.Generic.List[string]

# cSpell:disable
$ModuleAllowList.add("Google.Protobuf.ni.dll")
$ModuleAllowList.add("Microsoft.RightsManagementServices.Core.ni.dll")
$ModuleAllowList.add("Newtonsoft.Json.ni.dll")
$ModuleAllowList.add("Microsoft.Cloud.InstrumentationFramework.Events.ni.dll")
$ModuleAllowList.add("HealthServicePerformance.dll")
$ModuleAllowList.add("InterceptCounters.dll")
$ModuleAllowList.add("MOMConnectorPerformance.dll")
$ModuleAllowList.add("ExDbFailureItemApi.dll")
$ModuleAllowList.add("Microsoft.Cloud.InstrumentationFramework.Metrics.ni.dll")
$ModuleAllowList.add("IfxMetrics.dll")
$ModuleAllowList.add("ManagedBlingSigned.dll")
$ModuleAllowList.add("l3codecp.acm")
$ModuleAllowList.add("System.IdentityModel.Tokens.jwt.ni.dll")
# Oracle modules associated with 'Outside In® Technology'
$ModuleAllowList.add("wvcore.dll")
$ModuleAllowList.add("sccut.dll")
$ModuleAllowList.add("sccfut.dll")
$ModuleAllowList.add("sccfa.dll")
$ModuleAllowList.add("sccfi.dll")
$ModuleAllowList.add("sccch.dll")
$ModuleAllowList.add("sccda.dll")
$ModuleAllowList.add("sccfmt.dll")
$ModuleAllowList.add("sccind.dll")
$ModuleAllowList.add("sccca.dll")
$ModuleAllowList.add("scclo.dll")
$ModuleAllowList.add("SCCOLE2.DLL")
$ModuleAllowList.add("SCCSD.DLL")
$ModuleAllowList.add("SCCXT.DLL")
# cSpell:enable

Write-SimpleLogFile -string ("Allow List Module Count: " + $ModuleAllowList.count) -Name $LogFile

$UnexpectedModuleFound = 0

# Gather each process and work thru their module list to remove any known modules.
foreach ($process in $ServerProcess) {

    # Determine if it is a known exchange process
    if ($ProcessList -contains $process.path ) {

        # Gather all modules
        [array]$ProcessModules = $process.modules

        # Remove Microsoft modules
        $ProcessModules = $ProcessModules | Where-Object { $_.FileVersionInfo.CompanyName -ne "Microsoft Corporation." -and $_.FileVersionInfo.CompanyName -ne "Microsoft" -and $_.FileVersionInfo.CompanyName -ne "Microsoft Corporation" }

        # Generate and output path for an Non-Default modules file:
        $OutputProcessPath = Join-Path $env:LOCALAPPDATA NonDefaultModules.txt

        # Clear out modules from the allow list
        foreach ($module in $ModuleAllowList) {
            $ProcessModules = $ProcessModules | Where-Object { $_.ModuleName -ne $module }
        }

        if ($ProcessModules.count -gt 0) {
            Write-Warning ("Possible AV Modules found in process $($process.ProcessName)")
            $UnexpectedModuleFound++
            foreach ($module in $ProcessModules) {
                $OutString = ("[FAIL] - PROCESS: $($process.ProcessName) MODULE: $($module.ModuleName) COMPANY: $($module.Company)")
                Write-SimpleLogFile -string $OutString -Name $LogFile
                $OutString | Out-File $OutputProcessPath -Append
            }
        }
    }
}

# Final output for process detection
if ($UnexpectedModuleFound -gt 0) {
    Write-SimpleLogFile -string ("Found $($UnexpectedModuleFound) processes with unexpected modules loaded") -Name $LogFile -OutHost
    Write-SimpleLogFile ("AV Modules loaded in Exchange processes may indicate that exclusions are not properly configured.") -Name $LogFile -OutHost
    Write-SimpleLogFile ("Non AV Modules loaded into Exchange processes may be expected depending on applications installed.") -Name $LogFile -OutHost
    Write-Warning ("Review " + $OutputProcessPath + " For more information.")
} else {
    Write-SimpleLogFile -string ("Did not find any Non-Default modules loaded.") -Name $LogFile -OutHost
}
