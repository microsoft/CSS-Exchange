# Copyright (c) Microsoft Corporation.
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

.PARAMETER WaitingTimeForAVAnalysisInMinutes
Set the waiting time for AV to analyze the EICAR files. Default is 5 minutes.

.PARAMETER OpenLog
Open the log file after the script finishes.

.PARAMETER SkipVersionCheck
Skip script version verification.

.PARAMETER ScriptUpdateOnly
Just update script version to latest one.

.OUTPUTS
Log file:
$PSScriptRoot\ExchAvExclusions.log

List of Scanned Folders:
$PSScriptRoot\BadExclusions.txt

.EXAMPLE
.\Test-ExchAVExclusions.ps1

Puts and removes an EICAR file in all test paths.

.EXAMPLE
.\Test-ExchAVExclusions.ps1 -Recurse

Puts and Remove an EICAR file in all test paths + all SubFolders.

#>
[CmdletBinding(DefaultParameterSetName = 'Test')]
param (

    [Parameter(ParameterSetName = "Test")]
    [int]$WaitingTimeForAVAnalysisInMinutes = 5,

    [Parameter(ParameterSetName = "Test")]
    [switch]$Recurse,

    [Parameter(ParameterSetName = "Test")]
    [switch]$OpenLog,

    [Parameter(ParameterSetName = "Test")]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

. $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
. $PSScriptRoot\..\..\Shared\Get-ExchAVExclusions.ps1
. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\Write-SimpleLogFile.ps1

$BuildVersion = ""

Write-Host ("Test-ExchAVExclusions.ps1 script version $($BuildVersion)") -ForegroundColor Green

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/Test-ExchAVExclusions-VersionsURL" -Confirm:$false) {
    ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
    ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
    }
    return
}

if ((-not($SkipVersionCheck)) -and
    (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/Test-ExchAVExclusions-VersionsURL" -Confirm:$false)) {
    Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
    return
}

# Log file name
$LogFileName = Join-Path $PSScriptRoot ExchAvExclusions.log

# Open log file if switched
if ($OpenLog) { Write-SimpleLogFile -OpenLog -String " " -LogFile $LogFileName }

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

Write-SimpleLogFile -String ("###########################################################################################") -LogFile $LogFileName
Write-SimpleLogFile -String ("Starting AV Exclusions analysis at $((Get-Date).ToString())") -LogFile $LogFileName
Write-SimpleLogFile -String ("###########################################################################################") -LogFile $LogFileName
Write-SimpleLogFile -String ("You can find a detailed log on: $LogFileName") -LogFile $LogFileName -OutHost

# Create the Array List
$BaseFolders = Get-ExchAVExclusionsPaths -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)

if ( $BaseFolders.count -eq 0 ) {
    Write-Warning "We do not detect folders to analyze"
    exit
}

# Create list object to hold all Folders we are going to test
$FolderList = New-Object Collections.Generic.List[string]

$randomCharForWildCard = (Get-Random -Maximum 16).ToString('x')
$nonExistentFolder = New-Object Collections.Generic.List[string]

foreach ($path in $BaseFolders) {
    try {
        if ($path -match '\?') {
            $path = $path -replace '\?', $randomCharForWildCard
            $FolderList.Add($path.ToLower())
            $nonExistentFolder.Add($path.ToLower())
            New-Item -Path (Split-Path $path) -Name $path.split('\')[-1] -ItemType Directory -Force | Out-Null
            Write-SimpleLogFile -string ("Created folder: " + $path) -LogFile $LogFileName
        }
        # Resolve path only returns a bool so we have to manually throw to catch
        if (!(Resolve-Path -Path $path -ErrorAction SilentlyContinue)) {
            $nonExistentFolder.Add($path.ToLower())
            New-Item -Path (Split-Path $path) -Name $path.split('\')[-1] -ItemType Directory -Force | Out-Null
            Write-SimpleLogFile -string ("Created folder: " + $path) -LogFile $LogFileName
        }

        # If -recurse then we need to find all SubFolders and Add them to the list to be tested
        if ($Recurse) {

            # Add the root folder
            $FolderList.Add($path.ToLower())

            # Get the Folder and all subFolders and just return the fullName value as a string
            Get-ChildItem $path -Recurse -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName | ForEach-Object { $FolderList.Add($_.ToLower()) }
        }
        # Just Add the root folder
        $FolderList.Add($path.ToLower())
    } catch { Write-SimpleLogFile -string ("[ERROR] - Failed to resolve folder " + $path) -LogFile $LogFileName }
}

# Remove any Duplicates
$FolderList = $FolderList | Select-Object -Unique

Write-SimpleLogFile -String "Creating EICAR Files" -LogFile $LogFileName -OutHost

# Create the EICAR file in each path
$eicarFileName = "eicar"
$eicarFileExt = "com"
$eicarFullFileName = "$eicarFileName.$eicarFileExt"

#Base64 of eicar string
[string] $EncodedEicar = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='

foreach ($Folder in $FolderList) {

    [string] $FilePath = (Join-Path $Folder $eicarFullFileName)
    Write-SimpleLogFile -String ("Creating $eicarFullFileName file " + $FilePath) -LogFile $LogFileName

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
    } else {
        Write-SimpleLogFile -string ("[WARNING] - $eicarFullFileName already exists!: " + $FilePath) -LogFile $LogFileName -OutHost
    }
}

# Create a random folder in root path
$randomString = -join ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object { [char]$_ })
$randomFolder = New-Item -Path (Join-Path (Join-Path $env:SystemDrive '\') "TestExchAVExclusions-$randomString") -ItemType Directory
$extensionsList = New-Object Collections.Generic.List[string]
$extensionsList = Get-ExchAVExclusionsExtensions -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)

if ($randomFolder) {
    foreach ($extension in $extensionsList) {
        $filepath = Join-Path $randomFolder "$eicarFileName.$extension"
        Write-SimpleLogFile -String ("Creating $eicarFileName.$extension file " + $FilePath) -LogFile $LogFileName

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
            Write-SimpleLogFile -string ("[WARNING] - $randomFolder $eicarFileName.$extension  already exists!: ") -LogFile $LogFileName -OutHost
        }
    }
} else {
    Write-Warning "We cannot create a folder in root path to test extension exclusions."
}

Write-SimpleLogFile -String "EICAR Files Created" -LogFile $LogFileName -OutHost

Write-SimpleLogFile -String "Accessing EICAR Files" -LogFile $LogFileName -OutHost
# Try to open each EICAR file to force detection in paths
$i = 0
foreach ($Folder in $FolderList) {
    $FilePath = (Join-Path $Folder $eicarFullFileName)
    if (Test-Path $FilePath -PathType Leaf) {
        Write-SimpleLogFile -String ("Opening $eicarFullFileName file " + $FilePath) -LogFile $LogFileName
        Start-Process -FilePath more -ArgumentList """$FilePath""" -ErrorAction SilentlyContinue -WindowStyle Hidden | Out-Null
    }
    $i++
}

# Try to open extensions:
$i = 0
foreach ($extension in $extensionsList) {
    $FilePath = Join-Path $randomFolder "$eicarFileName.$extension"
    if (Test-Path $FilePath -PathType Leaf) {
        Write-SimpleLogFile -String ("Opening $eicarFileName.$extension file " + $FilePath) -LogFile $LogFileName
        Start-Process -FilePath more -ArgumentList """$FilePath""" -ErrorAction SilentlyContinue -WindowStyle Hidden | Out-Null
    }
    $i++
}

Write-SimpleLogFile -String "Access EICAR Files Finished" -LogFile $LogFileName -OutHost

$StartDate = Get-Date
[int]$initialDiff = (New-TimeSpan -End $StartDate.AddMinutes($WaitingTimeForAVAnalysisInMinutes) -Start $StartDate).TotalSeconds
$currentDiff = $initialDiff
$firstExecution = $true
$SuspiciousProcessList = New-Object Collections.Generic.List[string]
$SuspiciousW3wpProcessList = New-Object Collections.Generic.List[string]

Write-SimpleLogFile -String "Analyzing Exchange Processes" -LogFile $LogFileName -OutHost
while ($currentDiff -gt 0) {
    if ($firstExecution) {
        # Test Exchange Processes for unexpected modules
        $ProcessList = Get-ExchAVExclusionsProcess -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)

        # Include w3wp process in the analysis
        $ProcessList += (Join-Path $env:SystemRoot '\System32\inetSrv\W3wp.exe')

        # Gather all processes on the computer
        $ServerProcess = Get-Process | Sort-Object -Property ProcessName

        # Module allow list
        $ModuleAllowList = New-Object Collections.Generic.List[string]

        # cSpell:disable
        $ModuleAllowList.add("Google.Protobuf.dll")
        $ModuleAllowList.add("Microsoft.RightsManagementServices.Core.dll")
        $ModuleAllowList.add("Newtonsoft.Json.dll")
        $ModuleAllowList.add("Microsoft.Cloud.InstrumentationFramework.Events.dll")
        $ModuleAllowList.add("HealthServicePerformance.dll")
        $ModuleAllowList.add("InterceptCounters.dll")
        $ModuleAllowList.add("MOMConnectorPerformance.dll")
        $ModuleAllowList.add("ExDbFailureItemApi.dll")
        $ModuleAllowList.add("Microsoft.Cloud.InstrumentationFramework.Metrics.dll")
        $ModuleAllowList.add("IfxMetrics.dll")
        $ModuleAllowList.add("ManagedBlingSigned.dll")
        $ModuleAllowList.add("l3codecp.acm")
        $ModuleAllowList.add("System.IdentityModel.Tokens.jwt.dll")
        $ModuleAllowList.add("prxyqry.DLL")
        # cSpell:enable

        Write-SimpleLogFile -string ("Allow List Module Count: " + $ModuleAllowList.count) -LogFile $LogFileName

        # Gather each process and work thru their module list to remove any known modules.
        foreach ($process in $ServerProcess) {

            Write-Progress -Activity "Checking Exchange Processes" -CurrentOperation "$currentDiff More Seconds" -PercentComplete ((($initialDiff - $currentDiff) / $initialDiff) * 100) -Status " "
            [int]$currentDiff = (New-TimeSpan -End $StartDate.AddMinutes($WaitingTimeForAVAnalysisInMinutes) -Start (Get-Date)).TotalSeconds

            # Determine if it is a known exchange process
            if ($ProcessList -contains $process.path ) {

                # Gather all modules
                [array]$ProcessModules = $process.modules

                # Remove Microsoft modules
                $ProcessModules = $ProcessModules | Where-Object { $_.FileVersionInfo.CompanyName -ne "Microsoft Corporation." -and $_.FileVersionInfo.CompanyName -ne "Microsoft" -and $_.FileVersionInfo.CompanyName -ne "Microsoft Corporation" }

                # Remove Oracle modules on FIPS
                $ProcessModules = $ProcessModules | Where-Object { (($_.FileName -notlike "*\FIP-FS\Bin\*" -and $_.FileVersionInfo.CompanyName -ne "Oracle Corporation")) }

                # Clear out modules from the allow list
                foreach ($module in $ModuleAllowList) {
                    $ProcessModules = $ProcessModules | Where-Object { $_.ModuleName -ne $module -and $_.ModuleName -ne $($module.Replace(".dll", ".ni.dll")) }
                }

                if ($ProcessModules.count -gt 0) {
                    foreach ($module in $ProcessModules) {
                        $OutString = ("PROCESS: $($process.ProcessName) PID($($process.Id)) UNEXPECTED MODULE: $($module.ModuleName) COMPANY: $($module.Company)`n`tPATH: $($module.FileName)")
                        Write-SimpleLogFile -string "[FAIL] - $OutString" -LogFile $LogFileName -OutHost
                        if ($process.MainModule.ModuleName -eq "W3wp.exe") {
                            $SuspiciousW3wpProcessList += $OutString
                        } else {
                            $SuspiciousProcessList += $OutString
                        }
                    }
                }
            }
        }
        $firstExecution = $false
    } else {
        Start-Sleep -Seconds 1
        Write-Progress -Activity "Waiting for AV" -CurrentOperation "$currentDiff More Seconds" -PercentComplete ((($initialDiff - $currentDiff) / $initialDiff) * 100) -Status " "
        [int]$currentDiff = (New-TimeSpan -End $StartDate.AddMinutes($WaitingTimeForAVAnalysisInMinutes) -Start (Get-Date)).TotalSeconds
    }
}
Write-SimpleLogFile -String "Analyzed Exchange Processes" -LogFile $LogFileName -OutHost

# Create a list of folders that are probably being scanned by AV
$BadFolderList = New-Object Collections.Generic.List[string]

Write-SimpleLogFile -string "Testing for EICAR files" -LogFile $LogFileName -OutHost

# Test each location for the EICAR file
foreach ($Folder in $FolderList) {

    $FilePath = (Join-Path $Folder $eicarFullFileName)

    # If the file exists delete it -- this means the folder is not being scanned
    if (Test-Path $FilePath ) {
        #Get content to confirm that the file is not blocked by AV
        $output = Get-Content $FilePath -ErrorAction SilentlyContinue
        if ($output -eq $eicar) {
            Write-SimpleLogFile -String ("Removing " + $FilePath) -LogFile $LogFileName
            Remove-Item $FilePath -Confirm:$false -Force
        } else {
            Write-SimpleLogFile -String ("[FAIL] - Possible AV Scanning on Path: " + $Folder) -LogFile $LogFileName -OutHost
            $BadFolderList.Add($Folder)
        }
    }
    # If the file doesn't exist Add that to the bad folder list -- means the folder is being scanned
    else {
        Write-SimpleLogFile -String ("[FAIL] - Possible AV Scanning on Path: " + $Folder) -LogFile $LogFileName -OutHost
        $BadFolderList.Add($Folder)
    }

    if ($nonExistentFolder -contains $Folder) {
        Remove-Item $Folder -Confirm:$false -Force -Recurse
        Write-SimpleLogFile -string ("Removed folder: " + $Folder) -LogFile $LogFileName
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
            Write-SimpleLogFile -String ("Removing " + $FilePath) -LogFile $LogFileName
            Remove-Item $FilePath -Confirm:$false -Force
        } else {
            Write-SimpleLogFile -String ("[FAIL] - Possible AV Scanning on Extension: " + $extension) -LogFile $LogFileName -OutHost
            $BadExtensionList.Add($extension)
        }
    }
    # If the file doesn't exist Add that to the bad extension list -- means the extension is being scanned
    else {
        Write-SimpleLogFile -String ("[FAIL] - Possible AV Scanning on Extension: " + $extension) -LogFile $LogFileName -OutHost
        $BadExtensionList.Add($extension)
    }
}

#Delete Random Folder
Remove-Item $randomFolder

$OutputPath = Join-Path $PSScriptRoot BadExclusions.txt
"###########################################################################################" | Out-File $OutputPath
"Exclusions analysis at $((Get-Date).ToString())" | Out-File $OutputPath -Append
"###########################################################################################" | Out-File $OutputPath -Append

# Report what we found
if ($BadFolderList.count -gt 0 -or $BadExtensionList.Count -gt 0 -or $SuspiciousProcessList.count -gt 0 -or $SuspiciousW3wpProcessList.count -gt 0) {

    Write-SimpleLogFile -String "Possible AV Scanning found" -LogFile $LogFileName
    if ($BadFolderList.count -gt 0 ) {
        "`n[Missing Folder Exclusions]" | Out-File $OutputPath -Append
        $BadFolderList | Out-File $OutputPath -Append
        Write-Warning ("Found $($BadFolderList.count) of $($FolderList.Count) folders that are possibly being scanned! ")
    }
    if ($BadExtensionList.count -gt 0 ) {
        "`n[Missing Extension Exclusions]" | Out-File $OutputPath -Append
        $BadExtensionList | Out-File $OutputPath -Append
        Write-Warning ("Found $($BadExtensionList.count) of $($extensionsList.Count) extensions that are possibly being scanned! ")
    }
    if ($SuspiciousProcessList.count -gt 0 ) {
        "`n[Non-Default Modules Loaded]" | Out-File $OutputPath -Append
        $SuspiciousProcessList | Out-File $OutputPath -Append
        Write-Warning ("Found $($SuspiciousProcessList.count) UnExpected modules loaded into Exchange Processes ")
    }
    if ($SuspiciousW3wpProcessList.count -gt 0 ) {
        $SuspiciousW3wpProcessListString = "`n[WARNING] - W3wp.exe is not present in the recommended Exclusion list but we found 3rd Party modules on it and could affect Exchange performance or functionality."
        $SuspiciousW3wpProcessListString | Out-File $OutputPath -Append
        Write-Warning $SuspiciousW3wpProcessListString
        Write-SimpleLogFile -string $SuspiciousW3wpProcessListString -LogFile $LogFileName
        "`n[Non-Default Modules Loaded on W3wp.exe]" | Out-File $OutputPath -Append
        $SuspiciousW3wpProcessList | Out-File $OutputPath -Append
        Write-Warning ("Found $($SuspiciousW3wpProcessList.count) UnExpected modules loaded into W3wp.exe ")
    }
    Write-Warning ("Review " + $OutputPath + " For the full list.")
} else {
    $CorrectExclusionsString = "`nAll EICAR files found; File Exclusions, Extensions Exclusions and Processes Exclusions (Did not find Non-Default modules loaded) appear to be set properly"
    $CorrectExclusionsString | Out-File $OutputPath -Append
    Write-SimpleLogFile -String $CorrectExclusionsString -LogFile $LogFileName -OutHost
}

Write-SimpleLogFile -string "Testing for AV loaded in processes" -LogFile $LogFileName -OutHost
