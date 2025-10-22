﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: Test-ExchAVExclusions.ps1
	Requires: Administrator rights
    Major Release History:
        06/16/2021 - Initial Release
        06/26/2023 - Added ability to scan processes
        02/10/2025 - Added AMSI detection

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

.PARAMETER SkipVersionCheck
Skip script version verification.

.PARAMETER ScriptUpdateOnly
Just update script version to latest one.

.OUTPUTS
Log file:
$PSScriptRoot\Test-ExchAvExclusions-#DataTime#.txt

List of Scanned Folders:
$PSScriptRoot\BadExclusions-#DataTime#.txt

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
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

. $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
. $PSScriptRoot\..\..\Shared\Get-ExchAVExclusions.ps1
. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Warning.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Progress.ps1

function Write-DebugLog ($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $message
    }
}

function Write-HostLog ($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $message
        $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $message
    }
}

$LogFileName = "Test-ExchAvExclusions"
$StartDate = Get-Date
$StartDateFormatted = ($StartDate).ToString("yyyyMMddhhmmss")
$Script:DebugLogger = Get-NewLoggerInstance -LogName "$LogFileName-Debug-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue
$Script:HostLogger = Get-NewLoggerInstance -LogName "$LogFileName-Results-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue

SetWriteHostAction ${Function:Write-HostLog}
SetWriteProgressAction ${Function:Write-DebugLog}
SetWriteVerboseAction ${Function:Write-DebugLog}
SetWriteWarningAction ${Function:Write-HostLog}

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

# Confirm that we are an administrator
if (-not (Confirm-Administrator)) {
    Write-Host "[ERROR]: Please run as Administrator" -ForegroundColor Red
    exit
}

$serverExchangeInstallDirectory = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue

# Check Exchange registry key
if (-not  $serverExchangeInstallDirectory ) {
    Write-Host "[ERROR]: Failed to find the Exchange installation Path registry key" -ForegroundColor Red
    exit
}

# Check the installation path
if (-not ( Test-Path $($serverExchangeInstallDirectory.MsiInstallPath) -PathType Container) ) {
    Write-Host "[ERROR]: Failed to find the Exchange installation Path" -ForegroundColor Red
    exit
}

# Check Exchange is 2013, 2016 or 2019
if ( -not ( $($serverExchangeInstallDirectory.MsiProductMajor) -eq 15 -and `
        ($($serverExchangeInstallDirectory.MsiProductMinor) -eq 0 -or $($serverExchangeInstallDirectory.MsiProductMinor) -eq 1 -or $($serverExchangeInstallDirectory.MsiProductMinor) -eq 2 ) ) ) {
    Write-Host "[ERROR]: This script is designed for Exchange 2013, 2016 or 2019" -ForegroundColor Red
    exit
}

$ExchangePath = $serverExchangeInstallDirectory.MsiInstallPath

# Check Exchange Shell and Exchange installation
$exchangeShell = Confirm-ExchangeShell
if (-not($exchangeShell.ShellLoaded)) {
    Write-Host "Failed to load Exchange Shell Module..." -ForegroundColor Red
    exit
}

Write-Host "###########################################################################################"
Write-Host "Starting AV Exclusions analysis at $(($StartDate).ToString())"
Write-Host "###########################################################################################"
Write-Host "You can find a simple log on: $LogFileName-Results-$StartDateFormatted.txt"
Write-Host "And a detailed log on: $LogFileName-Debug-$StartDateFormatted.txt"

# Create the Array List
$BaseFolders = Get-ExchAVExclusionsPaths -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)

if ( $BaseFolders.count -eq 0 ) {
    Write-Host "We do not detect folders to analyze" -ForegroundColor Red
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
            Write-Verbose "Created folder: $path"
        }

        # Resolve path only returns a bool so we have to manually throw to catch
        if (!(Resolve-Path -Path $path -ErrorAction SilentlyContinue)) {
            $nonExistentFolder.Add($path.ToLower())
            New-Item -Path (Split-Path $path) -Name $path.split('\')[-1] -ItemType Directory -Force | Out-Null
            Write-Verbose "Created folder: $path"
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
    } catch { Write-Verbose "[ERROR] - Failed to resolve folder $path" -ForegroundColor Red }
}

# Remove any Duplicates
$FolderList = $FolderList | Select-Object -Unique

Write-Host "Creating EICAR Files"

# Create the EICAR file in each path
$eicarFileName = "eicar"
$eicarFileExt = "com"
$eicarFullFileName = "$eicarFileName.$eicarFileExt"

#Base64 of eicar string
[string] $EncodedEicar = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='

foreach ($Folder in $FolderList) {

    [string] $FilePath = (Join-Path $Folder $eicarFullFileName)
    Write-Verbose "Creating $eicarFullFileName file $FilePath"

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
        Write-Warning "$eicarFullFileName already exists!:  $FilePath"
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
        Write-Verbose "Creating $eicarFileName.$extension file $FilePath"

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
            Write-Warning "$randomFolder $eicarFileName.$extension  already exists!: "
        }
    }
} else {
    Write-Warning "We cannot create a folder in root path to test extension exclusions."
}

Write-Host "EICAR Files Created"

Write-Host "Accessing EICAR Files"
# Try to open each EICAR file to force detection in paths
$i = 0
foreach ($Folder in $FolderList) {
    $FilePath = (Join-Path $Folder $eicarFullFileName)
    if (Test-Path $FilePath -PathType Leaf) {
        Write-Verbose "Opening $eicarFullFileName file $FilePath"
        Start-Process -FilePath more -ArgumentList """$FilePath""" -ErrorAction SilentlyContinue -WindowStyle Hidden | Out-Null
    }
    $i++
}

# Try to open extensions:
$i = 0
foreach ($extension in $extensionsList) {
    $FilePath = Join-Path $randomFolder "$eicarFileName.$extension"
    if (Test-Path $FilePath -PathType Leaf) {
        Write-Verbose "Opening $eicarFileName.$extension file $FilePath"
        Start-Process -FilePath more -ArgumentList """$FilePath""" -ErrorAction SilentlyContinue -WindowStyle Hidden | Out-Null
    }
    $i++
}

Write-Host "Access EICAR Files Finished"

[int]$initialDiff = (New-TimeSpan -End $StartDate.AddMinutes($WaitingTimeForAVAnalysisInMinutes) -Start $StartDate).TotalSeconds
$currentDiff = $initialDiff
$firstExecution = $true
$SuspiciousProcessList = New-Object Collections.Generic.List[string]
$SuspiciousAMSIProcessList = New-Object Collections.Generic.List[string]

# Get AMSI Dlls registered
# Define the AMSI providers registry path
$registryPath = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"

$subKeys = $null
$AMSIDll = New-Object Collections.Generic.List[string]
# Get all subKeys in the specified registry path
$subKeys = Get-ChildItem -Path $registryPath -ErrorAction SilentlyContinue

if ($subKeys) {
    foreach ($subKey in $subKeys) {
        $matchingSubKeys = $null
        # Filter the subKeys that match the regular expression and get only their names
        $matchingSubKeys = $subKey -match '[0-9A-Fa-f\-]{36}'
        if ($matchingSubKeys) {
            foreach ($m in $Matches.Values) {
                $foundDll = (Get-Item "HKLM:\SOFTWARE\Classes\ClSid\{$m}\InprocServer32" -ErrorAction SilentlyContinue).GetValue("").trim('"')
                if ($null -eq $foundDll) {
                    Write-Host "No AMSI Dlls was found for $m, possible AMSI misconfiguration" -ForegroundColor Red
                } else {
                    Write-Verbose "AMSI $m was found"
                    $AMSIDll.Add($foundDll)
                    if ($foundDll -like "*MpOav.dll") {
                    $defenderPath = Split-Path $foundDll -Parent
                    $mpClientPath = Join-Path $defenderPath "MPCLIENT.DLL"
                    if (Test-Path $mpClientPath) {
                        Write-Verbose "Adding Windows Defender MPCLIENT.DLL: $mpClientPath"
                        $AMSIDll.Add($mpClientPath)
                    } else {
                        Write-Verbose "MPCLIENT.DLL not found at: $mpClientPath"
                    }
                }
            }
        } else {
            Write-Host 'No AMSI configuration was found, possible AMSI misconfiguration"' -ForegroundColor Red
        }
    }
} else {
    Write-Host '"No AMSI Providers was found"'
}

                }
            }
        } else {
            Write-Host 'No AMSI configuration was found, possible AMSI misconfiguration"' -ForegroundColor Red
        }
    }
} else {
    Write-Host '"No AMSI Providers was found"'
}

Write-Host "Analyzing Exchange Processes"
while ($currentDiff -gt 0) {
    if ($firstExecution) {
        # Test Exchange Processes for unexpected modules
        $ExchangeProcessList = Get-ExchAVExclusionsProcess -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)

        # Gather all processes on the computer and filter by the Exchange Process List
        $ServerProcess = Get-Process | Where-Object { $ExchangeProcessList -contains $_.path } | Sort-Object -Property ProcessName

        # Module allow list
        $ModuleAllowList = New-Object Collections.Generic.List[string]

        # cSpell:disable

        # No company name

        #Exchange 2013
        # Bin\Search\Ceres\HostController\Data\Repository\Journal\
        $ModuleAllowList.Add("Microsoft.Exchange.TransportFlow.50.dll")
        $ModuleAllowList.Add("Microsoft.ClientResourceView.FlowService.dll")
        $ModuleAllowList.Add("Microsoft.Exchange.TransportFlowMdm.50.dll")
        $ModuleAllowList.Add("Microsoft.Exchange.Search.Writer.50.dll")

        $ModuleAllowList.Add("FUSE.Paxos.Network.dll")
        $ModuleAllowList.Add("FUSE.Weld.Base.Portable.dll")
        $ModuleAllowList.Add("ParallelExtensionsExtras.dll")
        $ModuleAllowList.Add("Google.ProtocolBuffers.dll")

        #Exchange 2016
        # Bin\Search\Ceres\HostController\Data\Repository\Journal\
        $ModuleAllowList.Add("Microsoft.Exchange.TransportFlowMdm.105.dll")
        $ModuleAllowList.Add("Microsoft.Exchange.TransportFlow.105.dll")
        $ModuleAllowList.Add("Microsoft.Exchange.Search.Writer.109.dll")
        $ModuleAllowList.Add("Microsoft.Exchange.WatermarkCtsFlow.100.dll")

        $ModuleAllowList.Add("Bond.Precompiler.dll")
        $ModuleAllowList.Add("Microsoft.Applications.Telemetry.dll")
        $ModuleAllowList.Add("Microsoft.Applications.Telemetry.Server.dll")
        $ModuleAllowList.Add("Microsoft.RightsManagementServices.Core.dll")
        $ModuleAllowList.Add("Microsoft.Search.ObjectStore.Client.dll")
        $ModuleAllowList.Add("ParallelExtensionsExtras.dll")
        $ModuleAllowList.Add("System.IdentityModel.Tokens.Jwt.dll")
        $ModuleAllowList.Add("Owin.dll")
        $ModuleAllowList.Add("Google.ProtocolBuffers.dll")

        $ModuleAllowList.Add("DiskLockerApi.dll")
        $ModuleAllowList.Add("ExDbFailureItemApi.dll")
        $ModuleAllowList.Add("ManagedBlingSigned.dll")
        $ModuleAllowList.Add("Microsoft.DSSMNativeSSELib.dll")

        #Exchange 2019
        $ModuleAllowList.Add("Microsoft.Exchange.BigFunnelFlow.28.dll")
        $ModuleAllowList.Add("BigFunnel.NeuralTree.dll")
        $ModuleAllowList.Add("DocParserWrapper.dll")

        #.NET Foundation
        $ModuleAllowList.Add("Microsoft.AspNet.SignalR.Core.dll")
        $ModuleAllowList.Add("Microsoft.AspNet.SignalR.SystemWeb.dll")

        #Microsoft Research Limited
        $ModuleAllowList.Add("Infer.Compiler.dll")
        $ModuleAllowList.Add("Infer.Runtime.dll")

        #The Legion of the Bouncy Castle
        $ModuleAllowList.Add("BouncyCastle.Crypto.dll")

        #Google Inc.
        $ModuleAllowList.Add("Google.Protobuf.dll")

        #Newtonsoft
        $ModuleAllowList.Add("Newtonsoft.Json.dll")
        $ModuleAllowList.Add("Newtonsoft.Json.Bson.dll")

        #Marc Gravell
        $ModuleAllowList.Add("protobuf-net.dll")
        $ModuleAllowList.Add("protobuf-net.Core.dll")

        #Matthew Manela
        $ModuleAllowList.Add("DiffPlex.dll")

        #The Apache Software Foundation
        $ModuleAllowList.Add("log4net.dll")

        #http://system.data.sqlite.org/
        $ModuleAllowList.Add("System.Data.SQLite.dll")

        #Robert Simpson, et al.
        $ModuleAllowList.Add("SQLite.Interop.dll")

        #Microsoft.Cloud.InstrumentationFramework.*
        $ModuleAllowList.Add("Microsoft.Cloud.InstrumentationFramework.Events.dll")
        $ModuleAllowList.Add("Microsoft.Cloud.InstrumentationFramework.Health.dll")
        $ModuleAllowList.Add("Microsoft.Cloud.InstrumentationFramework.Metrics.dll")

        #Windows
        $ModuleAllowList.Add("prxyqry.DLL")
        $ModuleAllowList.Add("icu.dll")
        $ModuleAllowList.Add("TextShaping.dll")

        #Windows Fraunhofer IIS MPEG Audio Layer-3 ACM codec - MPEG Audio Layer-3 Codec for MSACM
        $ModuleAllowList.Add("l3codecp.acm")

        # CompanyName allow list
        $CompanyNameAllowList = New-Object Collections.Generic.List[string]
        $CompanyNameAllowList.Add("Microsoft Corporation")
        $CompanyNameAllowList.Add("Microsoft Corporation.")
        $CompanyNameAllowList.Add("Microsoft")
        $CompanyNameAllowList.Add("Microsoft Corp.")
        $CompanyNameAllowList.Add("Microsoft CoreXT")
        #$CompanyNameAllowList.Add("Microsoft Research Limited") #Only 2 modules

        $CompanyNameAllowList.Add("Корпорация Майкрософт")
        $CompanyNameAllowList.Add("Корпорація Майкрософт")
        $CompanyNameAllowList.Add("Корпорація Майкрософт (Microsoft Corporation)")
        $CompanyNameAllowList.Add("Корпорація Майкрософт (Microsoft Corporation)")
        $CompanyNameAllowList.Add("Microsoft  корпорациясы")
        $CompanyNameAllowList.Add("Корпорация Майкрософт.")

        # CompanyName allow list
        $FIPCompanyNameAllowList = New-Object Collections.Generic.List[string]
        $FIPCompanyNameAllowList.Add("Oracle Corporation")
        $FIPCompanyNameAllowList.Add("Oracle Corp.")

        # cSpell:enable

        Write-Verbose "Allow List Module Count: $($ModuleAllowList.count)"

        # Gather each process and work thru their module list to remove any known modules.
        foreach ($process in $ServerProcess) {

            Write-Verbose "Checking $($process.path) - PID: $($process.Id)"
            Write-Progress -Activity "Checking Exchange Processes" -CurrentOperation "$currentDiff More Seconds" -PercentComplete ((($initialDiff - $currentDiff) / $initialDiff) * 100) -Status " "
            [int]$currentDiff = (New-TimeSpan -End $StartDate.AddMinutes($WaitingTimeForAVAnalysisInMinutes) -Start (Get-Date)).TotalSeconds

            # Gather all modules
            [array]$ProcessModules = $process.modules

            # Remove Microsoft modules
            Write-Verbose "Removing Microsoft Modules"
            $ProcessModules = $ProcessModules | Where-Object { ($_.FileVersionInfo.CompanyName -notin $CompanyNameAllowList) -or ($_.FileName -like "*Windows Defender*")  }

            # Remove Oracle modules on FIPS
            Write-Verbose "Removing Oracle Modules"
            $ProcessModules = $ProcessModules | Where-Object { (-not($_.FileName -like "*\FIP-FS\Bin\*" -and ($_.FileVersionInfo.CompanyName -in $FIPCompanyNameAllowList))) }

            # Clear out modules from the allow list
            Write-Verbose "Removing Allow Modules"
            foreach ($module in $ModuleAllowList) {
                $ProcessModules = $ProcessModules | Where-Object { $_.ModuleName -ne $module -and $_.ModuleName -ne $($module.Replace(".dll", ".ni.dll")) }
            }

            if ($ProcessModules.count -gt 0) {
                $hasAmsiDll = $process.modules | Where-Object { $_.ModuleName -like "amsi.dll" }
                foreach ($module in $ProcessModules) {
                    $OutString = ("PROCESS: $($process.ProcessName) PID($($process.Id)) UNEXPECTED MODULE: $($module.ModuleName) COMPANY: $($module.Company)`n`tPATH: $($module.FileName)`n`tFileVersion: $($module.FileVersion)")
                    # If there is amsi.dll in the process and the module is in the AMSIDll list, it is the AMSI provider
                    if ($hasAmsiDll -and ($AMSIDll -contains $module.FileName)) {
                        $OutString = ("PROCESS: $($process.ProcessName) PID($($process.Id)) MODULE: $($module.ModuleName) COMPANY: $($module.Company)`n`tPATH: $($module.FileName)`n`tFileVersion: $($module.FileVersion)")
                        Write-Host "[WARNING] - AMSI Provider Detected: $OutString" -ForegroundColor Yellow
                        $SuspiciousAMSIProcessList += $OutString
                    } else {
                        Write-Host "[FAIL] - $OutString" -ForegroundColor Red
                        $SuspiciousProcessList += $OutString
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
Write-Host "Analyzed Exchange Processes"

# Create a list of folders that are probably being scanned by AV
$BadFolderList = New-Object Collections.Generic.List[string]

Write-Host "Testing for EICAR files"

# Test each location for the EICAR file
foreach ($Folder in $FolderList) {

    $FilePath = (Join-Path $Folder $eicarFullFileName)

    # If the file exists delete it -- this means the folder is not being scanned
    if (Test-Path $FilePath ) {
        #Get content to confirm that the file is not blocked by AV
        $output = Get-Content $FilePath -ErrorAction SilentlyContinue
        if ($output -eq $eicar) {
            Write-Verbose "Removing $FilePath"
            Remove-Item $FilePath -Confirm:$false -Force
        } else {
            Write-Host "[FAIL] - Possible AV Scanning on Path: $Folder" -ForegroundColor Red
            $BadFolderList.Add($Folder)
        }
    }
    # If the file doesn't exist Add that to the bad folder list -- means the folder is being scanned
    else {
        Write-Host "[FAIL] - Possible AV Scanning on Path: $Folder" -ForegroundColor Red
        $BadFolderList.Add($Folder)
    }

    if ($nonExistentFolder -contains $Folder) {
        Remove-Item $Folder -Confirm:$false -Force -Recurse
        Write-Verbose "Removed folder: $Folder"
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
            Write-Verbose "Removing $FilePath"
            Remove-Item $FilePath -Confirm:$false -Force
        } else {
            Write-Host "[FAIL] - Possible AV Scanning on Extension: $extension" -ForegroundColor Red
            $BadExtensionList.Add($extension)
        }
    }
    # If the file doesn't exist Add that to the bad extension list -- means the extension is being scanned
    else {
        Write-Host "[FAIL] - Possible AV Scanning on Extension: $extension" -ForegroundColor Red
        $BadExtensionList.Add($extension)
    }
}

#Delete Random Folder
Remove-Item $randomFolder -Confirm:$false -Force -Recurse

$OutputPath = Join-Path $PSScriptRoot BadExclusions-$StartDateFormatted.txt
"###########################################################################################" | Out-File $OutputPath
"Exclusions analysis at $((Get-Date).ToString())" | Out-File $OutputPath -Append
"###########################################################################################" | Out-File $OutputPath -Append

# Report what we found
if ($BadFolderList.count -gt 0 -or $BadExtensionList.Count -gt 0 -or $SuspiciousProcessList.count -gt 0 -or $SuspiciousAMSIProcessList.count -gt 0) {

    Write-Host "Possible AV Scanning found" -ForegroundColor Red
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
    if ($SuspiciousAMSIProcessList.count -gt 0 ) {
        $SuspiciousAMSIProcessListString = "`nAMSI.dll detected in Exchange processes with AMSI providers loaded. This may indicate antivirus integration that could affect Exchange performance."
        $SuspiciousAMSIProcessListString | Out-File $OutputPath -Append
        Write-Warning $SuspiciousAMSIProcessListString
        "`n[AMSI Provider Modules Detected in Exchange Processes]" | Out-File $OutputPath -Append
        $SuspiciousAMSIProcessList | Out-File $OutputPath -Append
        Write-Warning ("Found $($SuspiciousAMSIProcessList.count) AMSI provider modules loaded into Exchange processes ")
    }
    Write-Warning ("Review " + $OutputPath + " For the full list.")
} else {
    $CorrectExclusionsString = "`nAll EICAR files found; File Exclusions, Extensions Exclusions and Processes Exclusions (Did not find Non-Default modules loaded) appear to be set properly"
    $CorrectExclusionsString | Out-File $OutputPath -Append
    Write-Host $CorrectExclusionsString
}
