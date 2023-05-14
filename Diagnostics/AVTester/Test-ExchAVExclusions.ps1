# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: Test-ExchAVExclusions.ps1
	Requires: Administrator rights
    Major Release History:
        06/16/2021 - Initial Release

.SYNOPSIS
Uses EICAR files to verify that all Exchange paths that should be excluded from AV scanning are excluded.

.DESCRIPTION
Writes an EICAR test file https://en.wikipedia.org/wiki/EICAR_test_file to all paths specified by
https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019 and
https://docs.microsoft.com/en-us/exchange/anti-virus-software-in-the-operating-system-on-exchange-servers-exchange-2013-help


If the file is removed then the path is not properly excluded from AV Scanning.
IF the file is not removed then it should be properly excluded.

Once the files are created it will wait 60 seconds for AV to "see" and remove the file.

.PARAMETER DisableDirectoriesAnalysis
Disable the Directories Analysis exclusions

.PARAMETER Recurse
Places an EICAR file in all SubFolders in the Exclusions list as well as the root.
Generally should not be needed unless all folders pass without -Recuse but AV is still suspected.
It does not apply if you use DisableDirectoriesAnalysis parameter.

.PARAMETER DisableProcessesAnalysis
Disable the Processes Analysis exclusions.

.PARAMETER IncludeW3wpProcesses
Includes w3wp processes in the analysis.
It does not apply if you use DisableProcessesAnalysis parameter.

.PARAMETER DisableExtensionsAnalysis
Disable the Extension Analysis exclusions.

.PARAMETER OpenLog
Opens the script log file.

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

Puts and Remove an EICAR file in all test paths + all SubFolders.

#>
[CmdletBinding()]
param (

    [Parameter()]
    [switch]
    $DisableDirectoriesAnalysis,

    [Parameter()]
    [switch]
    $Recurse,

    [Parameter()]
    [switch]
    $DisableProcessesAnalysis,

    [Parameter()]
    [switch]
    $IncludeW3wpProcesses,

    [Parameter()]
    [switch]
    $DisableExtensionsAnalysis,

    [Parameter()]
    [switch]
    $OpenLog
)

. $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
. $PSScriptRoot\..\..\Shared\Get-ExchAVExclusions.ps1
. $PSScriptRoot\Write-SimpleLogFile.ps1
. $PSScriptRoot\Start-SleepWithProgress.ps1

function CheckIfISAcceptedRootCA {
    [CmdletBinding()]
    param(
        [string]$CAString,
        [switch]$isFIPFS,
        [switch]$Offline
    )

    switch ($CAString) {
        'CN=Microsoft Corporate Root CA, O=Microsoft Corporation' { return $true }
        'CN=Microsoft Root Authority, OU=Microsoft Corporation, OU=Copyright (c) 1997 Microsoft Corp.' { return $true }
        'CN=Microsoft Root Certificate Authority, DC=microsoft, DC=com' { return $true }
        'CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' { return $true }
        'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' { return $true }
        default {
            if ($Offline -and $CAString -eq 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' )
            { return $true }
            if ($isFIPFS) {
                if ( $CAString -eq 'CN=VeriSign Class 3 Public Primary Certification Authority - G5, OU="(c) 2006 VeriSign, Inc. - For authorized use only", OU=VeriSign Trust Network, O="VeriSign, Inc.", C=US' )
                { return $true }
                if ( $Offline -and $CAString -eq 'CN="Oracle America, Inc.", OU=Code Signing Bureau, O="Oracle America, Inc.", L=Redwood Shores, S=California, C=US' )
                { return $true }
            }
            return $false
        }
    }
}

function Test-UnknownCompany {
    param (
        [Parameter()]
        [string]
        $CompanyName
    )

    switch ($CompanyName) {
        'Microsoft Corporation' { return $false }
        'Microsoft Corporation.' { return $false }
        'Microsoft' { return $false }
        'Microsoft Corp.' { return $false }
        'Microsoft CoreXT' { return $false }
        'Корпорация Майкрософт' { return $false }
        default { return $true }
    }
}

function Test-UnknownModule {
    param (
        [Parameter()]
        [string]
        $ModuleName
    )

    switch ($ModuleName) {
        'Microsoft.RightsManagementServices.Core.ni.dll' { return $false }
        'Google.Protobuf.ni.dll' { return $false }
        'Newtonsoft.Json.ni.dll' { return $false }
        'l3codecp.acm' { return $false }
        'ManagedBlingSigned.ni.dll' { return $false }
        'System.IdentityModel.Tokens.jwt.ni.dll' { return $false }
        default { return $true }
    }
}

if ( $DisableDirectoriesAnalysis -and $DisableProcessesAnalysis -and $DisableExtensionsAnalysis ) {
    Write-Host "All Analysis are disabled" -ForegroundColor Red -BackgroundColor Black
    exit
}

# Log file name
$LogFile = "ExchAvExclusions.log"

# Open log file if switched
if ($OpenLog) { Write-SimpleLogFile -OpenLog -String " " -Name $LogFile }

# Confirm that we are an administrator
if (-not (Confirm-Administrator)) {
    Write-Host "Please run as Administrator"  -ForegroundColor Red -BackgroundColor Black
    exit
}

$serverExchangeInstallDirectory = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue

# Check Exchange registry key
if (-not  $serverExchangeInstallDirectory ) {
    Write-Warning "Failed to find the Exchange installation Path registry key"
    exit
}

# Check the installation path
if (-not ( Test-Path $($serverExchangeInstallDirectory.MsiInstallPath) -PathType Container -ErrorAction SilentlyContinue) ) {
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

Write-SimpleLogFile -String ("###########################################################################################") -name $LogFile
Write-SimpleLogFile -String ("Starting AV Exclusions analysis at $((Get-Date).ToString())") -name $LogFile
Write-SimpleLogFile -String ("###########################################################################################") -name $LogFile

if ( -not $DisableProcessesAnalysis) {
    try {
        $response = $null
        $response = Invoke-WebRequest http://crl.microsoft.com/pki/crl/products/CodeSigPCA.crl
        if ($null -ne $response) {
            if ( $response.StatusCode -eq 200 ) {
                $Offline = $false
            } else {
                $Offline = $true
            }
        } else {
            $Offline = $true
        }
    } catch {
        $Offline = $true
    }

    if ( $Offline ) {
        Write-Warning ""
        Write-Warning "External CRL Not reachable: http://crl.microsoft.com/pki/crl/products/CodeSigPCA.crl"
        Write-Warning "It is not possible to check the full certificate chain correctly"
        Write-Warning ""
    }
}

if ( -not $DisableDirectoriesAnalysis) {
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

                # Get the Folder and all SubFolders and just return the FullName value as a string
                Get-ChildItem $path -Recurse -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName | ForEach-Object { $FolderList.Add($_.ToLower()) }
            }
            # Just Add the root folder
            else { $FolderList.Add($path.ToLower()) }
        } catch { Write-SimpleLogFile -string ("[ERROR] - Failed to resolve folder " + $path) -Name $LogFile }
    }

    # Remove any Duplicates
    $FolderList = $FolderList | Select-Object -Unique
}

if ( -not ( ($DisableDirectoriesAnalysis ) -and ( $DisableExtensionsAnalysis ) ) ) {
    Write-SimpleLogFile -String "Creating EICAR Files" -name $LogFile -OutHost

    # Create the EICAR file in each path
    $EicarFileName = "eicar"
    $EicarFileExt = "com"
    $EicarFullFileName = "$EicarFileName.$EicarFileExt"

    #Base64 of Eicar string
    [string] $EncodedEicar = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='
}

if ( -not $DisableDirectoriesAnalysis ) {
    foreach ($Folder in $FolderList) {

        [string] $FilePath = (Join-Path $Folder $EicarFullFileName)
        Write-SimpleLogFile -String ("Creating $EicarFullFileName file " + $FilePath) -name $LogFile

        if (!(Test-Path -Path $FilePath -ErrorAction SilentlyContinue)) {

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
            Write-SimpleLogFile -string ("[WARNING] - $EicarFullFileName already exists!: " + $FilePath) -name $LogFile -OutHost
        }
    }
}

if ( -not $DisableExtensionsAnalysis ) {
    # Create a random folder in root path
    $randomString = -join ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object { [char]$_ })
    $randomFolder = New-Item -Path (Join-Path (Join-Path $env:SystemDrive '\') "TestExchAVExclusions-$randomString") -ItemType Directory
    $extensionsList = New-Object Collections.Generic.List[string]
    $extensionsList = Get-ExchAVExclusionsExtensions -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)

    if ($randomFolder) {
        foreach ($extension in $extensionsList) {
            $filepath = Join-Path $randomFolder "$EicarFileName.$extension"
            Write-SimpleLogFile -String ("Creating $EicarFileName.$extension file " + $FilePath) -name $LogFile

            if (!(Test-Path -Path $FilePath -ErrorAction SilentlyContinue)) {

                # Try writing the encoded string to a the file
                try {
                    [byte[]] $EicarBytes = [System.Convert]::FromBase64String($EncodedEicar)
                    [string] $Eicar = [System.Text.Encoding]::UTF8.GetString($EicarBytes)
                    [IO.File]::WriteAllText($FilePath, $Eicar)
                } catch {
                    Write-Warning "$randomFolder $EicarFileName.$extension file couldn't be created. Either permissions or AV prevented file creation."
                }
            } else {
                Write-SimpleLogFile -string ("[WARNING] - $randomFolder $EicarFileName.$extension  already exists!: ") -name $LogFile -OutHost
            }
        }
    } else {
        Write-Warning "We cannot create a folder in root path to test extension exclusions."
    }
}

if ( -not ( ( $DisableDirectoriesAnalysis ) -and ( $DisableExtensionsAnalysis ) ) ) {
    Write-SimpleLogFile -String "EICAR Files Created" -name $LogFile -OutHost
    Write-SimpleLogFile -String "Accessing EICAR Files" -name $LogFile -OutHost
    # Try to open each EICAR file to force detection in paths
}

if ( -not $DisableDirectoriesAnalysis ) {
    $foldersCounter = 0
    foreach ($Folder in $FolderList) {
        $FilePath = (Join-Path $Folder $EicarFullFileName)
        if (Test-Path $FilePath -PathType Leaf -ErrorAction SilentlyContinue) {
            Write-SimpleLogFile -String ("Opening $EicarFullFileName file " + $FilePath) -name $LogFile
            Start-Process -FilePath more -ArgumentList """$FilePath""" -ErrorAction SilentlyContinue -WindowStyle Hidden | Out-Null
        }
        $foldersCounter++
    }
}

if ( -not $DisableExtensionsAnalysis ) {
    # Try to open extensions:
    $extensionsCounter = 0
    foreach ($extension in $extensionsList) {
        $FilePath = Join-Path $randomFolder "$EicarFileName.$extension"
        if (Test-Path $FilePath -PathType Leaf -ErrorAction SilentlyContinue) {
            Write-SimpleLogFile -String ("Opening $EicarFileName.$extension file " + $FilePath) -name $LogFile
            Start-Process -FilePath more -ArgumentList """$FilePath""" -ErrorAction SilentlyContinue -WindowStyle Hidden | Out-Null
        }
        $extensionsCounter++
    }
}

if ( -not ( ( $DisableDirectoriesAnalysis ) -and ( $DisableExtensionsAnalysis ) ) ) {
    Write-SimpleLogFile -String "Access EICAR Files Finished" -name $LogFile -OutHost
}

if ( -not $DisableProcessesAnalysis ) {
    # Check thru all of the Processes that are supposed to be excluded and verify if there are non Microsoft modules loaded
    Write-SimpleLogFile -string "Checking Processes for 3rd party Modules" -name $LogFile -OutHost
    if ( $IncludeW3wpProcesses ) {
        Write-Warning "W3wp.exe is not present in the recommended Exclusion list but we will check if it includes 3rd Party modules"
        Write-SimpleLogFile -string "W3wp.exe is not present in the recommended Exclusion list but we will check if it includes 3rd Party modules" -name $LogFile
    }

    # Create the Array List
    $ExchProcessList = Get-ExchAVExclusionsProcess -ExchangePath $ExchangePath -MsiProductMinor ([byte]$serverExchangeInstallDirectory.MsiProductMinor)
    if ( $IncludeW3wpProcesses ) {
        $ExchProcessList += (Join-Path $env:SystemRoot '\System32\inetSrv\W3wp.exe')
    }

    $processListCounter = 0

    $BadProcessList = [ordered]@{}

    # Determine if the process contains 3rd party DLLs
    foreach ($Process in $ExchProcessList) {
        [array]$RunningProcess = $null

        Write-Progress -Id 0 -Activity "Examining Exchange processes." -PercentComplete (($processListCounter / $ExchProcessList.Count) * 100) -Status " "

        # First see if the process is running
        $ProcessName = (($Process.Split('\')[-1])).Substring(0, ($Process.Split('\')[-1]).lastIndexOf('.'))
        [array]$RunningProcess = Get-Process $ProcessName -ErrorAction SilentlyContinue

        # Look at if we have found it
        if ($null -eq $RunningProcess) {
            Write-SimpleLogFile -string "Process $Process not found" -name $LogFile
        } else {
            Write-SimpleLogFile -string "Found $Process" -name $LogFile

            $runningProcessesCounter = 0
            # Pull each instance of the process
            foreach ($Instance in $RunningProcess) {
                Write-Progress -Id 1 -ParentId 0 -Activity "Examining $Process $($runningProcessesCounter+1) of $($RunningProcess.Count)" -Status " "

                if ( $Process -eq $Instance.Path) {
                    Write-SimpleLogFile -String ("############################################################") -name $LogFile
                    Write-SimpleLogFile -String ("Working on Process $($Instance.Path)") -name $LogFile
                    Write-SimpleLogFile -String ("Working on PID $($Instance.Id)") -name $LogFile
                    $CommandLine = (Get-CimInstance  -Query "Select * from Win32_Process where ProcessId = '$($Instance.Id)'" | Select-Object CommandLine).CommandLine

                    Write-SimpleLogFile -String ("CommandLine: $CommandLine") -name $LogFile

                    $instancesCounter = 0
                    foreach ($module in $Instance.Modules ) {
                        Write-Progress -Id 2 -ParentId 1 -Activity "Examining loaded modules in $($Instance.Id) process." -PercentComplete (($instancesCounter / $Instance.Modules.Count) * 100) -Status " "
                        Write-SimpleLogFile -String ("Working on Module $($module.FileName)") -name $LogFile
                        $signature = $module.FileName | Get-AuthenticodeSignature
                        if ( $signature.Status -eq 'NotSigned') {
                            if ( ($module.FileName.ToLower().StartsWith(('c:\windows\assembly\NativeImages_').ToLower()) -and (
                                        $module.FileName.ToLower().EndsWith('.ni.dll') -or $module.FileName.ToLower().EndsWith('.ni.exe') -or
                                        $module.FileName.ToLower().EndsWith('.wrapper.dll') ) ) -or
                            ($module.FileName.ToLower().StartsWith('c:\windows\system32\') -and [environment]::OSVersion.Version.Major -le 6 ) -or
                            ($module.FileName.ToLower().StartsWith(('c:\windows\WinSxS\').ToLower()) -and [environment]::OSVersion.Version.Major -le 6 ) -or
                            ($module.FileName.ToLower().StartsWith('c:\windows\assembly\') -and [environment]::OSVersion.Version.Major -le 6 ) -or
                            ($module.FileName.ToLower().StartsWith('c:\windows\microsoft.net\assembly\gac_64\') -and [environment]::OSVersion.Version.Major -le 6 ) -or
                            ($module.FileName.ToLower() -eq (Join-Path ($env:ExchangeInstallPath).ToLower() 'bin\osafehtm.dll') -and ([byte]$serverExchangeInstallDirectory.MsiProductMinor) -gt 0 ) ) {
                                if ( Test-UnknownCompany $module.Company) {
                                    if ( Test-UnknownModule $module.ModuleName) {
                                        $BadProcessList["$($Instance.Id) - $($module.FileName)"] = "$($Instance.Id), $($module.FileName), $($module.Company), $($module.Description), $($module.Product),  $($Instance.Path), $CommandLine"
                                        Write-SimpleLogFile -String ("[FAIL] - Unknown Module $($module.FileName) `n`tCompany: $($module.Company) `n`tDescription: $($module.Description) `n`tProduct: $($module.Product) `n`tProcess Id: $($Instance.Id) `n`tCommandLine: $CommandLine") -name $LogFile -OutHost
                                    }
                                }
                            } else {
                                $BadProcessList["$($Instance.Id) - $($module.FileName)"] = "$($Instance.Id), $($module.FileName), $($module.Company), $($module.Description), $($module.Product),  $($Instance.Path), $CommandLine"
                                Write-SimpleLogFile -String ("[FAIL] - Unsigned Module File $($module.FileName) `n`tCompany: $($module.Company) `n`tDescription: $($module.Description) `n`tProduct: $($module.Product) `n`tProcess ID: $($Instance.Id) `n`tCommand Line: $CommandLine") -name $LogFile -OutHost
                            }
                        } else {
                            if ( $signature.Status -eq 'Valid' -and $signature.StatusMessage -eq 'Signature verified.') {
                                $cert = $null
                                $cert = $signature.SignerCertificate
                                if ( $null -eq $cert) {
                                    $BadProcessList["$($Instance.Id) - $($module.FileName)"] = "$($Instance.Id), $($module.FileName), $($module.Company), $($module.Description), $($module.Product),  $($Instance.Path), $CommandLine"
                                    Write-SimpleLogFile -String ("[FAIL] - We could not get signer certificate on Module: $($module.FileName) `n`tCompany: $($module.Company) `n`tDescription: $($module.Description) `n`tProduct: $($module.Product) `n`tProcess ID: $($Instance.Id) `n`tCommand Line: $CommandLine") -name $LogFile -OutHost
                                } else {
                                    $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
                                    $chain.Build($cert) | Out-Null
                                    $rootCertificate = $null
                                    $rootCertificate = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Subject
                                    if ( $null -eq $rootCertificate) {
                                        $BadProcessList["$($Instance.Id) - $($module.FileName)"] = "$($Instance.Id), $($module.FileName), $($module.Company), $($module.Description), $($module.Product),  $($Instance.Path), $CommandLine"
                                        Write-SimpleLogFile -String ("[FAIL] - We could not get root certificate on Module: $($module.FileName) `n`tCompany: $($module.Company) `n`tDescription: $($module.Description) `n`tProduct: $($module.Product) `n`tProcess ID: $($Instance.Id) `n`tCommand Line: $CommandLine") -name $LogFile -OutHost
                                    } else {
                                        $FIPSPath = Join-Path $env:ExchangeInstallPath 'FIP-FS\Bin\TE'
                                        if ($module.FileName.ToLower().StartsWith($FIPSPath.ToLower()) ) {
                                            if ($Offline) {
                                                if ( -not (CheckIfISAcceptedRootCA -CAString $rootCertificate -isFIPFS -Offline) ) {
                                                    $BadProcessList["$($Instance.Id) - $($module.FileName)"] = "$($Instance.Id), $($module.FileName), $($module.Company), $($module.Description), $($module.Product),  $($Instance.Path), $CommandLine"
                                                    Write-SimpleLogFile -String ("[FAIL] - root do not expected (FIP-FS) on Module: $($module.FileName) `n`tCompany: $($module.Company) `n`tDescription: $($module.Description) `n`tProduct: $($module.Product) `n`tRoot CA $rootCertificate `n`tProcess ID: $($Instance.Id) `n`tCommand Line: $CommandLine") -name $LogFile -OutHost
                                                }
                                            } else {
                                                if ( -not (CheckIfISAcceptedRootCA -CAString $rootCertificate -isFIPFS) ) {
                                                    $BadProcessList["$($Instance.Id) - $($module.FileName)"] = "$($Instance.Id), $($module.FileName), $($module.Company), $($module.Description), $($module.Product),  $($Instance.Path), $CommandLine"
                                                    Write-SimpleLogFile -String ("[FAIL] - root do not expected (FIP-FS) on Module: $($module.FileName) `n`tCompany: $($module.Company) `n`tDescription: $($module.Description) `n`tProduct: $($module.Product) `n`tRoot CA: $rootCertificate `n`tProcess ID: $($Instance.Id) `n`tCommand Line: $CommandLine") -name $LogFile -OutHost
                                                }
                                            }
                                        } else {
                                            if ($Offline) {
                                                if ( -not (CheckIfISAcceptedRootCA($rootCertificate) -Offline) ) {
                                                    $BadProcessList["$($Instance.Id) - $($module.FileName)"] = "$($Instance.Id), $($module.FileName), $($module.Company), $($module.Description), $($module.Product),  $($Instance.Path), $CommandLine"
                                                    Write-SimpleLogFile -String ("[FAIL] - root do not expected on Module: $($module.FileName) `n`tCompany: $($module.Company) `n`tDescription: $($module.Description) `n`tProduct: $($module.Product) `n`tRoot CA: $rootCertificate `n`tProcess ID: $($Instance.Id) `n`tCommand Line: $CommandLine" ) -name $LogFile -OutHost
                                                }
                                            } else {
                                                if ( -not (CheckIfISAcceptedRootCA($rootCertificate)) ) {
                                                    $BadProcessList["$($Instance.Id) - $($module.FileName)"] = "$($Instance.Id), $($module.FileName), $($module.Company), $($module.Description), $($module.Product),  $($Instance.Path), $CommandLine"
                                                    Write-SimpleLogFile -String ("[FAIL] - root do not expected on Module: $($module.FileName) `n`tCompany: $($module.Company) `n`tDescription: $($module.Description) `n`tProduct: $($module.Product) `n`tRoot CA: $rootCertificate `n`tProcess ID: $($Instance.Id) `n`tCommand Line: $CommandLine" ) -name $LogFile -OutHost
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                $BadProcessList["$($Instance.Id) - $($module.FileName)"] = "$($Instance.Id), $($module.FileName), $($module.Company), $($module.Description), $($module.Product),  $($Instance.Path), $CommandLine"
                                Write-SimpleLogFile -String ("[FAIL] - We could not verify the signature of $($module.FileName) `n`tCompany: $($module.Company) `n`tDescription: $($module.Description) `n`tProduct: $($module.Product) `n`tProcess ID: $($Instance.Id) `n`tCommand Line: $CommandLine") -name $LogFile -OutHost
                            }
                        }
                        $instancesCounter++
                    }
                }
                $runningProcessesCounter++
            }
        }
        $processListCounter++
    }
    Write-Progress -Completed -Activity "Examining loaded modules in Exchange processes." -Status " "
    Write-SimpleLogFile -string "Finished  Processes for 3rd party Modules" -name $LogFile -OutHost
}

if ( $DisableProcessesAnalysis ) {
    # Sleeping 5 minutes for AV to "find" the files
    Start-SleepWithProgress -SleepTime 300 -message "Allowing time for AV to Scan"
}

if ( -not ( ( $DisableDirectoriesAnalysis ) -and ( $DisableExtensionsAnalysis ) ) ) {
    Write-SimpleLogFile -string "Testing for EICAR files" -name $LogFile -OutHost
}

if ( -not $DisableDirectoriesAnalysis ) {
    # Create a list of folders that are probably being scanned by AV
    $BadFolderList = New-Object Collections.Generic.List[string]

    # Test each location for the EICAR file
    foreach ($Folder in $FolderList) {

        $FilePath = (Join-Path $Folder $EicarFullFileName)

        # If the file exists delete it -- this means the folder is not being scanned
        if (Test-Path $FilePath -ErrorAction SilentlyContinue) {
            #Get content to confirm that the file is not blocked by AV
            $output = $null
            $output = Get-Content $FilePath -ErrorAction SilentlyContinue
            if ($output -eq $Eicar) {
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
}

if ( -not $DisableExtensionsAnalysis ) {
    $BadExtensionList = New-Object Collections.Generic.List[string]
    # Test each extension for the EICAR file
    foreach ($extension in $extensionsList) {

        $filepath = Join-Path $randomFolder "$EicarFileName.$extension"

        # If the file exists delete it -- this means the extension is not being scanned
        if (Test-Path $filepath -ErrorAction SilentlyContinue) {
            #Get content to confirm that the file is not blocked by AV
            $output = $null
            $output = Get-Content $FilePath -ErrorAction SilentlyContinue
            if ($output -eq $Eicar) {
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
    Remove-Item $randomFolder -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5

    if ( Test-Path $randomFolder -PathType Container -ErrorAction SilentlyContinue) {
        Write-Warning ("We could not remove the temp folder $randomFolder used for extension test.")
        Write-Warning ("Could be blocked by Antivirus.")
    }
}

$OutputPath = Join-Path $env:LOCALAPPDATA BadExclusions.txt

#Report what we found
if ($BadFolderList.count -gt 0 -or $BadExtensionList.Count -gt 0 -or $BadProcessList.count -gt 0) {
    Write-SimpleLogFile -String "Possible AV Scanning found" -name $LogFile
    "Non-Expected Exclusions Detected - ($((Get-Date).ToString())):" | Out-File $OutputPath
}
if ($BadFolderList.count -eq 0 -and $BadExtensionList.Count -eq 0 -and $BadProcessList.count -eq 0) {
    Write-SimpleLogFile -String "Exclusions appear to be set properly" -name $LogFile
    "Exclusions appear to be set properly - ($((Get-Date).ToString())):" | Out-File $OutputPath
}

if ( -not $DisableDirectoriesAnalysis ) {
    " " | Out-File $OutputPath -Append
    if ( $BadFolderList.count -gt 0 ) {
        Write-Warning ("Found $($BadFolderList.count) of $($FolderList.Count) folders that are possibly being scanned! ")
        "Folders not Excluded:" | Out-File $OutputPath -Append
        $BadFolderList | Out-File $OutputPath -Append
    } else {
        Write-SimpleLogFile -String "Directory Exclusions appear to be set properly" -Name $LogFile -OutHost
        "All EICAR files found in the directories" | Out-File $OutputPath -Append
    }
}

if ( -not $DisableExtensionsAnalysis ) {
    " " | Out-File $OutputPath -Append
    if ( $BadExtensionList.count -gt 0 ) {
        Write-Warning ("Found $($BadExtensionList.count) of $($extensionsList.Count) extensions that are possibly being scanned! ")
        "Extensions not Excluded:" | Out-File $OutputPath -Append
        $BadExtensionList | Out-File $OutputPath -Append
    } else {
        Write-SimpleLogFile -String "Extension Exclusions appear to be set properly" -Name $LogFile -OutHost
        "All EICAR files found in the extension test" | Out-File $OutputPath -Append
    }
}

if ( -not $DisableProcessesAnalysis ) {
    " " | Out-File $OutputPath -Append
    if ($BadProcessList.count -gt 0) {
        Write-Warning ("Found $($BadProcessList.count) processes that are possibly being scanned! ")
        "Processes not Excluded (PID, Module, Company, Description, Product, Path, CommandLine):" | Out-File $OutputPath -Append
        $BadProcessList.Keys | ForEach-Object { $BadProcessList[$_] } | Out-File $OutputPath -Append
    } else {
        Write-SimpleLogFile -String "Exchange Processes appear clean" -Name $LogFile -OutHost
        "Exchange Processes appear clean" | Out-File $OutputPath -Append
    }
}

if ($BadFolderList.count -gt 0 -or $BadExtensionList.Count -gt 0 -or $BadProcessList.count -gt 0) {
    Write-Warning ("Review " + $OutputPath + " For the full list.")
}
