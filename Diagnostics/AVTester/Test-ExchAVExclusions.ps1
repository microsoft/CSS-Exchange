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
Examines Exchange processes to look for 3rd party modules loaded in the processes.

.DESCRIPTION
Writes an EICAR test file https://en.wikipedia.org/wiki/EICAR_test_file to all paths specified by
https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019 and
https://docs.microsoft.com/en-us/exchange/anti-virus-software-in-the-operating-system-on-exchange-servers-exchange-2013-help

If the file is removed then the path is not properly excluded from AV Scanning.
IF the file is not removed then it should be properly excluded.
Once the files are created it will wait 60 seconds for AV to "see" and remove the file.

Tries to pull the Exchange Processes that were published in the AV exclusion document.
If present will examine the loaded modules looking for one that are NOT well known.
Reports any modules that are not well known.


.PARAMETER Recurse
Will test not just the root folders but all subfolders.
Generally should not be needed unless all folders pass without -Recuse but AV is still suspected.

.OUTPUTS
Log file:
$env:LOCALAPPDATA\ExchAvExclusions.log

List of Scanned Folders:
$env:LOCALAPPDATA\BadFolders.txt

List of suspect Processes
$env:LOCALAPPDATA\SuspectProcesses.csv

.EXAMPLE
.\Test-ExchAVExclusions.ps1

Puts and removes an EICAR file in all test paths.
Examines all Exchange processes.

.EXAMPLE
.\Test-ExchAVExclusions.ps1 -Recurse

Puts and Remove an EICAR file in all test paths + all subfolders.
Examines all Exchange processes.

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
. $PSScriptRoot\Write-SimpleLogFile.ps1
. $PSScriptRoot\Start-SleepWithProgress.ps1
. $PSScriptRoot\Get-ExchAVExclusions.ps1

# Check the company name of the loaded module against a white list
function Test-UnknownCompany {
    param (
        [Parameter()]
        [string]
        $CompanyName
    )

    switch -Wildcard ($CompanyName) {
        'Microsoft*' { return $false }
        'Newtonsoft' { return $false }
        'Google Inc.' { return $false }
        'Oracle Corporation' { return $false }
        'Fraunhofer Institut Integrierte Schaltungen IIS' { return $false }
        default { return $true }
    }
}

# Check the module name against a white list
function Test-UnknownModule {
    param (
        [Parameter()]
        [string]
        $ModuleName
    )

    switch -Wildcard ($ModuleName) {
        'Microsoft.RightsManagementServices.Core.ni.dll' { return $false }
        'ExDBFailureItemAPI.dll' { return $false }
        'ManagedBlingSigned.dll' { return $false }
        'System.IdentityModel.Tokens.jwt.ni.dll' { return $false }
        default { return $true }
    }
}


# Log file name
$LogFile = "ExchAvExclusions.log"
$SuspectCSV = (Join-Path $env:LOCALAPPDATA SuspectProcesses.csv)

# Remove the suspectCSV if it is already there
if (Test-Path $SuspectCSV) { Remove-Item $SuspectCSV -Force -Confirm:$false }

# Open log file if switched
if ($OpenLog) { Write-SimpleLogFile -OpenLog -String " " -Name $LogFile }

# Confirm that we are an administrator
if (-not (Confirm-Administrator)) {
    Write-Error "Please run as Administrator"
    exit
}

# Determine the Exchange install directory from the registry
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
$exchangeShell = Confirm-ExchangeShell -Identity $env:computerName
if (-not($exchangeShell.ShellLoaded)) {
    Write-Warning "Failed to load Exchange Shell Module..."
    exit
}

# Create the Array List
$BaseFolders = Get-ExchAVExclusions -ExchangePath $ExchangePath

if ( $BaseFolders.count -eq 0 ) {
    Write-Warning "We do not detect folders to analyze"
    exit
}

# Create list object to hold all Folders we are going to test
$FolderList = New-Object Collections.Generic.List[string]

# Make sure each folders in our list resolve
foreach ($Path in $BaseFolders) {
    try {
        # Resolve path only returns a bool so we have to manually throw to catch
        if (!(Resolve-Path -Path $Path -ErrorAction SilentlyContinue)) {
            throw "Failed to resolve"
        }
        # If -recurse then we need to find all subfolders and Add them to the list to be tested
        if ($Recurse) {

            # Add the root folder
            $FolderList.Add($Path)

            # Get the Folder and all subFolders and just return the fullname value as a string
            Get-ChildItem $Path -Recurse -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName | ForEach-Object { $FolderList.Add($_) }
        }
        # Just Add the root folder
        else { $FolderList.Add($Path) }
    } catch { Write-SimpleLogfile -string ("[ERROR] - Failed to resolve folder " + $Path) -Name $LogFile }
}

Write-SimpleLogfile -String "Creating EICAR Files" -name $LogFile -OutHost

# Create the EICAR file in each path
foreach ($Folder in $FolderList) {

    [string] $FilePath = (Join-Path $Folder eicar.com)
    Write-SimpleLogfile -String ("Creating EICAR file " + $FilePath) -name $LogFile

    #Base64 of Eicar string
    [string] $EncodedEicar = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='

    if (!(Test-Path -Path $FilePath)) {

        # Try writing the encoded string to a the file
        try {
            [byte[]] $EicarBytes = [System.Convert]::FromBase64String($EncodedEicar)
            [string] $Eicar = [System.Text.Encoding]::UTF8.GetString($EicarBytes)
            Set-Content -Value $Eicar -Encoding ascii -Path $FilePath -Force
        }

        catch {
            Write-Warning "$Folder Eicar.com file couldn't be created. Either permissions or AV prevented file creation."
        }
    }

    else {
        Write-SimpleLogfile -string ("[WARNING] - Eicar.com already exists!: " + $FilePath) -name $LogFile -OutHost
    }
}

# Sleeping 1 minute for AV to "find" the files
Start-SleepWithProgress -sleeptime 60 -message "Allowing time for AV to Scan"

# Create a list of folders that are probably being scanned by AV
$BadFolderList = New-Object Collections.Generic.List[string]

Write-SimpleLogfile -string "Testing for EICAR files" -name $LogFile -OutHost

# Test each location for the EICAR file
foreach ($Folder in $FolderList) {

    $FilePath = (Join-Path $Folder eicar.com)

    # If the file exists delete it -- this means the folder is not being scanned
    if (Test-Path $FilePath ) {
        Write-SimpleLogfile -String ("Removing " + $FilePath) -name $LogFile
        Remove-Item $FilePath -Confirm:$false -Force
    }
    # If the file doesn't exist Add that to the bad folder list -- means the folder is being scanned
    else {
        Write-SimpleLogfile -String ("[FAIL] - Possible AV Scanning: " + $FilePath) -name $LogFile -OutHost
        $BadFolderList.Add($Folder)
    }
}

# Report what we found
if ($BadFolderList.count -gt 0) {
    $OutputPath = Join-Path $env:LOCALAPPDATA BadFolders.txt
    $BadFolderList | Out-File $OutputPath

    Write-SimpleLogfile -String "Possbile AV Scanning found" -name $LogFile
    Write-Warning ("Found " + $BadFolderList.count + " folders that are possibly being scanned!")
    Write-Warning ("Review " + $OutputPath + " For the full list.")
} else {
    Write-SimpleLogfile -String "All EICAR files found; File Exclusions appear to be set properly" -Name $LogFile -OutHost
}

# Check thru all of the Processes that are supposed to be excluded and verify if there are non-msft modules loaded
Write-SimpleLogFile -string "Checking Processes for 3rd party Modules" -name $LogFile -OutHost

# List of Exchange processes to check that we document
$ExchProcessList = ('ComplianceAuditService',
    'Dsamain',
    'EdgeTransport',
    'fms',
    'hostcontrollerservice',
    'inetinfo',
    'Microsoft.Exchange.AntispamUpdateSvc',
    'Microsoft.Exchange.ContentFilter.Wrapper',
    'Microsoft.Exchange.Diagnostics.Service',
    'Microsoft.Exchange.Directory.TopologyService',
    'Microsoft.Exchange.EdgeCredentialSvc',
    'Microsoft.Exchange.EdgeSyncSvc',
    'Microsoft.Exchange.Imap4',
    'Microsoft.Exchange.Imap4service',
    'Microsoft.Exchange.Notifications.Broker',
    'Microsoft.Exchange.Pop3',
    'Microsoft.Exchange.Pop3service',
    'Microsoft.Exchange.ProtectedServiceHost',
    'Microsoft.Exchange.RPCClientAccess.Service',
    'Microsoft.Exchange.Search.Service',
    'Microsoft.Exchange.Servicehost',
    'Microsoft.Exchange.Store.Service',
    'Microsoft.Exchange.Store.Worker',
    'Microsoft.Exchange.UM.CallRouter',
    'MSExchangeCompliance',
    'MSExchangeDagMgmt',
    'MSExchangeDelivery',
    'MSExchangeFrontendTransport',
    'MSExchangeHMHost',
    'MSExchangeHMWorker',
    'MSExchangeMailboxAssistants',
    'MSExchangeMailboxReplication',
    'MSExchangeRepl',
    'MSExchangeSubmission',
    'MSExchangeTransport',
    'MSExchangeTransportLogSearch',
    'MSExchangeThrottling',
    'Noderunner',
    'OleConverter',
    'ParserServer',
    'Powershell',
    'ScanEngineTest',
    'ScanningProcess',
    'UmService',
    'UmWorkerProcess',
    'UpdateService',
    'W3wp',
    'wsbexchange'
)

# Flag to see if we find an unknown module
$UnknownModule = $False
$i = 1

# Determine if the process contains 3rd party DLLs
foreach ($Process in $ExchProcessList) {
    [array]$RunningProcess = $null

    Write-Progress -Activity "Examining loaded modules in Exchange processes." -CurrentOperation "Examining process: $Process" -PercentComplete (($i / $ExchProcessList.Length) * 100) -Status " "

    # First see if the process is running
    [array]$RunningProcess = Get-Process $process -ErrorAction SilentlyContinue

    # Look at if we have found it
    if ($null -eq $RunningProcess) {
        Write-SimpleLogFile -string "Process $Process not found" -name $LogFile
    } else {
        Write-SimpleLogFile -string "Found $Process" -name $LogFile

        # Pull each instance of the process
        foreach ($Instance in $RunningProcess) {

            # Grab the modules in that instance
            foreach ($Module in $Instance.Modules) {
                # Test if they are known or unknown
                if (Test-UnknownCompany $Module.Company) {
                    if (Test-UnknownModule $Module.ModuleName) {
                        $UnknownModule = $true
                        # If unknown then we want to pull some data on them push to a CSV file
                        $Module | Select-Object -Property @{Name = "PID"; Expression = { $Instance.id } }, @{Name = "Name"; Expression = { $Instance.ProcessName } }, company, ModuleName | Export-Csv -Path $SuspectCSV -Append -NoTypeInformation
                    }
                }
            }
        }
    }

    $i++
}

Write-Progress -Completed -Activity "Examining loaded modules in Exchange processes." -Status " "

# Found an unknown module so open the csv file
if ($UnknownModule) {
    Write-SimpleLogFile -string "[WARNING] - Found unkown modules loaded in Exchange Processes." -name $LogFile -OutHost
    Write-SimpleLogFile -string "Please review the output CSV $SuspectCSV" -name $LogFile -OutHost
}
# Report clean run
else {
    Write-SimpleLogFile -string "Exchange Processes appear clean" -name $LogFile -OutHost
}
