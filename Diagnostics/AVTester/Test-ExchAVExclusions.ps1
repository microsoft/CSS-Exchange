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
https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019

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
$env:LOCALAPPDATA\BadFolders.txt

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
. $PSScriptRoot\Write-SimpleLogFile.ps1
. $PSScriptRoot\Start-SleepWithProgress.ps1

# Log file name
$LogFile = "ExchAvExclusions.log"

# Open log file if switched
if ($OpenLog) { Write-SimpleLogFile -OpenLog -String " " -Name $LogFile }

# Create the Array List
$BaseFolders = New-Object Collections.Generic.List[string]

# List of base Folders
$BaseFolders.Add((Join-Path $env:SystemRoot '\Cluster').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\ClientAccess\OAB').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\FIP-FS').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\GroupMetrics').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\Logging').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\Mailbox').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\TransportRoles\Data\Adam').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\TransportRoles\Data\IpFilter').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\TransportRoles\Data\Queue').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\TransportRoles\Data\SenderReputation').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\TransportRoles\Data\Temp').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\TransportRoles\Logs').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\TransportRoles\Pickup').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\TransportRoles\Replay').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\UnifiedMessaging\Grammars').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\UnifiedMessaging\Prompts').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\UnifiedMessaging\Temp').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\UnifiedMessaging\Voicemail').tolower())
$BaseFolders.Add((Join-Path $env:ExchangeInstallPath '\Working\OleConverter').tolower())
$BaseFolders.Add((Join-Path $env:SystemDrive '\inetpub\temp\IIS Temporary Compressed Files').tolower())
$BaseFolders.Add((Join-Path $env:SystemRoot '\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files').tolower())
$BaseFolders.Add((Join-Path $env:SystemRoot '\System32\Inetsrv').tolower())

# Add all database folder paths
Foreach ($Entry in (Get-MailboxDatabase -Server $Env:COMPUTERNAME)) {
    $BaseFolders.Add((Split-Path $Entry.EdbFilePath -Parent).tolower())
    $BaseFolders.Add(($Entry.LogFolderPath.pathname.tolower()))
}

# Get transport database path
[xml]$TransportConfig = Get-Content (Join-Path $env:ExchangeInstallPath "Bin\EdgeTransport.exe.config")
$BaseFolders.Add(($TransportConfig.configuration.appsettings.Add | Where-Object { $_.key -eq "QueueDatabasePath" }).value.tolower())
$BaseFolders.Add(($TransportConfig.configuration.appsettings.Add | Where-Object { $_.key -eq "QueueDatabaseLoggingPath" }).value.tolower())

# Remove any Duplicates
$BaseFolders = $BaseFolders | Select-Object -Unique

#'$env:SystemRoot\Temp\OICE_<GUID>'
#'$env:SystemDrive\DAGFileShareWitnesses\<DAGFQDN>'

Write-SimpleLogfile -String "Starting Test" -Name $LogFile

# Create list object to hold all Folders we are going to test
$FolderList = New-Object Collections.Generic.List[string]


# Confirm that we are an administrator
if (Confirm-Administrator) {}
else { Write-Error "Please run as Administrator" }

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
            $FolderList.Add($path)

            # Get the Folder and all subFolders and just return the fullname value as a string
            Get-ChildItem $path -Recurse -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName | ForEach-Object { $FolderList.Add($_) }
        }
        # Just Add the root folder
        else { $FolderList.Add($path) }
    } catch { Write-SimpleLogfile -string ("[ERROR] - Failed to resolve folder " + $path) -Name $LogFile }
}

Write-SimpleLogfile -String "Creating EICAR Files" -name $LogFile -OutHost

# Create the EICAR file in each path
foreach ($Folder in $FolderList) {

    [string] $FilePath = (Join-Path $Folder eicar.com)
    Write-SimpleLogfile -String ("Creating EICAR file " + $FilePath) -name $LogFile

    #Base64 of Eicar string
    [string] $EncodedEicar = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='

    If (!(Test-Path -Path $FilePath)) {

        # Try writing the encoded string to a the file
        Try {
            [byte[]] $EicarBytes = [System.Convert]::FromBase64String($EncodedEicar)
            [string] $Eicar = [System.Text.Encoding]::UTF8.GetString($EicarBytes)
            Set-Content -Value $Eicar -Encoding ascii -Path $FilePath -Force
        }

        Catch {
            Write-Warning "$Folder Eicar.com file couldn't be created. Either permissions or AV prevented file creation."
        }
    }

    Else {
        Write-SimpleLogfile -string ("[WARNING] - Eicar.com already exists!: " + $FilePath) -name $LogFile -OutHost
    }
}

# Sleeping 5 minutes for AV to "find" the files
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
    Write-SimpleLogfile -String "All EICAR files found; Exclusions appear to be set properly" -Name $LogFile -OutHost
}
