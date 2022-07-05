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
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
. $PSScriptRoot\Write-SimpleLogFile.ps1
. $PSScriptRoot\Start-SleepWithProgress.ps1

# Log file name
$LogFile = "ExchAvExclusions.log"

# Open log file if switched
if ($OpenLog) { Write-SimpleLogFile -OpenLog -String " " -Name $LogFile }

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
$BaseFolders = New-Object Collections.Generic.List[string]

# List of base Folders
if ((Get-ExchangeServer $env:COMPUTERNAME).IsMailboxServer) {
    if (Get-DatabaseAvailabilityGroup ) {
        if ((Get-DatabaseAvailabilityGroup).Servers.name.Contains($env:COMPUTERNAME) ) {
            $BaseFolders.Add((Join-Path $($env:SystemRoot) '\Cluster').tolower())
            $dag = $null
            $dag = Get-DatabaseAvailabilityGroup | Where-Object { $_.Servers.Name.Contains($env:COMPUTERNAME) }
            #needs local system rigths
            if ( $null -ne $dag ) {
                $BaseFolders.Add($("\\" + $($dag.WitnessServer.Fqdn) + "\" + $($dag.WitnessDirectory.PathName.Split("\")[-1])).ToLower())
            }
        }
    }
    $BaseFolders.Add((Join-Path $ExchangePath '\ClientAccess\OAB').tolower())
    $BaseFolders.Add((Join-Path $ExchangePath '\FIP-FS').tolower())
    $BaseFolders.Add((Join-Path $ExchangePath '\GroupMetrics').tolower())
    $BaseFolders.Add((Join-Path $ExchangePath '\Logging').tolower())
    $BaseFolders.Add((Join-Path $ExchangePath '\Mailbox\MDBTEMP').tolower())

    $mbxS = Get-MailboxServer -Identity $($env:COMPUTERNAME) | Select-Object CalendarRepairLogPath, LogPathForManagedFolders, `
        DataPath, MigrationLogFilePath, TransportSyncLogFilePath, TransportSyncMailboxHealthLogFilePath
    $mbxS.psobject.Properties.Value.PathName | ForEach-Object {
        if ( $_ ) {
            if ( Test-Path $_ -PathType Container ) {
                $BaseFolders.Add($_.tolower())
            }
        }
    }

    # Add all database folder paths
    foreach ($Entry in (Get-MailboxDatabase -Server $Env:COMPUTERNAME)) {
        $BaseFolders.Add((Split-Path $Entry.EdbFilePath -Parent).tolower())
        $mbdblogs = $Entry | Select-Object TemporaryDataFolderPath, LogFolderPath

        $mbdblogs.psobject.Properties.Value.PathName | ForEach-Object {
            if ( $_ ) {
                if ( Test-Path $_ -PathType Container ) {
                    $BaseFolders.Add($_.tolower())
                }
            }
        }
    }

    $mtsLogs = Get-MailboxTransportService $($env:COMPUTERNAME) | Select-Object ConnectivityLogPath, `
        ReceiveProtocolLogPath, SendProtocolLogPath, MailboxSubmissionAgentLogPath, MailboxDeliveryAgentLogPath, `
        DnsLogPath, RoutingTableLogPath, SyncDeliveryLogPath, MailboxDeliveryHttpDeliveryLogPath, `
        MailboxDeliveryThrottlingLogPath, AgentGrayExceptionLogPath, PipelineTracingPath
    $mtsLogs.psobject.Properties.Value.PathName | ForEach-Object {
        if ( $_ ) {
            if ( Test-Path $_ -PathType Container ) {
                $BaseFolders.Add($_.tolower())
            }
        }
    }

    #'$env:SystemRoot\Temp\OICE_<GUID>'
    $possibleOICEFolders = Get-ChildItem $env:SystemRoot\temp -Directory -Filter OICE_*.0
    $possibleOICEFolders | ForEach-Object {
        if ( $_.Name.Length -gt 41) {
            $possibleGUID = $_.Name.Substring(5, 36)
            $result = [System.Guid]::Empty
            if ( [System.Guid]::TryParse($possibleGUID, [System.Management.Automation.PSReference]$result) ) {
                $BaseFolders.Add($_.FullName.tolower())
            }
        }
    }
}

if ((Get-ExchangeServer $env:COMPUTERNAME).IsUnifiedMessagingServer) {
    $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Grammars'))
    $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Prompts'))
    $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Temp'))
    $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Voicemail'))
}

if ((Get-ExchangeServer $env:COMPUTERNAME).IsClientAccessServer) {

    $fetsLogs = Get-FrontEndTransportService $($env:COMPUTERNAME) | Select-Object ConnectivityLogPath, `
        ReceiveProtocolLogPath, SendProtocolLogPath, AgentLogPath, DnsLogPath, ResourceLogPath, `
        AttributionLogPath, `
        RoutingTableLogPath, ProxyDestinationsLogPath, TopInboundIpSourcesLogPath
    $fetsLogs.psobject.Properties.Value.PathName | ForEach-Object {
        if ( $_) {
            if ( Test-Path $_ -PathType Container ) {
                $BaseFolders.Add($_.tolower())
            }
        }
    }

    $BaseFolders.Add((Join-Path $env:SystemDrive '\inetpub\temp\IIS Temporary Compressed Files').tolower())
    $BaseFolders.Add((Join-Path $env:SystemRoot '\System32\Inetsrv').tolower())
    $BaseFolders.Add((Join-Path $env:SystemRoot '\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files').tolower())
    $BaseFolders.Add(($((Get-PopSettings).LogFileLocation)).tolower())
    $BaseFolders.Add(($((Get-ImapSettings).LogFileLocation)).tolower())
}

if ((Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer) {
    $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\Adam').tolower())
    $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\IpFilter').tolower())
}

if ((Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer -or (Get-ExchangeServer $env:COMPUTERNAME).IsHubTransportServer) {
    $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\Queue').tolower())
    $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\SenderReputation').tolower())
    $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\Temp').tolower())
    $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Logs').tolower())

    $tsLogs = Get-TransportService $($env:COMPUTERNAME) | Select-Object ConnectivityLogPath, MessageTrackingLogPath, `
        IrmLogPath, ActiveUserStatisticsLogPath, ServerStatisticsLogPath, ReceiveProtocolLogPath, RoutingTableLogPath, `
        SendProtocolLogPath, QueueLogPath, LatencyLogPath, GeneralLogPath, WlmLogPath, AgentLogPath, FlowControlLogPath, `
        ProcessingSchedulerLogPath, ResourceLogPath, DnsLogPath, JournalLogPath, TransportMaintenanceLogPath, `
        RequestBrokerLogPath, StorageRESTLogPath, AgentGrayExceptionLogPath, TransportHttpLogPath, PipelineTracingPath, `
        PickupDirectoryPath, ReplayDirectoryPath, `
        RootDropDirectoryPath
    $tsLogs.psobject.Properties.Value.PathName | ForEach-Object {
        if ( $_ ) {
            if ( Test-Path $_ -PathType Container ) {
                $BaseFolders.Add($_.tolower())
            }
        }
    }

    $BaseFolders.Add((Join-Path $ExchangePath '\Working\OleConverter').tolower())

    #E13MBX  By default, content conversions are performed in the Exchange server's %TMP% folder.
    $BaseFolders.Add((Join-Path $env:SystemRoot '\Temp').tolower())
}

#E13 Exchange Server setup temporary files.
$BaseFolders.Add((Join-Path $env:SystemRoot '\Temp\ExchangeSetup').tolower())

# it is only in client Access E13 doc--- Inetpub\logs\logfiles\w3svc
Get-Website | Where-Object { $_.name -eq 'Default Web Site' -or $_.name -eq 'Exchange Back End' } | ForEach-Object {
    if ($_.logfile.directory.StartsWith('%')) {
        $BaseFolders.Add(("$(Get-Content -Path Env:"$($_.logFile.directory.Split('%')[1])")$($_.logFile.directory.Split('%')[2])\W3SVC$($_.id)").ToLower())
    } else {
        $BaseFolders.Add(("$($_.logfile.directory)\W3SVC$($_.id)").ToLower())
    }
}

# Get transport database path
[xml]$TransportConfig = Get-Content (Join-Path $ExchangePath "Bin\EdgeTransport.exe.config")
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
