# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Test and/or trace VSS functionality on Exchange Server.
.DESCRIPTION
    Test and/or trace VSS functionality on Exchange Server.
.LINK
    https://microsoft.github.io/CSS-Exchange/Databases/VSSTester/
.EXAMPLE
    .\VSSTester -TraceOnly -DatabaseName "Mailbox Database 1637196748"
    Enables tracing of the specified database. The user may then attempt a backup of that database
    and use Ctrl-C to stop data collection after the backup attempt completes.
.EXAMPLE
    .\VSSTester -DiskShadow -DatabaseName "Mailbox Database 1637196748" -ExposeSnapshotsOnDriveLetters M, N
    Enables tracing and then uses DiskShadow to snapshot the specified database. If the database and logs
    are on the same drive, the snapshot is exposed as M: drive. If they are on separate drives, the snapshots are
    exposed as M: and N:. The user is prompted to stop data collection and should typically wait until
    log truncation has occurred before doing so, so that the truncation is traced.
.EXAMPLE
    .\VSSTester -WaitForWriterFailure -DatabaseName "Mailbox Database 1637196748"
    Enables circular tracing of the specified database, and then polls "vssadmin list writers" once
    per minute. When the writer is no longer present, indicating a failure, tracing is stopped
    automatically.
#>
[CmdletBinding()]
param(
    # Enable tracing and wait for the user to run a third-party backup solution.
    [Parameter(Mandatory = $true, ParameterSetName = "TraceOnly")]
    [switch]
    $TraceOnly,

    # Enable tracing and perform a database snapshot with DiskShadow.
    [Parameter(Mandatory = $true, ParameterSetName = "DiskShadowByDatabase")]
    [Parameter(Mandatory = $true, ParameterSetName = "DiskShadowByVolume")]
    [switch]
    $DiskShadow,

    # Enable tracing and automatically stop when the Microsoft Exchange Writer fails.
    [Parameter(Mandatory = $true, ParameterSetName = "WaitForWriterFailure")]
    [switch]
    $WaitForWriterFailure,

    # Name of the database to focus tracing on and/or snapshot.
    [Parameter(Mandatory = $true, ParameterSetName = "TraceOnly")]
    [Parameter(Mandatory = $true, ParameterSetName = "DiskShadowByDatabase")]
    [Parameter(Mandatory = $true, ParameterSetName = "WaitForWriterFailure")]
    [string]
    $DatabaseName,

    # Names of the volumes to snapshot.
    [Parameter(Mandatory = $true, ParameterSetName = "DiskShadowByVolume")]
    [ValidateCount(1, 2)]
    [ValidateScript({
            $validVolumeNames = @((Get-CimInstance -Query "select name, DeviceId from win32_volume where DriveType=3" |
                        Where-Object { $_.Name -match "^\w:" }).Name)
            if ($validVolumeNames -contains $_) {
                $true
            } else {
                throw "Invalid volume specified. Please specify one of the following values:`n$([string]::Join("`n", $validVolumeNames))"
            }
        })]
    [string[]]
    $VolumesToBackup,

    # Drive letters on which to expose the snapshots.
    [Parameter(Mandatory = $true, ParameterSetName = "DiskShadowByDatabase")]
    [Parameter(Mandatory = $true, ParameterSetName = "DiskShadowByVolume")]
    [ValidateLength(1, 1)]
    [ValidateCount(1, 2)]
    [string[]]
    $ExposeSnapshotsOnDriveLetters,

    # Path in which to put the collected traces. A subfolder named with the time of
    # the data collection is created in this path, and all files are put in that subfolder.
    # Defaults to the folder the script is in.
    [Parameter(Mandatory = $false, ParameterSetName = "TraceOnly")]
    [Parameter(Mandatory = $false, ParameterSetName = "DiskShadowByDatabase")]
    [Parameter(Mandatory = $false, ParameterSetName = "DiskShadowByVolume")]
    [Parameter(Mandatory = $false, ParameterSetName = "WaitForWriterFailure")]
    [string]
    $LoggingPath = $PSScriptRoot
)

if ($VolumesToBackup -and ($VolumesToBackup.Count -ne $ExposeSnapshotsOnDriveLetters.Count)) {
    Write-Host "The count of VolumesToBackup must match the count of ExposeSnapshotsOnDriveLetters."
    exit
}

. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Get-ScriptUpdateAvailable.ps1
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
. .\DiskShadow\Invoke-CreateDiskShadowFile.ps1
. .\DiskShadow\Invoke-DiskShadow.ps1
. .\DiskShadow\Invoke-RemoveExposedDrives.ps1
. .\ExchangeInformation\Get-CopyStatus.ps1
. .\ExchangeInformation\Get-Databases.ps1
. .\ExchangeInformation\Get-ExchangeVersion.ps1
. .\Logging\Get-WindowsEventLogs.ps1
. .\Logging\Get-VSSWritersAfter.ps1
. .\Logging\Get-VSSWritersBefore.ps1
. .\Logging\Invoke-CreateExtraTracingConfig.ps1
. .\Logging\Invoke-DisableDiagnosticsLogging.ps1
. .\Logging\Invoke-DisableExtraTracing.ps1
. .\Logging\Invoke-DisableVSSTracing.ps1
. .\Logging\Invoke-EnableDiagnosticsLogging.ps1
. .\Logging\Invoke-EnableExtraTracing.ps1
. .\Logging\Invoke-EnableVSSTracing.ps1

$updateInfo = Get-ScriptUpdateAvailable
if ($updateInfo.UpdateFound) {
    Write-Warning "An update is available for this script. Current: $($updateInfo.CurrentVersion) Latest: $($updateInfo.LatestVersion)"
    Write-Warning "Please download the latest: https://microsoft.github.io/CSS-Exchange/Databases/VSSTester/"
}

$Script:LocalExchangeShell = Confirm-ExchangeShell

if (!$Script:LocalExchangeShell.ShellLoaded) {
    Write-Host "Failed to load Exchange Shell. Stopping the script."
    exit
}

if ($Script:LocalExchangeShell.RemoteShell -or
    $Script:LocalExchangeShell.ToolsOnly) {
    Write-Host "Can't run this script from a non Exchange Server."
    exit
}

$startTime = Get-Date
$startTimeFolderName = $startTime.ToString("yyMMdd-HHmmss")
$LoggingPath = Join-Path $LoggingPath $startTimeFolderName
$serverName = $env:COMPUTERNAME

try {
    New-Item -ItemType Directory -Force -Path $LoggingPath | Out-Null
    if (-not (Test-Path $LoggingPath)) {
        Write-Host "The specified LoggingPath path does not exist. Please enter a valid path."
        exit
    }

    try {
        Start-Transcript -Path "$LoggingPath\vssTranscript.log"
    } catch {
        Write-Warning "Failed to start transcript. Stopping the script."
        exit
    }

    Get-ExchangeVersion -ServerName $serverName
    Get-VSSWritersBefore -OutputPath $LoggingPath

    if ($DatabaseName) {
        $databases = Get-Databases -ServerName $serverName
        $dbForBackup = $databases | Where-Object { $_.Name -eq $DatabaseName }
        if ($null -eq $dbForBackup) {
            Write-Warning "The specified database $DatabaseName does not exist on this server. Please enter a valid database name."
            exit
        }

        Get-CopyStatus -ServerName $serverName -Database $dbForBackup -OutputPath $LoggingPath
    }

    if ($DiskShadow) {
        if ($DatabaseName) {
            $p = @{
                OutputPath       = $LoggingPath
                ServerName       = $serverName
                Databases        = $databases
                DatabaseToBackup = $dbForBackup
                DriveLetters     = $ExposeSnapshotsOnDriveLetters
            }
        } else {
            $p = @{
                OutputPath      = $LoggingPath
                ServerName      = $serverName
                VolumesToBackup = $VolumesToBackup
                DriveLetters    = $ExposeSnapshotsOnDriveLetters
            }
        }
        $p | Out-Host
        $exposedDrives = Invoke-CreateDiskShadowFile @p
    }

    Invoke-EnableDiagnosticsLogging
    Invoke-EnableVSSTracing -OutputPath $LoggingPath -Circular $WaitForWriterFailure
    Invoke-CreateExTRATracingConfig
    Invoke-EnableExTRATracing -ServerName $serverName -DatabaseToBackup $dbForBackup -OutputPath $LoggingPath -Circular $WaitForWriterFailure

    $collectEventLogs = $false

    try {
        if ($DiskShadow) {
            # Always collect event logs for this scenario
            $collectEventLogs = $true

            Invoke-DiskShadow -OutputPath $LoggingPath
            Invoke-RemoveExposedDrives -OutputPath $LoggingPath -ExposedDrives $exposedDrives
        } elseif ($TraceOnly) {
            # Always collect event logs for this scenario
            $collectEventLogs = $true

            Write-Host "$(Get-Date) Data Collection"
            Write-Host
            Write-Host "Data collection is now enabled."
            Write-Host "Please start your backup using the third party software so the script can record the diagnostic data."
            Write-Host "When the backup is COMPLETE, use Ctrl-C to terminate data collection."
            while ($true) {
                Start-Sleep 1
            }
        } elseif ($WaitForWriterFailure) {
            Write-Host "Waiting for Microsoft Exchange Writer failure. Use Ctrl-C to abort."
            while ($true) {
                if (vssadmin list writers | Select-String "Microsoft Exchange Writer") {
                    Write-Host "$(Get-Date) Microsoft Exchange Writer is present."
                } else {
                    Write-Host "$(Get-Date) Microsoft Exchange Writer is missing. Stopping data collection."
                    break
                }

                Start-Sleep 60
            }

            # Only collect event logs if we exited the loop gracefully
            $collectEventLogs = $true
        }
    } finally {
        Write-Host "$(Get-Date) Stopping traces..."
        Invoke-DisableExTRATracing -ServerName $serverName -Database $dbForBackup -OutputPath $LoggingPath
        Invoke-DisableDiagnosticsLogging
        Invoke-DisableVSSTracing
        Write-Host "$(Get-Date) Tracing stopped."

        if ($collectEventLogs) {
            Get-VSSWritersAfter -OutputPath $LoggingPath
            Get-WindowsEventLogs -StartTime $startTime -ComputerName $ServerName -OutputPath $LoggingPath
        } else {
            Write-Host "Skipping event log collection, because WaitForWriterFailure was stopped before a writer failure was detected."
        }
    }
} finally {
    # always stop our transcript at end of script's execution
    Write-Host "$(Get-Date) Stopping transcript log..."
    Stop-Transcript -ErrorAction SilentlyContinue
    Write-Host "Script completed."
}
