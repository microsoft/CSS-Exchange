# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Replay queue databases from Messages.old-<date> folders.
.DESCRIPTION
    When Transport crashes, in some scenarios it will move the current queue
    database to Messaging.old-<date> and create a new empty database. The old
    database is usually not needed, unless shadow redundancy was failing. In
    that case, it can be useful to drain the old queue file to recover those
    messages.

    This script automates the process of replaying many old queue files created
    by a series of crashes.
.EXAMPLE
    PS> .\ReplayQueueDatabases
    Replays all queue databases newer than 7 days.
.EXAMPLE
    PS> .\ReplayQueueDatabases -RemoveDeliveryDelayedMessages
    Replays all queue databases newer than 7 days and removes delivery delay notifications.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param (
    # Only replay queue databases newer than this date
    [Parameter()]
    [int]
    $MaxAgeInDays = 7,

    # Attempt to remove delivery delay notifications so user mailboxes do not fill up with these while we replay old messages
    [Parameter()]
    [switch]
    $RemoveDeliveryDelayedMessages
)

begin {
    . $PSScriptRoot\..\Shared\Confirm-Administrator.ps1

    . $PSScriptRoot\..\Shared\Confirm-ExchangeManagementShell.ps1

    function Get-ExchangeInstallPath {
        return (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    }

    function Get-TransportConfigPath {
        $installPath = Get-ExchangeInstallPath
        return Join-Path $installPath "Bin\EdgeTransport.exe.config"
    }

    function Get-QueueDatabasePath {
        $transportConfigPath = Get-TransportConfigPath
        [xml]$TransportConfig = Get-Content $transportConfigPath
        $queueDatabasePath = ($TransportConfig.configuration.AppSettings.Add | Where-Object { $_.key -eq "QueueDatabasePath" }).value
        $queueDatabaseLoggingPath = ($TransportConfig.configuration.AppSettings.Add | Where-Object { $_.key -eq "QueueDatabaseLoggingPath" }).value
        if ($queueDatabasePath -ne $queueDatabaseLoggingPath) {
            Write-Warning "QueueDatabasePath and QueueDatabaseLoggingPath are not the same. This script does not yet support this scenario."
            exit
        }

        return $queueDatabasePath
    }

    function Get-BackupConfigPath {
        $installPath = Get-ExchangeInstallPath
        return Join-Path $installPath "bin\EdgeTransport.exe.config.before-replay"
    }

    function Backup-TransportConfig {
        $transportConfigPath = Get-TransportConfigPath
        $backupPath = Get-BackupConfigPath
        if (Test-Path $backupPath) {
            Remove-Item $backupPath
        }

        Copy-Item $transportConfigPath $backupPath
    }

    function Restore-TransportConfig {
        [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
        param()

        $transportConfigPath = Get-TransportConfigPath
        $backupPath = Get-BackupConfigPath
        if (Test-Path $backupPath) {
            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Copy-Item $backupPath $transportConfigPath -Force", $null)) {
                Copy-Item $backupPath $transportConfigPath -Force
            } else {
                exit
            }
        }
    }

    function Set-QueueDatabasePath {
        [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
        param(
            [Parameter(Mandatory = $true)]
            [string]
            $Path
        )

        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Point paths in EdgeTransport.exe.config to folder $Path", $null) -eq $false) {
            exit
        }

        $transportConfigPath = Get-TransportConfigPath
        [xml]$TransportConfig = Get-Content $transportConfigPath
        ($TransportConfig.configuration.appSettings.Add | Where-Object key -EQ "QueueDatabasePath").value = $Path
        ($TransportConfig.configuration.appSettings.Add | Where-Object key -EQ "QueueDatabaseLoggingPath").value = $Path
        $TransportConfig.Save($transportConfigPath)
    }

    function Stop-Transport {
        [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
        param()

        if ((Get-Service MSExchangeFrontEndTransport).Status -ne "Stopped") {
            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Stop-Service MSExchangeFrontEndTransport")) {
                Stop-Service MSExchangeFrontEndTransport -ErrorAction Stop
            } else {
                exit
            }
        }

        if ((Get-Service MSExchangeTransport).Status -ne "Stopped") {
            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Stop-Service MSExchangeTransport")) {
                Stop-Service MSExchangeTransport -ErrorAction Stop
            } else {
                exit
            }
        }
    }

    function Start-Transport {
        [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
        param()

        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Start-Service MSExchangeTransport")) {
            Start-Service MSExchangeTransport -ErrorAction Stop
        }

        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Start-Service MSExchangeFrontEndTransport")) {
            Start-Service MSExchangeFrontEndTransport -ErrorAction Stop
        }
    }

    $foldersToProcess = @()
    $foldersToSkip = @()
    $dateThreshold = (Get-Date).AddDays(-$MaxAgeInDays)
    $queueDatabasePath = Get-QueueDatabasePath
    $replayedFoldersPath = Join-Path $queueDatabasePath "QueuesReplayed"
    $skippedFoldersPath = Join-Path $queueDatabasePath "QueuesSkipped"
}

process {
    if (-not (Confirm-Administrator)) {
        Write-Host "This script must be run as an administrator."
        exit
    }

    if (-not (Confirm-ExchangeManagementShell)) {
        Write-Host "This script must be run from Exchange Management Shell."
        exit
    }

    $oldQueueDatabaseFolders = Get-ChildItem "\\?\$queueDatabasePath" -Directory -Recurse | Where-Object { $_.Name -like "Messaging.old*" }
    if ($oldQueueDatabaseFolders.Count -lt 1) {
        Write-Host "No old queue database folders found."
        exit
    }

    [Array]::Reverse($oldQueueDatabaseFolders)
    foreach ($folder in $oldQueueDatabaseFolders) {
        $folderName = $folder.Name
        $folderDate = [DateTime]::ParseExact($folderName.Substring(14), "yyyyMMddHHmmss", $null)
        if ($folderDate -lt $dateThreshold) {
            $foldersToSkip += $folder
            continue
        }

        $foldersToProcess += $folder
    }

    Write-Host "Found $($foldersToProcess.Count) folders to process."
    foreach ($folder in $foldersToProcess) {
        $folder.FullName
    }

    if ($foldersToProcess.Count -gt 0) {
        if (-not (Test-Path $replayedFoldersPath)) {
            New-Item $replayedFoldersPath -ItemType Directory | Out-Null
        }
    } else {
        exit
    }

    Write-Host

    if ($foldersToSkip.Count -gt 0) {
        if (-not (Test-Path $skippedFoldersPath)) {
            New-Item $skippedFoldersPath -ItemType Directory | Out-Null
        }

        Write-Host "Found $($foldersToSkip.Count) folders to skip due to age."
        foreach ($folder in $foldersToSkip) {
            $folder.FullName

            Move-Item $folder $skippedFoldersPath
        }

        Write-Host
    }

    $replayPath = Join-Path $queueDatabasePath "OldQueueReplay"
    if (Test-Path $replayPath) {
        Write-Warning "OldQueueReplay folder already exists. Manual cleanup required."
        exit
    }

    Backup-TransportConfig

    try {
        $componentState = Get-ServerComponentState -Identity $env:COMPUTERNAME -Component HubTransport
        if ($componentState.State -ne "Draining") {
            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Set-ServerComponentState -Identity $env:COMPUTERNAME -Component HubTransport -State Draining -Requester Maintenance")) {
                Set-ServerComponentState -Identity $env:COMPUTERNAME -Component HubTransport -State Draining -Requester Maintenance
            }
        }

        Stop-Transport

        Set-QueueDatabasePath -Path $replayPath

        for ($i = 0; $i -lt $foldersToProcess.Count; $i++) {
            $folder = $foldersToProcess[$i]

            Write-Host "Processing folder $($i + 1) of $($foldersToProcess.Count): $($folder.FullName)"

            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Move-Item $($folder.FullName) $replayPath", $null)) {
                Move-Item $folder.FullName $replayPath
            }

            Start-Transport

            $removeDelayedDeliveryInterval = [TimeSpan]::FromMinutes(1)
            $lastRemovedDelayedDelivery = [DateTime]::MinValue

            while ($true) {
                Start-Sleep -Seconds 5
                if ($RemoveDeliveryDelayedMessages -and (Get-Date) -gt $lastRemovedDelayedDelivery.Add($removeDelayedDeliveryInterval)) {
                    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Remove-Message -Filter 'Subject -like 'Delivery Delayed:*'' -Server $server -Confirm:`$false", $null)) {
                        Remove-Message -Filter "Subject -like 'Delivery Delayed:*'" -Server $server -Confirm:$false
                        $lastRemovedDelayedDelivery = Get-Date
                    }
                }

                $q = Get-Queue | Where-Object { $_.DeliveryType -ne "ShadowRedundancy" }
                Write-Host "$(Get-Date): Queue state:"
                $q | Out-Host
                $queuesWithMessages = $q | Where-Object { $_.MessageCount -gt 0 }
                if ($queuesWithMessages.Count -eq 0) {
                    Write-Host "Queues are cleared."
                    Write-Host
                    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Stop replaying this database", $null)) {
                        break
                    }
                }
            }

            Stop-Transport

            $replayedPath = Join-Path $replayedFoldersPath $folder.Name.Replace("Messaging.old", "Replayed")
            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Move-Item $replayPath $replayedPath", $null)) {
                Move-Item $replayPath $replayedPath
            }
        }
    } finally {
        Stop-Transport

        Restore-TransportConfig

        Start-Transport

        Write-Host "Replay complete."
        Write-Host "HubTransport was left in a Draining state. You should run the following command to return it to an Active state when ready:"
        Write-Host "Set-ServerComponentState -Identity $env:COMPUTERNAME -Component HubTransport -State Active -Requester Maintenance"
    }
}
