# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Powershell script to enable and collect EAS mailbox logs.
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)] [string[]] $Mailbox = "",
    [ValidateScript({ Test-Path $_ })]
    [Parameter(Mandatory = $true)] [string] $OutputPath = (Get-Location).Path,
    [Parameter(Mandatory = $false)] [int] $Interval = 30,
    [Parameter(Mandatory = $false)] [Nullable[bool]] $EnableMailboxLoggingVerboseMode = $null
)

#parse $EnableMailboxLoggingVerboseMode and convert it boolean value(s)
switch ($EnableMailboxLoggingVerboseMode) {
    $true { $EnableVerboseLogging = "true" }
    $false { $EnableVerboseLogging = "false" }
    default { $EnableVerboseLogging = $null }
}

#Override EnableMailboxLoggingVerboseMode key's value with EnableVerboseLogging
if ($null -ne $EnableVerboseLogging) {
    if ($PSCmdlet.ShouldProcess("Set EnableMailboxLoggingVerboseMode attribute to $EnableVerboseLogging in $env:ExchangeInstallPath" + "ClientAccess\Sync\web.config", 'TARGET', 'OPERATION')) {
        $WebConfigPath=$env:ExchangeInstallPath+"ClientAccess\Sync\web.config"
        try {
            [xml]$web = Get-Content $WebConfigPath
        } catch {
            Write-Error ("Failed to read $WebConfigPath file. Exception $_")
            exit
        }
        try {
            Copy-Item $WebConfigPath -Destination $WebConfigPath".bak"
        } catch {
            Write-Error ("Failed to make $WebConfigPath.bak file with exception $_")
            exit
        }
        $web.SelectSingleNode('//add[@key="EnableMailboxLoggingVerboseMode"]').Value = $EnableVerboseLogging
        try {
            $web.Save($WebConfigPath)
        } catch {
            Write-Error ("Failed to update $WebConfigPath file. Exception $_")
            exit
        }
    } else {
        exit
    }
}

# Convert the interval into seconds
$Interval = $Interval * 60

# SMTP address of mailbox(es) to retrieve logs from
$targetMailboxes = @()
try {
    $targetMailboxes = $Mailbox.Split(",")
} catch {
    "Failed to split" | Out-Null
}

# Looping indefinitely...
while ($true) {
    # Ensure that mailbox logging is not disabled after 72 hours
    # For each mailbox...
    foreach ($targetMailbox in $targetMailboxes) {
        #...attempt to enable mailbox logging for the mailbox
        Write-Host "Enabling mailbox log for $targetMailbox." -ForegroundColor DarkGray
        try {
            Set-CasMailbox $targetMailbox -ActiveSyncDebugLogging:$true -ErrorAction Stop -WarningAction SilentlyContinue
        } catch {
            # Should only error when mailbox is on a different version of Exchange than server where command executed
            Write-Host "Error enabling the ActiveSync mailbox log for $targetMailbox. This script must run on the version of Exchange where the mailbox is located." -ForegroundColor White -BackgroundColor Red
            exit
        }
    }
    # For each target mailbox...
    foreach ($targetMailbox in $targetMailboxes) {
        Write-Host "Getting all devices for mailbox:" $targetMailbox
        # ...get all devices syncing with mailbox...
        try {
            $devices = Get-MobileDeviceStatistics -Mailbox $targetMailbox
        } catch {
            Write-Host "Error locating devices for $targetMailbox." -ForegroundColor White -BackgroundColor Red
        }

        #...and for each device...
        if ($null -ne $devices) {
            foreach ($device in $devices) {
                Write-Host "Downloading logs for device: $($device.DeviceFriendlyName) $($device.DeviceID)" -ForegroundColor Cyan
                # ...create an output file...
                $fileName = [System.IO.Path]::Combine($OutputPath, "$targetMailbox`_MailboxLog_$($device.DeviceFriendlyName)_$($device.DeviceID)_$((Get-Date).Ticks).txt")

                # ...and write the mailbox log to the output file...
                try {
                    Get-MobileDeviceStatistics $device.Identity -GetMailboxLog -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty MailboxLogReport |
                        Out-File -FilePath $fileName
                } catch {
                    Write-Host "Unable to retrieve mailbox log for $device.Identity" -ForegroundColor White -BackgroundColor Red
                }
            }
        }
        # Escape the infinite loop if there are no devices
        else { Write-Host "No devices found for $targetMailbox." -ForegroundColor Yellow; exit }
    }

    #...and then wait x number of seconds before retrieving the logs again
    Write-Host "Reminder: Do no close this window until you are ready to collect the logs." -ForegroundColor White -BackgroundColor Red
    Write-Host "Next set of logs will be retrieved at" (Get-Date).AddSeconds($Interval) -ForegroundColor Green
    Start-Sleep $Interval
}
