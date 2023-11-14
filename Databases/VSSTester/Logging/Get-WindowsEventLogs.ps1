# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-WindowsEventLogs {
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]
        $StartTime,

        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName,

        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath
    )

    Write-Host "$(Get-Date) Getting events from the application and system logs since the script's start time of ($StartTime)"

    $timeString = $StartTime.ToUniversalTime().ToString("O")
    Write-Host "  Getting application log events..."
    if (Test-Path $OutputPath\events-Application.evtx) {
        Remove-Item $OutputPath\events-Application.evtx
    }
    wevtutil epl Application $OutputPath\events-Application.evtx /q:"Event/System/TimeCreated[@SystemTime > '$timeString']"
    Write-Host "  Getting system log events..."
    if (Test-Path $OutputPath\events-System.evtx) {
        Remove-Item $OutputPath\events-System.evtx
    }
    wevtutil epl System $OutputPath\events-System.evtx /q:"Event/System/TimeCreated[@SystemTime > '$timeString']"
    Write-Host "  Getting events complete!"
}
