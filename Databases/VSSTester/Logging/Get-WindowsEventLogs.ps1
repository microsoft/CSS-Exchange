# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-WindowsEventLogs {

    function Get-WindowEventsPerServer {
        param(
            [string]$ComputerName
        )
        "Getting application log events..."
        Get-WinEvent -FilterHashtable @{LogName = "Application"; StartTime = $startTime } -ComputerName $ComputerName | Export-Clixml $path\events-$ComputerName-App.xml
        "Getting system log events..."
        Get-WinEvent -FilterHashtable @{LogName = "System"; StartTime = $startTime } -ComputerName $ComputerName | Export-Clixml $path\events-$ComputerName-System.xml
        "Getting TruncationDebug log events..."
        Get-WinEvent -FilterHashtable @{LogName = "Microsoft-Exchange-HighAvailability/TruncationDebug"; StartTime = $startTime } -ComputerName $ComputerName -ErrorAction SilentlyContinue | Export-Clixml $path\events-$ComputerName-TruncationDebug.xml
    }
    " "
    Get-Date
    Write-Host "Getting events from the application and system logs since the script's start time of ($startInfo)" -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    "Getting application log events..."
    Get-EventLog -LogName Application -After $startInfo | Export-Clixml $path\events-App.xml
    "Getting system log events..."
    Get-EventLog -LogName System -After $startInfo | Export-Clixml $path\events-System.xml
    "Getting events complete!"
}
