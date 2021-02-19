
function Get-WindowsEventLogs {

    Function Get-WindowEventsPerServer {
        param(
            [string]$CompunterName
        )
        "Getting application log events..."
        Get-WinEvent -FilterHashtable @{LogName = "Application"; StartTime = $startTime } -ComputerName $CompunterName | Export-Clixml $path\events-$CompunterName-App.xml
        "Getting system log events..."
        Get-WinEvent -FilterHashtable @{LogName = "System"; StartTime = $startTime } -ComputerName $CompunterName | Export-Clixml $path\events-$CompunterName-System.xml
        "Getting TruncationDebug log events..."
        Get-WinEvent -FilterHashtable @{LogName = "Microsoft-Exchange-HighAvailability/TruncationDebug"; StartTime = $startTime } -ComputerName $CompunterName -ErrorAction SilentlyContinue | Export-Clixml $path\events-$CompunterName-TruncationDebug.xml
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
