
function Get-ApplicationAndSystemLogs {
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
