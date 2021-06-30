# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Save-WindowsEventLogs {

    Write-ScriptDebug("Function Enter: Save-WindowsEventLogs")
    $baseSaveLocation = $Script:RootCopyToDirectory + "\Windows_Event_Logs"
    $SaveLogs = @{}
    $rootLogPath = "$env:SystemRoot\System32\Winevt\Logs"
    $allLogPaths = Get-ChildItem $rootLogPath |
        ForEach-Object {
            $_.VersionInfo.FileName
        }

    if ($PassedInfo.AppSysLogs) {
        Write-ScriptDebug("Adding Application and System Logs")
        $logs = @()
        $logs += "$rootLogPath\Application.evtx"
        $logs += "$rootLogPath\System.evtx"
        $logs += "$rootLogPath\MSExchange Management.evtx"
    }

    if ($PassedInfo.WindowsSecurityLogs) { $logs += "$rootLogPath\Security.evtx" }

    if ($PassedInfo.AppSysLogs -or
        $PassedInfo.WindowsSecurityLogs) {
        $SaveLogs.Add("Windows-Logs", $logs)
    }

    if ($PassedInfo.ManagedAvailabilityLogs) {
        Write-ScriptDebug("Adding Managed Availability Logs")

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-ActiveMonitoring") }
        $SaveLogs.Add("Microsoft-Exchange-ActiveMonitoring", $Logs)

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-ManagedAvailability") }
        $SaveLogs.Add("Microsoft-Exchange-ManagedAvailability", $Logs)
    }

    if ($PassedInfo.HighAvailabilityLogs) {
        Write-ScriptDebug("Adding High Availability Logs")

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-HighAvailability") }
        $SaveLogs.Add("Microsoft-Exchange-HighAvailability", $Logs)

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-MailboxDatabaseFailureItems") }
        $SaveLogs.Add("Microsoft-Exchange-MailboxDatabaseFailureItems", $Logs)

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Windows-FailoverClustering") }
        $SaveLogs.Add("Microsoft-Windows-FailoverClustering", $Logs)
    }

    foreach ($directory in $SaveLogs.Keys) {
        Write-ScriptDebug("Working on directory: {0}" -f $directory)

        $logs = $SaveLogs[$directory]
        $saveLocation = "$baseSaveLocation\$directory"

        Copy-BulkItems -CopyToLocation $saveLocation -ItemsToCopyLocation $logs
        Get-ChildItem $saveLocation | Rename-Item -NewName { $_.Name -replace "%4", "-" }

        if ($directory -eq "Windows-Logs" -and
            $PassedInfo.AppSysLogsToXml) {
            try {
                Write-ScriptDebug("starting to collect event logs and saving out to xml files.")
                Save-DataInfoToFile -DataIn (Get-EventLog Application -After ([DateTime]::Now.AddDays(-$PassedInfo.DaysWorth))) -SaveToLocation ("{0}\Application" -f $saveLocation) -SaveTextFile $false
                Save-DataInfoToFile -DataIn (Get-EventLog System -After ([DateTime]::Now.AddDays(-$PassedInfo.DaysWorth))) -SaveToLocation ("{0}\System" -f $saveLocation) -SaveTextFile $false
                Write-ScriptDebug("end of collecting event logs and saving out to xml files.")
            } catch {
                Write-ScriptDebug("Error occurred while trying to export out the Application and System logs to xml")
                Invoke-CatchBlockActions
            }
        }

        Invoke-ZipFolder -Folder $saveLocation
    }
}
