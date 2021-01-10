Function Save-WindowsEventLogs {

    Write-ScriptDebug("Function Enter: Save-WindowsEventLogs")
    $baseSaveLocation = $Script:RootCopyToDirectory + "\Windows_Event_Logs"
    $SaveLogs = @{}
    $Logs = @()
    if ($PassedInfo.AppSysLogs) {
        Write-ScriptDebug("Adding Application and System Logs")
        $Logs += "Application.evtx"
        $Logs += "System.evtx"
        $Logs += "MSExchange Management.evtx"
    }
    if ($PassedInfo.WindowsSecurityLogs) {
        $Logs += "Security.evtx"
    }
    if ($PassedInfo.AppSysLogs -or
        $PassedInfo.WindowsSecurityLogs) {
        $SaveLogs.Add("Windows-Logs", $Logs)
    }
    if ($PassedInfo.ManagedAvailability) {
        Write-ScriptDebug("Adding Managed Availability Logs")
        $Logs = @()
        $Logs += "Microsoft-Exchange-ActiveMonitoring%4MaintenanceDefinition.evtx"
        $Logs += "Microsoft-Exchange-ActiveMonitoring%4MaintenanceResult.evtx"
        $Logs += "Microsoft-Exchange-ActiveMonitoring%4MonitorDefinition.evtx"
        $Logs += "Microsoft-Exchange-ActiveMonitoring%4MonitorResult.evtx"
        $Logs += "Microsoft-Exchange-ActiveMonitoring%4ProbeDefinition.evtx"
        $Logs += "Microsoft-Exchange-ActiveMonitoring%4ProbeResult.evtx"
        $Logs += "Microsoft-Exchange-ActiveMonitoring%4ResponderDefinition.evtx"
        $Logs += "Microsoft-Exchange-ActiveMonitoring%4ResponderResult.evtx"
        $SaveLogs.Add("Microsoft-Exchange-ActiveMonitoring", $Logs)

        $Logs = @()
        $Logs += "Microsoft-Exchange-ManagedAvailability%4InvokeNowRequest.evtx"
        $Logs += "Microsoft-Exchange-ManagedAvailability%4InvokeNowResult.evtx"
        $Logs += "Microsoft-Exchange-ManagedAvailability%4Monitoring.evtx"
        $Logs += "Microsoft-Exchange-ManagedAvailability%4RecoveryActionLogs.evtx"
        $Logs += "Microsoft-Exchange-ManagedAvailability%4RecoveryActionResults.evtx"
        $Logs += "Microsoft-Exchange-ManagedAvailability%4RemoteActionLogs.evtx"
        $Logs += "Microsoft-Exchange-ManagedAvailability%4StartupNotification.evtx"
        $Logs += "Microsoft-Exchange-ManagedAvailability%4ThrottlingConfig.evtx"
        $SaveLogs.Add("Microsoft-Exchange-ManagedAvailability", $Logs)
    }
    if ($PassedInfo.HighAvailabilityLogs) {
        Write-ScriptDebug("Adding High Availability Logs")
        $Logs = @()
        $Logs += "Microsoft-Exchange-HighAvailability%4BlockReplication.evtx"
        $Logs += "Microsoft-Exchange-HighAvailability%4Debug.evtx"
        $Logs += "Microsoft-Exchange-HighAvailability%4Operational.evtx"
        $Logs += "Microsoft-Exchange-HighAvailability%4TruncationDebug.evtx"
        $Logs += "Microsoft-Exchange-HighAvailability%4SeedingDebug.evtx"
        $Logs += "Microsoft-Exchange-HighAvailability%4Network.evtx"
        $Logs += "Microsoft-Exchange-HighAvailability%4Seeding.evtx"
        $Logs += "Microsoft-Exchange-HighAvailability%4Monitoring.evtx"
        $Logs += "Microsoft-Exchange-HighAvailability%4AppLogMirror.evtx"
        $SaveLogs.Add("Microsoft-Exchange-HighAvailability", $Logs)

        $Logs = @()
        $Logs += "Microsoft-Exchange-MailboxDatabaseFailureItems%4Operational.evtx"
        $Logs += "Microsoft-Exchange-MailboxDatabaseFailureItems%4Debug.evtx"
        $SaveLogs.Add("Microsoft-Exchange-MailboxDatabaseFailureItems", $Logs)

        $Logs = @()
        $Logs += "Microsoft-Windows-FailoverClustering%4Operational.evtx"
        $Logs += "Microsoft-Windows-FailoverClustering%4Diagnostic.evtx"
        $Logs += $env:SystemRoot + "\Cluster\Reports\Cluster.log"
        $SaveLogs.Add("Microsoft-Windows-FailoverClustering", $Logs)
    }

    foreach ($directory in $SaveLogs.Keys) {
        $validLogs = @()
        Write-ScriptDebug("Working on directory: {0}" -f $directory)
        foreach ($log in $SaveLogs[$directory]) {
            $path = $log

            if (!($log.StartsWith("C:\"))) {
                $path = "{0}\System32\Winevt\Logs\{1}" -f $env:SystemRoot, $log
            }

            if (Test-Path $path) {
                $validLogs += $path
            } else {
                Write-ScriptDebug("Failed to find path: '{0}'" -f $path)
            }
        }
        $zipFolder = $true

        if ($directory -notlike "ROOT*") {
            $saveLocation = "{0}\{1}" -f $baseSaveLocation, $directory
        } else {
            $zipFolder = $false
            $saveLocation = $baseSaveLocation
        }

        if ($null -ne $validLogs) {
            Copy-BulkItems -CopyToLocation $saveLocation -ItemsToCopyLocation $validLogs
            Remove-EventLogChar -location $saveLocation

            if ($zipFolder) {
                Invoke-ZipFolder -Folder $saveLocation
            }
        }
    }
}