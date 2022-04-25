# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Copy-BulkItems.ps1
. $PSScriptRoot\Save-DataInfoToFile.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
Function Save-WindowsEventLogs {

    Write-Verbose("Function Enter: Save-WindowsEventLogs")
    $baseSaveLocation = $Script:RootCopyToDirectory + "\Windows_Event_Logs"
    $SaveLogs = @{}
    $rootLogPath = "$env:SystemRoot\System32\Winevt\Logs"
    $allLogPaths = Get-ChildItem $rootLogPath |
        ForEach-Object {
            $_.VersionInfo.FileName
        }

    $baseRegistryLocation = "SYSTEM\CurrentControlSet\Services\EventLog\"
    $logs = @()
    $baseParams = @{
        MachineName = $env:COMPUTERNAME
        GetValue    = "File"
    }

    if ($PassedInfo.AppSysLogs) {
        Write-Verbose("Adding Application and System Logs")

        $appParams = $baseParams + @{
            SubKey = "$baseRegistryLocation`Application"
        }
        $sysParams = $baseParams + @{
            SubKey = "$baseRegistryLocation`System"
        }
        $manParams = $baseParams + @{
            SubKey = "$baseRegistryLocation`MSExchange Management"
        }
        $applicationLogs = Get-RemoteRegistryValue @appParams
        $systemLogs = Get-RemoteRegistryValue @sysParams
        $managementLogs = Get-RemoteRegistryValue @manParams

        if ($null -eq $applicationLogs) { $applicationLogs = "$rootLogPath\Application.evtx" }

        if ($null -eq $systemLogs) { $systemLogs = "$rootLogPath\System.evtx" }

        if ($null -eq $managementLogs) { $managementLogs = "$rootLogPath\MSExchange Management.evtx" }

        $logs += $applicationLogs
        $logs += $systemLogs
        $logs += $managementLogs
    }

    if ($PassedInfo.WindowsSecurityLogs) {

        $secParams = $baseParams + @{
            SubKey = "$baseRegistryLocation`Security"
        }
        $securityLogs = Get-RemoteRegistryValue @secParams

        if ($null -eq $securityLogs) {
            $securityLogs = "$rootLogPath\Security.evtx"
        }
        $logs += $securityLogs
    }

    if ($PassedInfo.AppSysLogs -or
        $PassedInfo.WindowsSecurityLogs) {
        $SaveLogs.Add("Windows-Logs", $logs)
    }

    if ($PassedInfo.ManagedAvailabilityLogs) {
        Write-Verbose("Adding Managed Availability Logs")

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-ActiveMonitoring") }
        $SaveLogs.Add("Microsoft-Exchange-ActiveMonitoring", $Logs)

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-ManagedAvailability") }
        $SaveLogs.Add("Microsoft-Exchange-ManagedAvailability", $Logs)
    }

    if ($PassedInfo.HighAvailabilityLogs) {
        Write-Verbose("Adding High Availability Logs")

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-HighAvailability") }
        $SaveLogs.Add("Microsoft-Exchange-HighAvailability", $Logs)

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Exchange-MailboxDatabaseFailureItems") }
        $SaveLogs.Add("Microsoft-Exchange-MailboxDatabaseFailureItems", $Logs)

        $logs = $allLogPaths | Where-Object { $_.Contains("Microsoft-Windows-FailoverClustering") }
        $SaveLogs.Add("Microsoft-Windows-FailoverClustering", $Logs)
    }

    foreach ($directory in $SaveLogs.Keys) {
        Write-Verbose("Working on directory: {0}" -f $directory)

        $logs = $SaveLogs[$directory]
        $saveLocation = "$baseSaveLocation\$directory"

        Copy-BulkItems -CopyToLocation $saveLocation -ItemsToCopyLocation $logs
        Get-ChildItem $saveLocation | Rename-Item -NewName { $_.Name -replace "%4", "-" }

        if ($directory -eq "Windows-Logs" -and
            $PassedInfo.AppSysLogsToXml) {
            try {
                Write-Verbose("starting to collect event logs and saving out to xml files.")
                Save-DataInfoToFile -DataIn (Get-EventLog Application -After ([DateTime]::Now - $PassedInfo.TimeSpan)) -SaveToLocation ("{0}\Application" -f $saveLocation) -SaveTextFile $false
                Save-DataInfoToFile -DataIn (Get-EventLog System -After ([DateTime]::Now - $PassedInfo.TimeSpan)) -SaveToLocation ("{0}\System" -f $saveLocation) -SaveTextFile $false
                Write-Verbose("end of collecting event logs and saving out to xml files.")
            } catch {
                Write-Verbose("Error occurred while trying to export out the Application and System logs to xml")
                Invoke-CatchBlockActions
            }
        }

        Invoke-ZipFolder -Folder $saveLocation
    }
}
