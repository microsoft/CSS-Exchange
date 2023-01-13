# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Copy-BulkItems.ps1
. $PSScriptRoot\Save-DataInfoToFile.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
function Save-WindowsEventLogs {

    Write-Verbose("Function Enter: Save-WindowsEventLogs")
    $baseSaveLocation = $Script:RootCopyToDirectory + "\Windows_Event_Logs"
    $SaveLogs = @{}
    $rootLogPath = "$env:SystemRoot\System32\WinEvt\Logs"
    $allLogPaths = Get-ChildItem $rootLogPath |
        ForEach-Object {
            $_.VersionInfo.FileName
        }

    if ($PassedInfo.AppSysLogs -or
        $PassedInfo.WindowsSecurityLogs) {

        $baseRegistryLocation = "SYSTEM\CurrentControlSet\Services\EventLog\"
        $logs = @()
        $baseParams = @{
            MachineName = $env:COMPUTERNAME
            GetValue    = "File"
        }

        Write-Verbose("Adding Windows Default Event Logging: AppSysLogs: $($PassedInfo.AppSysLogs) WindowsSecurityLogs: $($PassedInfo.WindowsSecurityLogs)")

        foreach ($logName in @("Application", "System", "MSExchange Management", "Security")) {

            if ((-not ($PassedInfo.WindowsSecurityLogs)) -and
                $logName -eq "Security") { continue }
            elseif ((-not ($PassedInfo.AppSysLogs)) -and
                $logName -ne "Security") { continue }

            Write-Verbose "Adding LogName: $logName"
            $params = $baseParams + @{
                SubKey = "$baseRegistryLocation$logName"
            }
            $logLocation = Get-RemoteRegistryValue @params

            if ($null -eq $logLocation) { $logLocation = "$rootLogPath\$logName.evtx" }
            $logs += $logLocation
        }

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
                Save-DataInfoToFile -DataIn (Get-EventLog Application -After ([DateTime]::Now - $PassedInfo.TimeSpan) -Before ([DateTime]::Now - $PassedInfo.EndTimeSpan)) -SaveToLocation ("{0}\Application" -f $saveLocation) -SaveTextFile $false
                Save-DataInfoToFile -DataIn (Get-EventLog System -After ([DateTime]::Now - $PassedInfo.TimeSpan) -Before ([DateTime]::Now - $PassedInfo.EndTimeSpan)) -SaveToLocation ("{0}\System" -f $saveLocation) -SaveTextFile $false
                Write-Verbose("end of collecting event logs and saving out to xml files.")
            } catch {
                Write-Verbose("Error occurred while trying to export out the Application and System logs to xml")
                Invoke-CatchActions
            }
        }

        Invoke-ZipFolder -Folder $saveLocation
    }
}
