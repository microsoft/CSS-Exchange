# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\WriteHelpers.ps1

function Write-SearchProcessStateObject {
    [CmdletBinding()]
    param(
        [object]$SearchProcessState # The object from Get-SearchProcessState.ps1
    )
    process {

        # If any of the things we check for is false, we want to state the Search Process State is in a failed state
        $statusReason = [string]::Empty

        if (-not ($SearchProcessState.ServicesConfigCorrectly) -or
            -not ($SearchProcessState.AllProcessesRunning) -or
            -not ($SearchProcessState.RunForAnHour)) {

            if (-not ($SearchProcessState.ServicesConfigCorrectly)) {
                $statusReason = "Services aren't configured correctly. Must be running and automatic."
            } elseif (-not ($SearchProcessState.AllProcessesRunning)) {
                $statusReason = "Not all processes are running."
            } else {
                $statusReason = "Processes haven't been running for at least 1 hour. This could be caused by a crash or an unexpected restart."
            }
            $status = "Failed"
        } elseif ($SearchProcessState.ThirdPartyModuleFound) {
            # Warning only if we didn't fail when we detect 3rd party modules
            $status = "Warning - Third Party Modules Detected"
        } else {
            $status = "Success"
        }

        Write-DashLineBox "Search Process Status - $($SearchProcessState.ServerName): $status"

        if ($statusReason -ne [string]::Empty) {
            Write-Host "Failed Reason: $statusReason"
            Write-Host ""
        }

        # Write out quick find info for debug
        if ($status -ne "Success") {
            Write-Verbose "Latest Process Start: $($SearchProcessState.LatestProcessStartTime)"
            Write-Verbose "ServicesConfigCorrectly: $($SearchProcessState.ServicesConfigCorrectly)"
            Write-Verbose "AllProcessesRunning: $($SearchProcessState.AllProcessesRunning)"
            Write-Verbose "RunForAnHour: $($SearchProcessState.RunForAnHour)"
            Write-Verbose "ThirdPartyModuleFound: $($SearchProcessState.ThirdPartyModuleFound)"
            Write-Verbose ""
        }

        # Display the Services and Process Information
        foreach ($service in $SearchProcessState.ProcessInformation.Services) {
            Write-Host "Name: $($service.Name)"
            Write-Host "Status: $($service.Status)"
            Write-Host "StartType: $($service.StartType)"
            Write-Host ""
        }

        foreach ($process in $SearchProcessState.ProcessInformation.Processes) {
            Write-Host "Process Name: $($process.Name)"
            Write-Host "PID: $($process.PID)"
            Write-Host "Start Time: $($process.StartTime)"
            Write-Host "Contains 3rd Party Modules: $($process.ThirdPartyModules.Count -ne 0)"
            Write-Host ""
        }

        #TODO: Display the modules
        if ($SearchProcessState.ThirdPartyModuleFound) {
            Write-Host "Please exclude AV from all Exchange processes: https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019"
            Write-Host ""
        }

        Write-Host ""
    }
}
