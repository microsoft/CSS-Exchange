# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
function Get-ExchangeServerMaintenanceState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [array]$ComponentsToSkip
    )
    begin {
        Write-Verbose "Calling Function: $($MyInvocation.MyCommand)"
        $getClusterNode = $null
        $getServerComponentState = $null
        $inactiveComponents = @()
    } process {

        $getServerComponentState = Get-ServerComponentState -Identity $Server -ErrorAction SilentlyContinue

        try {
            # Check to see if on the local box, we have CluSSvc running,
            # if not we need to run Get-ClusterNode within Invoke-Command to avoid a warning being displayed.
            $clusterService = Get-Service CluSSvc -ErrorAction Stop
            $runLocally = $clusterService.Status.ToString() -eq "Running"
        } catch {
            Write-Verbose "Failed to get cluster service status information. Inner Exception: $_"
            Invoke-CatchActions
        }

        if ($runLocally) {
            try {
                $errorCount = $Error.Count
                Write-Verbose "Trying to run Get-ClusterNode"
                $getClusterNode = Get-ClusterNode -Name $Server -ErrorAction Stop
                Invoke-ErrorCatchActionLoopFromIndex $errorCount
            } catch {
                Write-Verbose "Failed to run Get-ClusterNode"
                Invoke-ErrorCatchActionLoopFromIndex $errorCount
            }
        } else {
            try {
                Write-Verbose "Trying to run Get-ClusterNode remotely"
                $sb = {
                    # Set to silently continue to avoid warning on the screen.
                    # This can still occur when Cluster Service is not running on the server when within Start-Job.
                    $WarningPreference = "SilentlyContinue"
                    Get-ClusterNode -Name $env:COMPUTERNAME
                }
                $getClusterNode = Invoke-Command -ScriptBlock $sb -ComputerName $Server -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to get the cluster information remotely."
                Invoke-CatchActions
            }
        }

        Write-Verbose "Running ServerComponentStates checks"

        foreach ($component in $getServerComponentState) {
            if (($null -ne $ComponentsToSkip -and
                    $ComponentsToSkip.Count -ne 0) -and
                $ComponentsToSkip -notcontains $component.Component) {
                if ($component.State.ToString() -ne "Active") {
                    $latestLocalState = $null
                    $latestRemoteState = $null

                    if ($null -ne $component.LocalStates -and
                        $component.LocalStates.Count -gt 0) {
                        $latestLocalState = ($component.LocalStates | Sort-Object { $_.TimeStamp } -ErrorAction SilentlyContinue)[-1]
                    }

                    if ($null -ne $component.RemoteStates -and
                        $component.RemoteStates.Count -gt 0) {
                        $latestRemoteState = ($component.RemoteStates | Sort-Object { $_.TimeStamp } -ErrorAction SilentlyContinue)[-1]
                    }

                    Write-Verbose "Component: '$($component.Component)' LocalState: '$($latestLocalState.State)' RemoteState: '$($latestRemoteState.State)'"

                    if ($latestLocalState.State -eq $latestRemoteState.State) {
                        $inactiveComponents += "'{0}' is in Maintenance Mode" -f $component.Component
                    } else {
                        if (($null -ne $latestLocalState) -and
                            ($latestLocalState.State -ne "Active")) {
                            $inactiveComponents += "'{0}' is in Local Maintenance Mode only" -f $component.Component
                        }

                        if (($null -ne $latestRemoteState) -and
                            ($latestRemoteState.State -ne "Active")) {
                            $inactiveComponents += "'{0}' is in Remote Maintenance Mode only" -f $component.Component
                        }
                    }
                } else {
                    Write-Verbose "Component '$($component.Component)' is Active"
                }
            } else {
                Write-Verbose "Component: $($component.Component) will be skipped"
            }
        }
    } end {

        return [PSCustomObject]@{
            InactiveComponents      = [array]$inactiveComponents
            GetServerComponentState = $getServerComponentState
            GetClusterNode          = $getClusterNode
        }
    }
}
