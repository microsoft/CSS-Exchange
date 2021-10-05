# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Invoke-CatchActions.ps1
Function Get-ExchangeServerMaintenanceState {
    param(
        [Parameter(Mandatory = $false)][array]$ComponentsToSkip
    )
    Write-Verbose "Calling Function: $($MyInvocation.MyCommand)"

    [HealthChecker.ExchangeServerMaintenance]$serverMaintenance = New-Object -TypeName HealthChecker.ExchangeServerMaintenance
    $serverMaintenance.GetServerComponentState = Get-ServerComponentState -Identity $Script:Server -ErrorAction SilentlyContinue

    try {
        $serverMaintenance.GetClusterNode = Get-ClusterNode -Name $Script:Server -ErrorAction Stop
    } catch {
        Write-Verbose "Failed to run Get-ClusterNode"
        Invoke-CatchActions
    }

    Write-Verbose "Running ServerComponentStates checks"

    foreach ($component in $serverMaintenance.GetServerComponentState) {
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
                    $serverMaintenance.InactiveComponents += "'{0}' is in Maintenance Mode" -f $component.Component
                } else {
                    if (($null -ne $latestLocalState) -and
                        ($latestLocalState.State -ne "Active")) {
                        $serverMaintenance.InactiveComponents += "'{0}' is in Local Maintenance Mode only" -f $component.Component
                    }

                    if (($null -ne $latestRemoteState) -and
                        ($latestRemoteState.State -ne "Active")) {
                        $serverMaintenance.InactiveComponents += "'{0}' is in Remote Maintenance Mode only" -f $component.Component
                    }
                }
            } else {
                Write-Verbose "Component '$($component.Component)' is Active"
            }
        } else {
            Write-Verbose "Component: $($component.Component) will be skipped"
        }
    }

    return $serverMaintenance
}
