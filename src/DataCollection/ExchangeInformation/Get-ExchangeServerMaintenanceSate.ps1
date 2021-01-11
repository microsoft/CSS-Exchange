Function Get-ExchangeServerMaintenanceState {
    param(
        [Parameter(Mandatory = $false)][array]$ComponentsToSkip
    )
    Write-VerboseOutput("Calling Function: Get-ExchangeServerMaintenanceState")

    [HealthChecker.ExchangeServerMaintenance]$serverMaintenance = New-Object -TypeName HealthChecker.ExchangeServerMaintenance
    $serverMaintenance.GetServerComponentState = Get-ServerComponentState -Identity $Script:Server -ErrorAction SilentlyContinue

    try {
        $serverMaintenance.GetMailboxServer = Get-MailboxServer -Identity $Script:Server -ErrorAction SilentlyContinue
    } catch {
        Write-VerboseOutput("Failed to run Get-MailboxServer")
        Invoke-CatchActions
    }

    try {
        $serverMaintenance.GetClusterNode = Get-ClusterNode -Name $Script:Server -ErrorAction Stop
    } catch {
        Write-VerboseOutput("Failed to run Get-ClusterNode")
        Invoke-CatchActions
    }

    Write-VerboseOutput("Running ServerComponentStates checks")

    foreach ($component in $serverMaintenance.GetServerComponentState) {
        if (($null -ne $ComponentsToSkip -and
                $ComponentsToSkip.Count -ne 0) -and
            $ComponentsToSkip -notcontains $component.Component) {
            if ($component.State -ne "Active") {
                $latestLocalState = $null
                $latestRemoteState = $null

                if ($null -ne $component.LocalStates) {
                    $latestLocalState = ($component.LocalStates | Sort-Object { $_.TimeStamp } -ErrorAction SilentlyContinue)[-1]
                }

                if ($null -ne $component.RemoteStates) {
                    $latestRemoteState = ($component.RemoteStates | Sort-Object { $_.TimeStamp } -ErrorAction SilentlyContinue)[-1]
                }

                Write-VerboseOutput("Component: {0} LocalState: '{1}' RemoteState: '{2}'" -f $component.Component, $latestLocalState.State, $latestRemoteState.State)

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
                Write-VerboseOutput("Component '{0}' is Active" -f $component.Component)
            }
        } else {
            Write-VerboseOutput("Component: {0} will be skipped" -f $component.Component)
        }
    }

    return $serverMaintenance
}