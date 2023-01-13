# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeBasicServerObject.ps1
. $PSScriptRoot\Get-TransportLoggingInformationPerServer.ps1
function Get-ServerObjects {
    param(
        [Parameter(Mandatory = $true)][Array]$ValidServers
    )

    Write-Verbose ("Function Enter: Get-ServerObjects")
    Write-Verbose ("Passed: {0} number of Servers" -f $ValidServers.Count)
    $serversObject = @()
    $validServersList = @()
    foreach ($svr in $ValidServers) {
        Write-Verbose ("Working on Server {0}" -f $svr)

        $serverObj = Get-ExchangeBasicServerObject -ServerName $svr
        if ($serverObj -eq $true) {
            Write-Host "Removing Server $svr from the list" -ForegroundColor "Red"
            continue
        } else {
            $validServersList += $svr
        }

        if ($Script:AnyTransportSwitchesEnabled -and ($serverObj.Hub -or $serverObj.Version -ge 15)) {
            $serverObj | Add-Member -Name TransportInfoCollect -MemberType NoteProperty -Value $true
            $serverObj | Add-Member -Name TransportInfo -MemberType NoteProperty -Value `
            (Get-TransportLoggingInformationPerServer -Server $svr `
                    -version $serverObj.Version `
                    -EdgeServer $serverObj.Edge `
                    -CASOnly $serverObj.CASOnly `
                    -MailboxOnly $serverObj.MailboxOnly)
        } else {
            $serverObj | Add-Member -Name TransportInfoCollect -MemberType NoteProperty -Value $false
        }

        if ($PopLogs -and
            !$Script:EdgeRoleDetected) {
            $serverObj | Add-Member -Name PopLogsLocation -MemberType NoteProperty -Value ((Get-PopSettings -Server $svr).LogFileLocation)
        }

        if ($ImapLogs -and
            !$Script:EdgeRoleDetected) {
            $serverObj | Add-Member -Name ImapLogsLocation -MemberType NoteProperty -Value ((Get-ImapSettings -Server $svr).LogFileLocation)
        }

        $serversObject += $serverObj
    }

    if (($null -eq $serversObject) -or
        ($serversObject.Count -eq 0)) {
        Write-Host "Something wrong happened in Get-ServerObjects stopping script" -ForegroundColor "Red"
        exit
    }
    #Set the valid servers
    $Script:ValidServers = $validServersList
    Write-Verbose("Function Exit: Get-ServerObjects")
    return $serversObject
}
