# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeBasicServerObject.ps1
. $PSScriptRoot\Get-TransportLoggingInformationPerServer.ps1
Function Get-ServerObjects {
    param(
        [Parameter(Mandatory = $true)][Array]$ValidServers
    )

    Write-Verbose ("Function Enter: Get-ServerObjects")
    Write-Verbose ("Passed: {0} number of Servers" -f $ValidServers.Count)
    $svrsObject = @()
    $validServersList = @()
    foreach ($svr in $ValidServers) {
        Write-Verbose ("Working on Server {0}" -f $svr)

        $sobj = Get-ExchangeBasicServerObject -ServerName $svr
        if ($sobj -eq $true) {
            Write-Host "Removing Server $svr from the list" -ForegroundColor "Red"
            continue
        } else {
            $validServersList += $svr
        }

        if ($Script:AnyTransportSwitchesEnabled -and ($sobj.Hub -or $sobj.Version -ge 15)) {
            $sobj | Add-Member -Name TransportInfoCollect -MemberType NoteProperty -Value $true
            $sobj | Add-Member -Name TransportInfo -MemberType NoteProperty -Value `
            (Get-TransportLoggingInformationPerServer -Server $svr `
                    -version $sobj.Version `
                    -EdgeServer $sobj.Edge `
                    -CASOnly $sobj.CASOnly `
                    -MailboxOnly $sobj.MailboxOnly)
        } else {
            $sobj | Add-Member -Name TransportInfoCollect -MemberType NoteProperty -Value $false
        }

        if ($PopLogs -and
            !$Script:EdgeRoleDetected) {
            $sobj | Add-Member -Name PopLogsLocation -MemberType NoteProperty -Value ((Get-PopSettings -Server $svr).LogFileLocation)
        }

        if ($ImapLogs -and
            !$Script:EdgeRoleDetected) {
            $sobj | Add-Member -Name ImapLogsLocation -MemberType NoteProperty -Value ((Get-ImapSettings -Server $svr).LogFileLocation)
        }

        $svrsObject += $sobj
    }

    if (($null -eq $svrsObject) -or
        ($svrsObject.Count -eq 0)) {
        Write-Host "Something wrong happened in Get-ServerObjects stopping script" -ForegroundColor "Red"
        exit
    }
    #Set the valid servers
    $Script:ValidServers = $validServersList
    Write-Verbose("Function Exit: Get-ServerObjects")
    Return $svrsObject
}
