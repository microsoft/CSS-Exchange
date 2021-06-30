# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-ServerObjects {
    param(
        [Parameter(Mandatory = $true)][Array]$ValidServers
    )

    Write-ScriptDebug ("Function Enter: Get-ServerObjects")
    Write-ScriptDebug ("Passed: {0} number of Servers" -f $ValidServers.Count)
    $svrsObject = @()
    $validServersList = @()
    foreach ($svr in $ValidServers) {
        Write-ScriptDebug ("Working on Server {0}" -f $svr)

        $sobj = Get-ExchangeBasicServerObject -ServerName $svr
        if ($sobj -eq $true) {
            Write-ScriptHost -WriteString ("Removing Server {0} from the list" -f $svr) -ForegroundColor "Red" -ShowServer $false
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
        Write-ScriptHost -WriteString ("Something wrong happened in Get-ServerObjects stopping script") -ShowServer $false -ForegroundColor "Red"
        exit
    }
    #Set the valid servers
    $Script:ValidServers = $validServersList
    Write-ScriptDebug("Function Exit: Get-ServerObjects")
    Return $svrsObject
}
