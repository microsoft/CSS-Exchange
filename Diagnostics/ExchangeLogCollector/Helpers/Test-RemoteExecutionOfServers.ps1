# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-RemoteExecutionOfServers {
    param(
        [Parameter(Mandatory = $true)][Array]$ServerList
    )
    Write-ScriptDebug("Function Enter: Test-RemoteExecutionOfServers")
    Write-ScriptHost -WriteString "Checking to see if the servers are up in this list:" -ShowServer $false
    $ServerList | ForEach-Object { Write-ScriptHost -WriteString $_ -ShowServer $false }
    #Going to just use Invoke-Command to see if the servers are up. As ICMP might be disabled in the environment.
    Write-ScriptHost " " -ShowServer $false
    Write-ScriptHost -WriteString "For all the servers in the list, checking to see if Invoke-Command will work against them." -ShowServer $false
    #shouldn't need to test if they are Exchange servers, as we should be doing that locally as well.
    $validServers = @()
    foreach ($server in $ServerList) {

        try {
            Write-ScriptHost -WriteString ("Checking Server {0}....." -f $server) -ShowServer $false -NoNewLine $true
            Invoke-Command -ComputerName $server -ScriptBlock { Get-Process | Out-Null } -ErrorAction Stop
            #if that doesn't fail, we should be okay to add it to the working list
            Write-ScriptHost -WriteString ("Passed") -ShowServer $false -ForegroundColor "Green"
            $validServers += $server
        } catch {
            Write-ScriptHost -WriteString "Failed" -ShowServer $false -ForegroundColor "Red"
            Write-ScriptHost -WriteString ("Removing Server {0} from the list to collect data from" -f $server) -ShowServer $false
            Invoke-CatchBlockActions
        }
    }

    if ($validServers.Count -gt 0) {
        $validServers = Test-DiskSpace -Servers $validServers -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize
    }

    #all servers in teh list weren't able to do Invoke-Command or didn't have enough free space. Try to do against local server.
    if ($null -ne $validServers -and
        $validServers.Count -eq 0) {

        #Can't do this on a tools or remote shell
        if ($Script:LocalExchangeShell.ToolsOnly -or
            $Script:LocalExchangeShell.RemoteShell) {
            Write-ScriptHost -WriteString "Failed to invoke against the machines to do remote collection from a tools box or a remote machine." -ForegroundColor "Red"
            exit
        }

        Write-ScriptHost -ShowServer $false -WriteString ("Failed to do remote collection for all the servers in the list...") -ForegroundColor "Yellow"

        if ((Enter-YesNoLoopAction -Question "Do you want to collect from the local server only?" -YesAction { return $true } -NoAction { return $false })) {
            $validServers = @($env:COMPUTERNAME)
        } else {
            exit
        }

        #want to test local server's free space first before moving to just collecting the data
        if ($null -eq (Test-DiskSpace -Servers $validServers -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize)) {
            Write-ScriptHost -ShowServer $false -WriteString ("Failed to have enough space available locally. We can't continue with the data collection") -ForegroundColor "Yellow"
            exit
        }
    }

    Write-ScriptDebug("Function Exit: Test-RemoteExecutionOfServers")
    return $validServers
}
