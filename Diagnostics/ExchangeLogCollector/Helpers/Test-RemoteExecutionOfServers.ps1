# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Enter-YesNoLoopAction.ps1
. $PSScriptRoot\Test-DiskSpace.ps1
function Test-RemoteExecutionOfServers {
    param(
        [Parameter(Mandatory = $true)][Array]$ServerList
    )
    Write-Verbose("Function Enter: Test-RemoteExecutionOfServers")
    Write-Host "Checking to see if the servers are up in this list:"
    $ServerList | ForEach-Object { Write-Host $_ }
    #Going to just use Invoke-Command to see if the servers are up. As ICMP might be disabled in the environment.
    Write-Host ""
    Write-Host "For all the servers in the list, checking to see if Invoke-Command will work against them."
    #shouldn't need to test if they are Exchange servers, as we should be doing that locally as well.
    $validServers = @()
    foreach ($server in $ServerList) {

        try {
            Write-Host "Checking Server $server....." -NoNewline
            Invoke-Command -ComputerName $server -ScriptBlock { Get-Process | Out-Null } -ErrorAction Stop
            #if that doesn't fail, we should be okay to add it to the working list
            Write-Host "Passed" -ForegroundColor "Green"
            $validServers += $server
        } catch {
            Write-Host "Failed" -ForegroundColor "Red"
            Write-Host "Removing Server $server from the list to collect data from"
            Invoke-CatchActions
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
            Write-Host "Failed to invoke against the machines to do remote collection from a tools box or a remote machine." -ForegroundColor "Red"
            exit
        }

        Write-Host "Failed to do remote collection for all the servers in the list..." -ForegroundColor "Yellow"

        if ((Enter-YesNoLoopAction -Question "Do you want to collect from the local server only?" -YesAction { return $true } -NoAction { return $false })) {
            $validServers = @($env:COMPUTERNAME)
        } else {
            exit
        }

        #want to test local server's free space first before moving to just collecting the data
        if ($null -eq (Test-DiskSpace -Servers $validServers -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize)) {
            Write-Host "Failed to have enough space available locally. We can't continue with the data collection" -ForegroundColor "Yellow"
            exit
        }
    }

    Write-Verbose("Function Exit: Test-RemoteExecutionOfServers")
    return $validServers
}
