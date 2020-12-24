Function Test-RemoteExecutionOfServers {
    param(
        [Parameter(Mandatory = $true)][Array]$ServerList
    )
    Write-ScriptDebug("Function Enter: Test-RemoteExecutionOfServers")
    $serversUp = @() 
    Write-ScriptHost -WriteString "Checking to see if the servers are up in this list:" -ShowServer $false 
    foreach ($server in $ServerList) {
        Write-ScriptHost -WriteString $server -ShowServer $false
    }
    Write-ScriptHost -WriteString " " -ShowServer $false 
    Write-ScriptHost -WriteString "Checking their status...." -ShowServer $false 
    foreach ($server in $ServerList) {
        Write-ScriptHost -WriteString ("Checking server {0}...." -f $server) -ShowServer $false -NoNewLine $true
        if ((Test-Connection $server -Quiet)) {   
            Write-ScriptHost -WriteString "Online" -ShowServer $false -ForegroundColor "Green"
            $serversUp += $server
        } else {
            Write-ScriptHost -WriteString "Offline" -ShowServer $false -ForegroundColor "Red"
            Write-ScriptHost -WriteString ("Removing Server {0} from the list to collect data from" -f $server) -ShowServer $false 
        }
    }
    #Now we should check to see if can use WRM with invoke-command
    Write-ScriptHost " " -ShowServer $false 
    Write-ScriptHost -WriteString "For all the servers that are up, we are going to see if remote execution will work" -ShowServer $false 
    #shouldn't need to test if they are Exchange servers, as we should be doing that locally as well. 
    $validServers = @()
    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    foreach ($server in $serversUp) {
    
        try {
            Write-ScriptHost -WriteString ("Checking Server {0}....." -f $server) -ShowServer $false -NoNewLine $true
            Invoke-Command -ComputerName $server -ScriptBlock { Get-Process | Out-Null }
            #if that doesn't fail, we should be okay to add it to the working list 
            Write-ScriptHost -WriteString ("Passed") -ShowServer $false -ForegroundColor "Green" 
            $validServers += $server
        } catch {
            Write-ScriptHost -WriteString "Failed" -ShowServer $false -ForegroundColor "Red" 
            Write-ScriptHost -WriteString ("Removing Server {0} from the list to collect data from" -f $server) -ShowServer $false 
        }
    }
    Write-ScriptDebug("Function Exit: Test-RemoteExecutionOfServers")
    $ErrorActionPreference = $oldErrorAction
    return $validServers 
}