Function Test-LocalServerIsUsed {
    param(
        [Parameter(Mandatory = $true)]$Servers
    )
    foreach ($server in $Servers) {
        if ($server -eq $env:COMPUTERNAME) {
            Write-ScriptDebug ("Local Server {0} is in the list" -f $server)
            return
        }
    }

    Write-ScriptHost -ShowServer $true -WriteString("The server that you are running the script from isn't in the list of servers that we are collecting data from, this is currently not supported. Stopping the script.") -ForegroundColor "Yellow"
    exit
}