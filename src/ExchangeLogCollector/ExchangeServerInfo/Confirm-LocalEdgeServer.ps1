Function Confirm-LocalEdgeServer {
    $server = Get-ExchangeBasicServerObject -ServerName $env:COMPUTERNAME
    if ($server.Edge) {
        return $true 
    } else {
        return $false 
    }
}