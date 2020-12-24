Function Get-ExchangeObjectServerData {
    param(
        [Parameter(Mandatory = $true)][array]$Servers 
    )
    Write-ScriptDebug("Enter Function: Get-ExchangeObjectServerData")
    $serverObjects = @()
    foreach ($server in $Servers) {
        $obj = Get-ExchangeBasicServerObject -ServerName $server -AddGetServerProperty $true 
    
        if ($obj.Hub) {
            if ($obj.Version -ge 15) {
                $hubInfo = Get-TransportService $server 
            } else {
                $hubInfo = Get-TransportServer $server
            }
            $obj | Add-Member -MemberType NoteProperty -Name TransportServerInfo -Value $hubInfo
        }
        if ($obj.CAS) {
            if ($obj.Version -ge 16) {
                $casInfo = Get-ClientAccessService $server -IncludeAlternateServiceAccountCredentialStatus 
            } else {
                $casInfo = Get-ClientAccessServer $server -IncludeAlternateServiceAccountCredentialStatus 
            }
            $obj | Add-Member -MemberType NoteProperty -Name CAServerInfo -Value $casInfo
        }
        if ($obj.Mailbox) {
            $obj | Add-Member -MemberType NoteProperty -Name MailboxServerInfo -Value (Get-MailboxServer $server)
        }
        if ($obj.Version -ge 15) {
            $obj | Add-Member -MemberType NoteProperty -Name HealthReport -Value (Get-HealthReport $server) 
            $obj | Add-Member -MemberType NoteProperty -Name ServerComponentState -Value (Get-ServerComponentState $server)
            $obj | Add-Member -MemberType NoteProperty -Name serverMonitoringOverride -Value (Get-serverMonitoringOverride $server)
            $obj | Add-Member -MemberType NoteProperty -Name ServerHealth -Value (Get-ServerHealth $server)
        }
    
        $serverObjects += $obj 
    }
    
    return $serverObjects 
}