function Invoke-EnableDiagnosticsLogging {
    " "
    Get-Date
    Write-Host "Enabling Diagnostics Logging..." -ForegroundColor green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    Set-EventLogLevel 'MSExchange Repl\Service' -level expert
    $getReplSvc = Get-EventLogLevel 'MSExchange Repl\Service'
    Write-Host "$($getReplSvc.Identity) - $($getReplSvc.EventLevel) $nl"

    Set-EventLogLevel 'MSExchange Repl\Exchange VSS Writer' -level expert
    $getReplVSSWriter = Get-EventLogLevel 'MSExchange Repl\Exchange VSS Writer'
    Write-Host "$($getReplVSSWriter.Identity)  - $($getReplVSSWriter.EventLevel)  $nl"

    if ($exchVer -eq "2010") {
        Set-EventLogLevel 'MSExchangeIS\9002 System\Backup Restore' -level expert
        $getBackRest = Get-EventLogLevel 'MSExchangeIS\9002 System\Backup Restore'
        Write-Host "$($getBackRest.Identity) - $($getBackRest.EventLevel)  $nl"
    }
}
