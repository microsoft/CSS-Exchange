# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-DisableDiagnosticsLogging {

    Write-Host " "  $nl
    Get-Date
    Write-Host "Disabling Diagnostics Logging..." -ForegroundColor green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    Set-EventLogLevel 'MSExchange Repl\Service' -level lowest
    $disGetReplSvc = Get-EventLogLevel 'MSExchange Repl\Service'
    Write-Host "$($disGetReplSvc.Identity) - $($disGetReplSvc.EventLevel) $nl"

    Set-EventLogLevel 'MSExchange Repl\Exchange VSS Writer' -level lowest
    $disGetReplVSSWriter = Get-EventLogLevel 'MSExchange Repl\Exchange VSS Writer'
    Write-Host "$($disGetReplVSSWriter.Identity) - $($disGetReplVSSWriter.EventLevel) $nl"
}
