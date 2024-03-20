# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-EnableDiagnosticsLogging {
    [OutputType([System.Void])]
    param()

    Write-Host "$(Get-Date) Enabling Diagnostics Logging..."
    Set-EventLogLevel 'MSExchange Repl\Service' -level expert
    $getReplSvc = Get-EventLogLevel 'MSExchange Repl\Service'
    Write-Host "  $($getReplSvc.Identity) - $($getReplSvc.EventLevel)"

    Set-EventLogLevel 'MSExchange Repl\Exchange VSS Writer' -level expert
    $getReplVSSWriter = Get-EventLogLevel 'MSExchange Repl\Exchange VSS Writer'
    Write-Host "  $($getReplVSSWriter.Identity)  - $($getReplVSSWriter.EventLevel)"
}
