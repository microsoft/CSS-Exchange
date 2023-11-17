# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Disable diagnostics logging for VSSTester.
.NOTES
    This function may be called within a finally block, so it MUST NOT write to the pipeline:
    https://stackoverflow.com/questions/45104509/powershell-finally-block-skipped-with-ctrl-c
#>
function Invoke-DisableDiagnosticsLogging {
    [OutputType([System.Void])]
    param()

    Write-Host "$(Get-Date) Disabling Diagnostics Logging..."
    Set-EventLogLevel 'MSExchange Repl\Service' -level lowest
    $disGetReplSvc = Get-EventLogLevel 'MSExchange Repl\Service'
    Write-Host "  $($disGetReplSvc.Identity) - $($disGetReplSvc.EventLevel)"

    Set-EventLogLevel 'MSExchange Repl\Exchange VSS Writer' -level lowest
    $disGetReplVSSWriter = Get-EventLogLevel 'MSExchange Repl\Exchange VSS Writer'
    Write-Host "  $($disGetReplVSSWriter.Identity) - $($disGetReplVSSWriter.EventLevel)"
}
