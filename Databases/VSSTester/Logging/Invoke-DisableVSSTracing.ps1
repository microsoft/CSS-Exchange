# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Disables VSS tracing.
.NOTES
    This function may be called within a finally block, so it MUST NOT write to the pipeline:
    https://stackoverflow.com/questions/45104509/powershell-finally-block-skipped-with-ctrl-c
#>
function Invoke-DisableVSSTracing {
    [OutputType([System.Void])]
    param()

    Write-Host "$(Get-Date) Disabling VSS Tracing..."
    logman stop vss -ets
}
