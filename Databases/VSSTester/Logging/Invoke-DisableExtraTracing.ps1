# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Disable ExTRA tracing
.NOTES
    This function may be called within a finally block, so it MUST NOT write to the pipeline:
    https://stackoverflow.com/questions/45104509/powershell-finally-block-skipped-with-ctrl-c
#>
function Invoke-DisableExTRATracing {
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ServerName,

        [Parameter(Mandatory = $false)]
        [object]
        $DatabaseToBackup,

        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath
    )
    Write-Host "$(Get-Date) Disabling ExTRA Tracing..."
    $traceLocalServerOnly = $null -eq $DatabaseToBackup -or $DatabaseToBackup.Server.Name -eq $ServerName
    if ($traceLocalServerOnly) {
        Write-Host
        Write-Host "  Stopping Exchange Trace data collector on $ServerName..."
        logman stop vssTester -s $ServerName
        Write-Host "  Deleting Exchange Trace data collector on $ServerName..."
        logman delete vssTester -s $ServerName
        Write-Host
    } else {
        #stop passive copy
        $dbMountedOn = $DatabaseToBackup.Server.Name
        Write-Host "  Stopping Exchange Trace data collector on $ServerName..."
        logman stop vssTester-Passive -s $ServerName
        Write-Host "  Deleting Exchange Trace data collector on $ServerName..."
        logman delete vssTester-Passive -s $ServerName
        #stop active copy
        Write-Host "  Stopping Exchange Trace data collector on $dbMountedOn..."
        logman stop vssTester-Active -s $dbMountedOn
        Write-Host "  Deleting Exchange Trace data collector on $dbMountedOn..."
        logman delete vssTester-Active -s $dbMountedOn
        Write-Host "  Moving ETL file from $dbMountedOn to $serverName..."
        $etlPath = $OutputPath -replace ":\\", "$\"
        Move-Item "\\$dbMountedOn\$etlPath\vsstester-active_000001.etl" "\\$ServerName\$etlPath\vsstester-active_000001.etl" -Force
    }
}
