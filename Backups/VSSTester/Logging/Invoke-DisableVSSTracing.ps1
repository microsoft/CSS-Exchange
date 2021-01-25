function Invoke-DisableVSSTracing {
    " "
    Get-Date
    Write-Host "Disabling VSS Tracing..." -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    logman stop vss -ets
    " "
}