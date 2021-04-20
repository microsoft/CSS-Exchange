function Invoke-EnableVSSTracing {
    " "
    Get-Date
    Write-Host "Enabling VSS Tracing..." -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    logman start vss -o $path\vss.etl -ets -p "{9138500e-3648-4edb-aa4c-859e9f7b7c38}" 0xfff 255
}