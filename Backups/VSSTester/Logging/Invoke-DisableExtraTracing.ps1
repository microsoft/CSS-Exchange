function Invoke-DisableExTRATracing {
    " "
    Get-Date
    Write-Host "Disabling ExTRA Tracing..." -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    if ($dbMountedOn -eq "$serverName") {
        #stop active copy
        Write-Host " "
        "Stopping Exchange Trace data collector on $serverName..."
        logman stop vssTester -s $serverName
        "Deleting Exchange Trace data collector on $serverName..."
        logman delete vssTester -s $serverName
        " "
    } else {
        #stop passive copy
        "Stopping Exchange Trace data collector on $serverName..."
        logman stop vssTester-Passive -s $serverName
        "Deleting Exchange Trace data collector on $serverName..."
        logman delete vssTester-Passive -s $serverName
        #stop active copy
        "Stopping Exchange Trace data collector on $dbMountedOn..."
        logman stop vssTester-Active -s $dbMountedOn
        "Deleting Exchange Trace data collector on $dbMountedOn..."
        logman delete vssTester-Active -s $dbMountedOn
        " "
        "Moving ETL file from $dbMountedOn to $serverName..."
        " "
        $etlPath = $path -replace ":\\", "$\"
        Move-Item "\\$dbMountedOn\$etlPath\vsstester-active_000001.etl" "\\$servername\$etlPath\vsstester-active_000001.etl" -Force
    }
}