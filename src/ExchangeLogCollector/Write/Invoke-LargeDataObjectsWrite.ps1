Function Invoke-LargeDataObjectsWrite {

    if ($ExchangeServerInfo) {
        [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-LargeDataObjectsOnMachine
        $timer.Stop()
        Write-ScriptDebug("Write-ExchangeDataOnMachines total time took {0} seconds" -f $timer.Elapsed.TotalSeconds)
    }
}