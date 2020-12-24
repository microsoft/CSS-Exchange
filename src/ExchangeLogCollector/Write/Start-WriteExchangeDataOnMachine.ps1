Function Start-WriteExchangeDataOnMachines {
    if ($ExchangeServerInfo) {
        [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-ExchangeDataOnMachines
        $timer.Stop()
        Write-ScriptDebug("Write-ExchangeDataOnMachines total time took {0} seconds" -f $timer.Elapsed.TotalSeconds)
    }
}