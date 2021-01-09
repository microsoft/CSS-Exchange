Function Start-WriteExchangeDataOnMachines {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'TODO: Change this')]
    [CmdletBinding()]
    param()
    if ($ExchangeServerInfo) {
        [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-ExchangeDataOnMachines
        $timer.Stop()
        Write-ScriptDebug("Write-ExchangeDataOnMachines total time took {0} seconds" -f $timer.Elapsed.TotalSeconds)
    }
}