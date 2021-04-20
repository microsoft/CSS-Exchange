Function Get-CounterSamples {
    param(
        [Parameter(Mandatory = $true)][array]$MachineNames,
        [Parameter(Mandatory = $true)][array]$Counters
    )
    Write-VerboseOutput("Calling: Get-CounterSamples")

    try {
        $counterSamples = (Get-Counter -ComputerName $MachineNames -Counter $Counters -ErrorAction Stop).CounterSamples
    } catch {
        Invoke-CatchActions
        Write-VerboseOutput("Failed to get counter samples")
    }
    Write-VerboseOutput("Exiting: Get-CounterSamples")
    return $counterSamples
}