# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-CounterSamples {
    param(
        [Parameter(Mandatory = $true)][array]$MachineNames,
        [Parameter(Mandatory = $true)][array]$Counters
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    try {
        $counterSamples = (Get-Counter -ComputerName $MachineNames -Counter $Counters -ErrorAction Stop).CounterSamples
    } catch {
        Invoke-CatchActions
        Write-Verbose "Failed to get counter samples"
    }
    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    return $counterSamples
}
