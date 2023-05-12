# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ProcessorInformation.ps1
. $PSScriptRoot\Get-ServerType.ps1
. $PSScriptRoot\Get-WmiObjectCriticalHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-WmiObjectHandler.ps1
function Get-HardwareInformation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $system = Get-WmiObjectCriticalHandler -ComputerName $Server -Class "Win32_ComputerSystem" -CatchActionFunction ${Function:Invoke-CatchActions}
        $physicalMemory = Get-WmiObjectHandler -ComputerName $Server -Class "Win32_PhysicalMemory" -CatchActionFunction ${Function:Invoke-CatchActions}
        $processorInformation = Get-ProcessorInformation -MachineName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $totalMemory = 0

        if ($null -eq $physicalMemory) {
            Write-Verbose "Using memory from Win32_ComputerSystem class instead. This may cause memory calculation issues."
            $totalMemory = $system.TotalPhysicalMemory
        } else {
            foreach ($memory in $physicalMemory) {
                $totalMemory += $memory.Capacity
            }
        }
    } end {
        Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
        return [PSCustomObject]@{
            Manufacturer      = $system.Manufacturer
            ServerType        = (Get-ServerType -ServerType $system.Manufacturer)
            AutoPageFile      = $system.AutomaticManagedPagefile
            Model             = $system.Model
            System            = $system
            Processor         = $processorInformation
            TotalMemory       = $totalMemory
            MemoryInformation = [array]$physicalMemory
        }
    }
}
