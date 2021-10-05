# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ProcessorInformation.ps1
. $PSScriptRoot\Get-ServerType.ps1
. $PSScriptRoot\Get-WmiObjectCriticalHandler.ps1
Function Get-HardwareInformation {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    [HealthChecker.HardwareInformation]$hardware_obj = New-Object HealthChecker.HardwareInformation
    $system = Get-WmiObjectCriticalHandler -ComputerName $Script:Server -Class "Win32_ComputerSystem" -CatchActionFunction ${Function:Invoke-CatchActions}
    $hardware_obj.MemoryInformation = Get-WmiObjectCriticalHandler -ComputerName $Script:Server -Class "Win32_PhysicalMemory" -CatchActionFunction ${Function:Invoke-CatchActions}
    $hardware_obj.Manufacturer = $system.Manufacturer
    $hardware_obj.System = $system
    $hardware_obj.AutoPageFile = $system.AutomaticManagedPagefile
    ForEach ($memory in $hardware_obj.MemoryInformation) {
        $hardware_obj.TotalMemory += $memory.Capacity
    }
    $hardware_obj.ServerType = (Get-ServerType -ServerType $system.Manufacturer)
    $processorInformation = Get-ProcessorInformation -MachineName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions}

    #Need to do it this way because of Windows 2012R2
    $processor = New-Object HealthChecker.ProcessorInformation
    $processor.Name = $processorInformation.Name
    $processor.NumberOfPhysicalCores = $processorInformation.NumberOfPhysicalCores
    $processor.NumberOfLogicalCores = $processorInformation.NumberOfLogicalCores
    $processor.NumberOfProcessors = $processorInformation.NumberOfProcessors
    $processor.MaxMegacyclesPerCore = $processorInformation.MaxMegacyclesPerCore
    $processor.CurrentMegacyclesPerCore = $processorInformation.CurrentMegacyclesPerCore
    $processor.ProcessorIsThrottled = $processorInformation.ProcessorIsThrottled
    $processor.DifferentProcessorsDetected = $processorInformation.DifferentProcessorsDetected
    $processor.DifferentProcessorCoreCountDetected = $processorInformation.DifferentProcessorCoreCountDetected
    $processor.EnvironmentProcessorCount = $processorInformation.EnvironmentProcessorCount
    $processor.ProcessorClassObject = $processorInformation.ProcessorClassObject

    $hardware_obj.Processor = $processor
    $hardware_obj.Model = $system.Model

    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    return $hardware_obj
}
