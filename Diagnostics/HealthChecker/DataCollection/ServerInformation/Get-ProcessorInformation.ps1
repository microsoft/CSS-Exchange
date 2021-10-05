# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-WmiObjectCriticalHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
Function Get-ProcessorInformation {
    [CmdletBinding()]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [scriptblock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $wmiObject = $null
        $processorName = [string]::Empty
        $maxClockSpeed = 0
        $numberOfLogicalCores = 0
        $numberOfPhysicalCores = 0
        $numberOfProcessors = 0
        $currentClockSpeed = 0
        $processorIsThrottled = $false
        $differentProcessorCoreCountDetected = $false
        $differentProcessorsDetected = $false
        $presentedProcessorCoreCount = 0
        $previousProcessor = $null
    }
    process {
        $wmiObject = @(Get-WmiObjectCriticalHandler -ComputerName $MachineName -Class "Win32_Processor" -CatchActionFunction $CatchActionFunction)
        $processorName = $wmiObject[0].Name
        $maxClockSpeed = $wmiObject[0].MaxClockSpeed
        Write-Verbose "Evaluating processor results"

        foreach ($processor in $wmiObject) {
            $numberOfPhysicalCores += $processor.NumberOfCores
            $numberOfLogicalCores += $processor.NumberOfLogicalProcessors
            $numberOfProcessors++

            if ($processor.CurrentClockSpeed -lt $processor.MaxClockSpeed) {
                Write-Verbose "Processor is being throttled"
                $processorIsThrottled = $true
                $currentClockSpeed = $processor.CurrentClockSpeed
            }

            if ($null -ne $previousProcessor) {

                if ($processor.Name -ne $previousProcessor.Name -or
                    $processor.MaxClockSpeed -ne $previousProcessor.MaxClockSpeed) {
                    Write-Verbose "Different Processors are detected!!! This is an issue."
                    $differentProcessorsDetected = $true
                }

                if ($processor.NumberOfLogicalProcessors -ne $previousProcessor.NumberOfLogicalProcessors) {
                    Write-Verbose "Different Processor core count per processor socket detected. This is an issue."
                    $differentProcessorCoreCountDetected = $true
                }
            }
            $previousProcessor = $processor
        }

        $presentedProcessorCoreCount = Invoke-ScriptBlockHandler -ComputerName $MachineName `
            -ScriptBlock { [System.Environment]::ProcessorCount } `
            -ScriptBlockDescription "Trying to get the System.Environment ProcessorCount" `
            -CatchActionFunction $CatchActionFunction

        if ($null -eq $presentedProcessorCoreCount) {
            Write-Verbose "Wasn't able to get Presented Processor Core Count on the Server. Setting to -1."
            $presentedProcessorCoreCount = -1
        }
    }
    end {
        Write-Verbose "PresentedProcessorCoreCount: $presentedProcessorCoreCount"
        Write-Verbose "NumberOfPhysicalCores: $numberOfPhysicalCores | NumberOfLogicalCores: $numberOfLogicalCores | NumberOfProcessors: $numberOfProcessors"
        Write-Verbose "ProcessorIsThrottled: $processorIsThrottled | CurrentClockSpeed: $currentClockSpeed"
        Write-Verbose "DifferentProcessorsDetected: $differentProcessorsDetected | DifferentProcessorCoreCountDetected: $differentProcessorCoreCountDetected"
        return [PSCustomObject]@{
            Name                                = $processorName
            MaxMegacyclesPerCore                = $maxClockSpeed
            NumberOfPhysicalCores               = $numberOfPhysicalCores
            NumberOfLogicalCores                = $numberOfLogicalCores
            NumberOfProcessors                  = $numberOfProcessors
            CurrentMegacyclesPerCore            = $currentClockSpeed
            ProcessorIsThrottled                = $processorIsThrottled
            DifferentProcessorsDetected         = $differentProcessorsDetected
            DifferentProcessorCoreCountDetected = $differentProcessorCoreCountDetected
            EnvironmentProcessorCount           = $presentedProcessorCoreCount
            ProcessorClassObject                = $wmiObject
        }
    }
}
