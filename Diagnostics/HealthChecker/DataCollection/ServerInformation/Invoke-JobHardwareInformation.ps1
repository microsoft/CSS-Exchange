# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    This the main function script block that will be executed to collect data about the Hardware Information of the remote server.
    This function must be executed only on the server you want to collect data from.
    This will return an object to the pipeline about the server.
#>
function Invoke-JobHardwareInformation {
    [CmdletBinding()]
    param()
    begin {

        # Extract for Pester Testing - Start
        # Build Process to add functions.
        . $PSScriptRoot\Get-ProcessorInformation.ps1
        . $PSScriptRoot\Get-ServerType.ps1
        # Extract for Pester Testing - End

        if ($PSSenderInfo) {
            $Script:ErrorsExcluded = @()
        }

        $jobStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $system = $null
        $physicalMemory = $null
        $processorInformation = $null
        $totalMemory = 0
        $serverType = [string]::Empty
    }
    process {
        Get-WmiObjectCriticalHandler -Class "Win32_ComputerSystem" -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$system)
        Get-WmiObjectHandler -Class "Win32_PhysicalMemory" -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$physicalMemory)
        Get-ProcessorInformation -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$processorInformation)

        if ($null -eq $physicalMemory) {
            Write-Verbose "Using memory from Win32_ComputerSystem class instead. This may cause memory calculation issues."
            $totalMemory = $system.TotalPhysicalMemory
        } else {
            foreach ($memory in $physicalMemory) {
                $totalMemory += $memory.Capacity
            }
        }

        Get-ServerType -ServerType $system.Manufacturer | Invoke-RemotePipelineHandler -Result ([ref]$serverType)

        if ($PSSenderInfo) {
            $jobHandledErrors = $Script:ErrorsExcluded
            $allErrors = $Error
        }
    }
    end {
        Write-Verbose "Completed: $($MyInvocation.MyCommand) and took $($jobStopWatch.Elapsed.TotalSeconds) seconds"
        [PSCustomObject]@{
            Manufacturer      = $system.Manufacturer
            ServerType        = $serverType
            AutoPageFile      = $system.AutomaticManagedPagefile
            Model             = $system.Model
            System            = $system
            Processor         = $processorInformation
            TotalMemory       = $totalMemory
            MemoryInformation = [array]$physicalMemory
            RemoteJob         = $true -eq $PSSenderInfo
            JobHandledErrors  = $jobHandledErrors
            AllErrors         = $allErrors
        }
    }
}
