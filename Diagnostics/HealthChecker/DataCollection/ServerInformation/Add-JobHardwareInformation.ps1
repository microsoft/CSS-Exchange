# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-WmiObjectCriticalHandler.ps1
. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\..\..\Shared\JobManagement\Add-JobQueue.ps1

function Add-JobHardwareInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )
    process {
        <#
            Non Default Script Block Dependencies
                Get-WmiObjectCriticalHandler
                Get-WmiObjectHandler
        #>

        function Invoke-JobHardwareInformation {
            [CmdletBinding()]
            param()
            begin {

                # Build Process to add functions.
                . $PSScriptRoot\Get-ProcessorInformation.ps1
                . $PSScriptRoot\Get-ServerType.ps1

                if ($PSSenderInfo) {
                    $Script:ErrorsExcluded = @()
                }

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
                }
            }
            end {
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
                }
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $params = @{
            PrimaryScriptBlock = ${Function:Invoke-JobHardwareInformation}
            IncludeScriptBlock = @(${Function:Get-WmiObjectCriticalHandler}, ${Function:Get-WmiObjectHandler})
        }
        $scriptBlock = Get-HCDefaultSBInjection @params
        $params = @{
            JobParameter = @{
                ComputerName = $ComputerName
                ScriptBlock  = $scriptBlock
            }
            JobId        = "Invoke-JobHardwareInformation-$ComputerName"
        }
        Add-JobQueue @params
    }
}
