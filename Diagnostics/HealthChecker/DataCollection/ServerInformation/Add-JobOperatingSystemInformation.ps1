# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-NETFrameworkVersion.ps1

function Add-JobOperatingSystemInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Legacy", "Queue", "StartNow")]
        [string]$RunType
    )
    process {
        <#
            Non Default Script Block Dependencies
                Get-WmiObjectCriticalHandler
                Get-WmiObjectHandler
                Get-RemoteRegistryValue
                Get-RemoteRegistrySubKey
                Get-LocalizedCounterSamples
                Get-CounterSamples
                Get-LocalizedPerformanceCounterName
                Get-CounterFullNameToCounterObject
                Get-VisualCRedistributableInstalledVersion
                Get-NETFrameworkVersion
                GetNetVersionDictionary
                ValidateNetNameParameter
        #>
        . $PSScriptRoot\Invoke-JobOperatingSystemInformation.ps1

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        if ($RunType -eq "Legacy") {
            throw "Legacy Not Implemented"
        } else {
            $sbInjectionParams = @{
                PrimaryScriptBlock = ${Function:Invoke-JobOperatingSystemInformation}
                IncludeScriptBlock = @(${Function:Get-WmiObjectCriticalHandler}, ${Function:Get-WmiObjectHandler}, ${Function:Get-RemoteRegistryValue},
                    ${Function:Get-RemoteRegistrySubKey}, ${Function:Get-LocalizedCounterSamples}, ${Function:Get-CounterSamples},
                    ${Function:Get-LocalizedPerformanceCounterName}, ${Function:Get-CounterFullNameToCounterObject}, ${Function:Get-VisualCRedistributableInstalledVersion},
                    ${Function:Get-NETFrameworkVersion}, ${Function:GetNetVersionDictionary}, ${Function:ValidateNetNameParameter})
            }
            $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
            $params = @{
                JobParameter = @{
                    ComputerName = $ComputerName
                    ScriptBlock  = $scriptBlock
                }
                JobId        = "Invoke-JobOperatingSystemInformation-$ComputerName"
                TryStartNow  = $RunType -eq "StartNow"
            }
            Add-JobQueue @params
        }
    }
}
