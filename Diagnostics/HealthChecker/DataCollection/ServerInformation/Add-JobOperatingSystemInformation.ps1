# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-NETFrameworkVersion.ps1
. $PSScriptRoot\Invoke-JobOperatingSystemInformation.ps1

function Add-JobOperatingSystemInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )
    process {

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $nonDefaultSbDependencies = @(
            ${Function:GetNetVersionDictionary},
            ${Function:ValidateNetNameParameter},
            ${Function:Get-CounterFullNameToCounterObject},
            ${Function:Get-CounterSamples},
            ${Function:Get-LocalizedCounterSamples},
            ${Function:Get-LocalizedPerformanceCounterName},
            ${Function:Get-NETFrameworkVersion},
            ${Function:Get-RemoteRegistrySubKey},
            ${Function:Get-RemoteRegistryValue},
            ${Function:Get-VisualCRedistributableInstalledVersion}
            ${Function:Get-WmiObjectCriticalHandler},
            ${Function:Get-WmiObjectHandler}
        )

        $sbInjectionParams = @{
            PrimaryScriptBlock = ${Function:Invoke-JobOperatingSystemInformation}
            IncludeScriptBlock = $nonDefaultSbDependencies
        }
        $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
        $params = @{
            JobParameter = @{
                ComputerName = $ComputerName
                ScriptBlock  = $scriptBlock
            }
            JobId        = "Invoke-JobOperatingSystemInformation-$ComputerName"
            TryStartNow  = $true
        }
        Add-JobQueue @params
    }
}
