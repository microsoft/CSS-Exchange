# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-WmiObjectCriticalHandler.ps1
. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\..\..\Shared\JobManagementFunctions\Add-JobQueue.ps1
. $PSScriptRoot\Invoke-JobHardwareInformation.ps1

function Add-JobHardwareInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )
    process {

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $nonDefaultSbDependencies = @(
            ${Function:Get-WmiObjectCriticalHandler},
            ${Function:Get-WmiObjectHandler}
        )

        $params = @{
            PrimaryScriptBlock = ${Function:Invoke-JobHardwareInformation}
            IncludeScriptBlock = $nonDefaultSbDependencies
        }
        $scriptBlock = Get-HCDefaultSBInjection @params
        $params = @{
            JobParameter = @{
                ComputerName = $ComputerName
                ScriptBlock  = $scriptBlock
            }
            JobId        = "Invoke-JobHardwareInformation-$ComputerName"
            TryStartNow  = $true
        }
        Add-JobQueue @params
    }
}
