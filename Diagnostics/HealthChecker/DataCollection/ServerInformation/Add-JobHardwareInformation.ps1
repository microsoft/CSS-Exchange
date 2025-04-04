# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-WmiObjectCriticalHandler.ps1
. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\..\..\Shared\JobManagement\Add-JobQueue.ps1

function Add-JobHardwareInformation {
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
        #>
        . $PSScriptRoot\Invoke-JobHardwareInformation.ps1

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        if ($RunType -eq "Legacy") {
            throw "Legacy Not Implemented"
        } else {
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

            if ($RunType -eq "Queue") {
                Add-JobQueue @params
            } elseif ($RunType -eq "StartNow") {
                throw "StartNow Not Implemented"
            }
        }
    }
}
