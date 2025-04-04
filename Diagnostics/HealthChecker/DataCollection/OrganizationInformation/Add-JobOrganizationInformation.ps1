# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-DefaultConnectExchangeShell.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeContainer.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-MonitoringOverride.ps1
. $PSScriptRoot\..\..\..\..\Shared\JobManagement\Add-JobQueue.ps1

function Add-JobOrganizationInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Legacy", "Queue", "StartNow")]
        [string]$RunType
    )
    process {
        <#
            Non Default Script Block Dependencies
                Invoke-DefaultConnectExchangeShell
                Get-ExchangeContainer
                Get-MonitoringOverride
        #>
        . $PSScriptRoot\Invoke-JobOrganizationInformation.ps1

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        if ($RunType -eq "Legacy") {
            throw "Legacy Not Implemented"
        } else {
            $sbInjectionParams = @{
                PrimaryScriptBlock = ${Function:Invoke-JobOrganizationInformation}
                IncludeScriptBlock = @(${Function:Get-MonitoringOverride}, ${Function:Invoke-DefaultConnectExchangeShell}, ${Function:Get-ExchangeContainer})
            }
            $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
            $params = @{
                JobCommand   = "Start-Job"
                JobParameter = @{
                    ScriptBlock = $scriptBlock
                }
                JobId        = "Invoke-JobOrganizationInformation"
            }

            if ($RunType -eq "Queue") {
                Add-JobQueue @params
            } elseif ($RunType -eq "StartNow") {
                throw "StartNow Not Implemented"
            }
        }
    }
}
