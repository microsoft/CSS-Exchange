# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-DefaultConnectExchangeShell.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeContainer.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-MonitoringOverride.ps1
. $PSScriptRoot\..\..\..\..\Shared\JobManagementFunctions\Add-JobQueue.ps1
. $PSScriptRoot\Invoke-JobOrganizationInformation.ps1

<#
.DESCRIPTION
    This function will start a job to be executed on the server to collect information about the organization.
#>
function Add-JobOrganizationInformation {
    [CmdletBinding()]
    param()
    process {

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $nonDefaultSbDependencies = @(
            ${Function:Get-ExchangeContainer},
            ${Function:Get-MonitoringOverride},
            ${Function:Invoke-DefaultConnectExchangeShell}
        )

        $sbInjectionParams = @{
            PrimaryScriptBlock = ${Function:Invoke-JobOrganizationInformation}
            IncludeScriptBlock = $nonDefaultSbDependencies
        }
        $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
        $params = @{
            JobCommand   = "Start-Job"
            JobParameter = @{
                ScriptBlock = $scriptBlock
            }
            JobId        = "Invoke-JobOrganizationInformation"
            TryStartNow  = $true
        }
        Add-JobQueue @params
    }
}
