# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-DefaultConnectExchangeShell.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeBuildVersionInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeContainer.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-MonitoringOverride.ps1

function Add-JobExchangeInformationCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )
    process {
        <#
            Non Default Script Block Dependencies
                Invoke-DefaultConnectExchangeShell
                Get-ExchangeContainer
                Get-MonitoringOverride
                Get-RemoteRegistrySubKey
        #>
        . $PSScriptRoot\Invoke-JobExchangeInformationCmdlet.ps1

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $sbInjectionParams = @{
            PrimaryScriptBlock = ${Function:Invoke-JobExchangeInformationCmdlet}
            IncludeScriptBlock = @(${Function:Invoke-DefaultConnectExchangeShell}, ${Function:Get-ExchangeContainer},
                ${Function:Get-MonitoringOverride})
        }
        $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
        $params = @{
            JobCommand   = "Start-Job"
            JobParameter = @{
                ScriptBlock  = $scriptBlock
                ArgumentList = $ComputerName
            }
            JobId        = "Invoke-JobExchangeInformationCmdlet-$ComputerName"
        }
        Add-JobQueue @params
    }
}
