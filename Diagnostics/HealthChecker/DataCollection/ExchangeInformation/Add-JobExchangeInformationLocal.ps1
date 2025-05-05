# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-OrganizationContainer.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeBuildVersionInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1
. $PSScriptRoot\Invoke-JobExchangeInformationLocal.ps1

function Add-JobExchangeInformationLocal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [object]$GetExchangeServer
    )
    process {

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $nonDefaultSbDependencies = @(
            ${Function:GetExchangeBuildDictionary},
            ${Function:GetValidatePossibleParameters},
            ${Function:ValidateCUParameter},
            ${Function:ValidateSUParameter},
            ${Function:ValidateVersionParameter},
            ${Function:Get-ExchangeBuildVersionInformation},
            ${Function:Get-ExchangeContainer},
            ${Function:Get-OrganizationContainer},
            ${Function:Get-RemoteRegistrySubKey},
            ${Function:Get-RemoteRegistryValue},
            ${Function:Test-ExchangeBuildGreaterOrEqualThanSecurityPatch}
        )

        $sbInjectionParams = @{
            PrimaryScriptBlock = ${Function:Invoke-JobExchangeInformationLocal}
            IncludeScriptBlock = $nonDefaultSbDependencies
        }
        $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
        $params = @{
            JobParameter = @{
                ComputerName = $ComputerName
                ScriptBlock  = $scriptBlock
                ArgumentList = $GetExchangeServer
            }
            JobId        = "Invoke-JobExchangeInformationLocal-$ComputerName"
            TryStartNow  = $true
        }
        Add-JobQueue @params
    }
}
