# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeBuildVersionInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1

function Add-JobExchangeInformationLocal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [object]$GetExchangeServer,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Legacy", "Queue", "StartNow")]
        [string]$RunType
    )
    process {
        <#
            Non Default Script Block Dependencies
            Get-ExchangeBuildVersionInformation
            GetExchangeBuildDictionary
            GetValidatePossibleParameters
            ValidateSUParameter
            ValidateCUParameter
            ValidateVersionParameter
            Test-ExchangeBuildGreaterOrEqualThanSecurityPatch
            Get-RemoteRegistryValue
            Get-RemoteRegistrySubKey
        #>
        . $PSScriptRoot\Invoke-JobExchangeInformationLocal.ps1

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        if ($RunType -eq "Legacy") {
            throw "Legacy Not Implemented"
        } else {
            $sbInjectionParams = @{
                PrimaryScriptBlock = ${Function:Invoke-JobExchangeInformationLocal}
                IncludeScriptBlock = @(${Function:Get-ExchangeBuildVersionInformation}, ${Function:GetExchangeBuildDictionary}, ${Function:GetValidatePossibleParameters},
                    ${Function:ValidateSUParameter}, ${Function:ValidateCUParameter}, ${Function:ValidateVersionParameter}, ${Function:Get-RemoteRegistrySubKey},
                    ${Function:Get-RemoteRegistryValue}, ${Function:Test-ExchangeBuildGreaterOrEqualThanSecurityPatch})
            }
            $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
            $params = @{
                JobParameter = @{
                    ComputerName = $ComputerName
                    ScriptBlock  = $scriptBlock
                    ArgumentList = $GetExchangeServer
                }
                JobId        = "Invoke-JobExchangeInformationLocal-$ComputerName"
                TryStartNow  = $RunType -eq "StartNow"
            }
            Add-JobQueue @params
        }
    }
}
