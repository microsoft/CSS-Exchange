# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\JobManagement\Add-JobQueue.ps1
. $PSScriptRoot\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\Get-NETFrameworkVersion.ps1
. $PSScriptRoot\..\..\..\Shared\CompareExchangeBuildLevel.ps1

function Add-JobAnalyzerEngine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Legacy", "StartNow")]
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
            Test-ExchangeBuildGreaterOrEqualThanBuild
            Test-ExchangeBuildLessThanBuild
            Get-VisualCRedistributableLatest
            Get-NETFrameworkVersion
            GetNetVersionDictionary
            ValidateNetNameParameter
        #>
        . $PSScriptRoot\Invoke-JobAnalyzerEngine.ps1

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        if ($RunType -eq "Legacy") {
            throw "Legacy Not Implemented"
        } elseif ($RunType -eq "StartNow") {
            $sbInjectionParams = @{
                PrimaryScriptBlock = ${Function:Invoke-JobAnalyzerEngine}
                IncludeScriptBlock = @(${Function:Get-ExchangeBuildVersionInformation}, ${Function:GetExchangeBuildDictionary}, ${Function:GetExchangeBuildDictionary},
                    ${Function:GetValidatePossibleParameters}, ${Function:ValidateSUParameter}, ${Function:ValidateCUParameter}, ${Function:ValidateVersionParameter},
                    ${Function:Test-ExchangeBuildGreaterOrEqualThanSecurityPatch}, ${Function:Get-VisualCRedistributableLatest}, ${Function:Get-NETFrameworkVersion},
                    ${Function:GetNetVersionDictionary}, ${Function:ValidateNetNameParameter}, ${Function:Test-ExchangeBuildGreaterOrEqualThanBuild}, ${Function:Test-ExchangeBuildLessThanBuild},
                    ${Function:Test-ExchangeBuildEqualBuild}, ${Function:Test-VisualCRedistributableUpToDate}, ${Function:Get-VisualCRedistributableInfo}, ${Function:Test-VisualCRedistributableInstalled})
            }
            $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
            $params = @{
                JobCommand   = "Invoke-Command"
                JobParameter = @{
                    ComputerName = ($HealthServerObject.ServerName) # TODO: Improve the logic here.
                    ScriptBlock  = $scriptBlock
                    ArgumentList = $HealthServerObject
                }
                JobId        = "Invoke-JobAnalyzerEngine-$($HealthServerObject.ServerName)"
                TryStartNow  = $true
            }
            Add-JobQueue @params
        }
    }
}
