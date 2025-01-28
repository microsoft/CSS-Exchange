# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\JobManagementFunctions\Add-JobQueue.ps1
. $PSScriptRoot\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\Get-NETFrameworkVersion.ps1
. $PSScriptRoot\..\..\..\Shared\CompareExchangeBuildLevel.ps1
. $PSScriptRoot\Invoke-JobAnalyzerEngine.ps1

function Add-JobAnalyzerEngine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [string]$ExecutingServer
    )
    process {

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $nonDefaultSbDependencies = @(
            ${Function:GetExchangeBuildDictionary},
            ${Function:GetNetVersionDictionary},
            ${Function:GetValidatePossibleParameters},
            ${Function:ValidateCUParameter},
            ${Function:ValidateNetNameParameter},
            ${Function:ValidateSUParameter},
            ${Function:ValidateVersionParameter},
            ${Function:Get-ExchangeBuildVersionInformation},
            ${Function:Get-NETFrameworkVersion},
            ${Function:Get-VisualCRedistributableInfo},
            ${Function:Get-VisualCRedistributableLatest},
            ${Function:Test-ExchangeBuildEqualBuild},
            ${Function:Test-ExchangeBuildGreaterOrEqualThanBuild},
            ${Function:Test-ExchangeBuildGreaterOrEqualThanSecurityPatch},
            ${Function:Test-ExchangeBuildLessThanBuild},
            ${Function:Test-VisualCRedistributableInstalled}
            ${Function:Test-VisualCRedistributableUpToDate}
        )

        $sbInjectionParams = @{
            PrimaryScriptBlock = ${Function:Invoke-JobAnalyzerEngine}
            IncludeScriptBlock = $nonDefaultSbDependencies
        }
        $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
        $params = @{
            JobCommand   = "Invoke-Command"
            JobParameter = @{
                ComputerName = $ExecutingServer
                ScriptBlock  = $scriptBlock
                ArgumentList = $HealthServerObject
            }
            JobId        = "Invoke-JobAnalyzerEngine-$($HealthServerObject.ServerName)"
            TryStartNow  = $true
        }
        Add-JobQueue @params
    }
}
