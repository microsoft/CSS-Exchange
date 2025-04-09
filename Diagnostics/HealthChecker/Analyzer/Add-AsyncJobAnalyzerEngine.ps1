# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\JobManagement\Add-AsyncJobQueue.ps1
. $PSScriptRoot\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\Get-NETFrameworkVersion.ps1
. $PSScriptRoot\..\..\..\Shared\CompareExchangeBuildLevel.ps1

function Add-AsyncJobAnalyzerEngine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject
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
        function Invoke-JobAnalyzerEngine {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [object]$HealthServerObject
            )
            begin {
                # Build Process to add functions.
                . $PSScriptRoot\Invoke-AnalyzerEngine.ps1

                if ($PSSenderInfo) {
                    $Script:ErrorsExcluded = @()
                }
                $healthCheckerAnalyzedResult = $null
            }
            process {
                Invoke-AnalyzerEngine -HealthServerObject $HealthServerObject |
                    Invoke-RemotePipelineHandler -Result ([ref]$healthCheckerAnalyzedResult)

                if ($PSSenderInfo) {
                    $jobHandledErrors = $Script:ErrorsExcluded
                }
            }
            end {
                [PSCustomObject]@{
                    HCAnalyzedResults = $healthCheckerAnalyzedResult
                    RemoteJob         = $true -eq $PSSenderInfo
                    JobHandledErrors  = $jobHandledErrors
                }
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
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
                ComputerName = $env:COMPUTERNAME
                ScriptBlock  = $scriptBlock
                ArgumentList = $HealthServerObject
            }
            JobId        = "Invoke-JobAnalyzerEngine-$($HealthServerObject.ServerName)"
            TryStartNow  = $true
        }
        Add-AsyncJobQueue @params
    }
}
