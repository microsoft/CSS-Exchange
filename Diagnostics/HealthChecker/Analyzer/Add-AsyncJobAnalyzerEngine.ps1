# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
            Get-VisualCRedistributableInstalledVersion
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
                ${Function:Test-ExchangeBuildGreaterOrEqualThanSecurityPatch}, ${Function:Get-VisualCRedistributableInstalledVersion}, ${Function:Get-NETFrameworkVersion},
                ${Function:GetNetVersionDictionary}, ${Function:ValidateNetNameParameter} )
        }
        $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
        $params = @{
            JobParameter = @{
                ScriptBlock  = $scriptBlock
                ArgumentList = $HealthServerObject
            }
            JobId        = "Invoke-JobAnalyzerEngine-$($HealthServerObject.ServerName)"
        }
        Add-AsyncJobQueue @params
    }
}
