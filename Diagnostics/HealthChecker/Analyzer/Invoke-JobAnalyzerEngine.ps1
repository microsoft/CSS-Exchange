# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\CompareExchangeBuildLevel.ps1
. $PSScriptRoot\..\..\..\Shared\CompareExchangeBuildLevel.ps1
. $PSScriptRoot\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\Get-NETFrameworkVersion.ps1

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
