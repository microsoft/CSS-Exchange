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
        [object]$HealthServerObject
    )
    begin {
        . $PSScriptRoot\Invoke-AnalyzerEngine.ps1
    }
    process {
        $analyzedResults = $null
        Invoke-AnalyzerEngine -HealthServerObject $HealthServerObject | Invoke-RemotePipelineHandler -Result ([ref]$analyzedResults)
        $analyzedResults
    }
}
