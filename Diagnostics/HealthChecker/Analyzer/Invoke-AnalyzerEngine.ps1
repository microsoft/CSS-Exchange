# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\Invoke-AnalyzerExchangeInformation.ps1
. $PSScriptRoot\Invoke-AnalyzerHybridInformation.ps1
. $PSScriptRoot\Invoke-AnalyzerOsInformation.ps1
. $PSScriptRoot\Invoke-AnalyzerHardwareInformation.ps1
. $PSScriptRoot\Invoke-AnalyzerNicSettings.ps1
. $PSScriptRoot\Invoke-AnalyzerFrequentConfigurationIssues.ps1
. $PSScriptRoot\Invoke-AnalyzerWebAppPools.ps1
. $PSScriptRoot\Security\Invoke-AnalyzerSecuritySettings.ps1
Function Invoke-AnalyzerEngine {
    param(
        [HealthChecker.HealthCheckerExchangeServer]$HealthServerObject
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $analyzedResults = New-Object HealthChecker.AnalyzedInformation
    $analyzedResults.HealthCheckerExchangeServer = $HealthServerObject

    #Display Grouping Keys
    $order = 1
    $keyBeginningInfo = Get-DisplayResultsGroupingKey -Name "BeginningInfo" -DisplayGroupName $false -DisplayOrder 0 -DefaultTabNumber 0

    if (!$Script:DisplayedScriptVersionAlready) {
        $analyzedResults | Add-AnalyzedResultInformation -Name "Exchange Health Checker Version" -Details $BuildVersion `
            -DisplayGroupingKey $keyBeginningInfo `
            -AddHtmlDetailRow $false
    }

    if ($HealthServerObject.HardwareInformation.ServerType -eq [HealthChecker.ServerType]::VMWare -or
        $HealthServerObject.HardwareInformation.ServerType -eq [HealthChecker.ServerType]::HyperV) {
        $analyzedResults | Add-AnalyzedResultInformation -Details $VirtualizationWarning -DisplayWriteType "Yellow" `
            -DisplayGroupingKey $keyBeginningInfo `
            -AddHtmlDetailRow $false
    }

    Invoke-AnalyzerExchangeInformation -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerHybridInformation -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerOsInformation -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerHardwareInformation -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerNicSettings -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerFrequentConfigurationIssues -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerSecuritySettings -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerWebAppPools -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Write-Debug("End of Analyzer Engine")
    return $analyzedResults
}


