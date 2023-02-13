# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\Invoke-AnalyzerExchangeInformation.ps1
. $PSScriptRoot\Invoke-AnalyzerHybridInformation.ps1
. $PSScriptRoot\Invoke-AnalyzerOsInformation.ps1
. $PSScriptRoot\Invoke-AnalyzerHardwareInformation.ps1
. $PSScriptRoot\Invoke-AnalyzerIISInformation.ps1
. $PSScriptRoot\Invoke-AnalyzerNicSettings.ps1
. $PSScriptRoot\Invoke-AnalyzerOrganizationInformation.ps1
. $PSScriptRoot\Invoke-AnalyzerFrequentConfigurationIssues.ps1
. $PSScriptRoot\Security\Invoke-AnalyzerSecuritySettings.ps1
. $PSScriptRoot\Security\Invoke-AnalyzerSecurityVulnerability.ps1
function Invoke-AnalyzerEngine {
    [CmdletBinding()]
    param(
        [object]$HealthServerObject
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $analyzedResults = [PSCustomObject]@{
        HealthCheckerExchangeServer = $HealthServerObject
        HtmlServerValues            = @{}
        DisplayResults              = @{}
    }

    #Display Grouping Keys
    $order = 1
    $baseParams = @{
        AnalyzedInformation = $analyzedResults
        DisplayGroupingKey  = (Get-DisplayResultsGroupingKey -Name "BeginningInfo" -DisplayGroupName $false -DisplayOrder 0 -DefaultTabNumber 0)
    }

    if (!$Script:DisplayedScriptVersionAlready) {
        $params = $baseParams + @{
            Name             = "Exchange Health Checker Version"
            Details          = $BuildVersion
            AddHtmlDetailRow = $false
        }
        Add-AnalyzedResultInformation @params
    }

    $VirtualizationWarning = @"
Virtual Machine detected.  Certain settings about the host hardware cannot be detected from the virtual machine.  Verify on the VM Host that:

    - There is no more than a 1:1 Physical Core to Virtual CPU ratio (no oversubscribing)
    - If Hyper-Threading is enabled do NOT count Hyper-Threaded cores as physical cores
    - Do not oversubscribe memory or use dynamic memory allocation

Although Exchange technically supports up to a 2:1 physical core to vCPU ratio, a 1:1 ratio is strongly recommended for performance reasons.  Certain third party Hyper-Visors such as VMWare have their own guidance.

VMWare recommends a 1:1 ratio.  Their guidance can be found at https://aka.ms/HC-VMwareBP2019.
Related specifically to VMWare, if you notice you are experiencing packet loss on your VMXNET3 adapter, you may want to review the following article from VMWare:  https://aka.ms/HC-VMwareLostPackets.

For further details, please review the virtualization recommendations on Microsoft Docs here: https://aka.ms/HC-Virtualization.

"@

    if ($HealthServerObject.HardwareInformation.ServerType -eq "VMWare" -or
        $HealthServerObject.HardwareInformation.ServerType -eq "HyperV") {
        $params = $baseParams + @{
            Details          = $VirtualizationWarning
            DisplayWriteType = "Yellow"
            AddHtmlDetailRow = $false
        }
        Add-AnalyzedResultInformation @params
    }

    # Can't do a Hash Table pass param due to [ref]
    Invoke-AnalyzerExchangeInformation -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerOrganizationInformation -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerHybridInformation -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerOsInformation -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerHardwareInformation -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerNicSettings -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerFrequentConfigurationIssues -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerSecuritySettings -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerSecurityVulnerability -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Invoke-AnalyzerIISInformation -AnalyzeResults ([ref]$analyzedResults) -HealthServerObject $HealthServerObject -Order ($order++)
    Write-Debug("End of Analyzer Engine")
    return $analyzedResults
}
