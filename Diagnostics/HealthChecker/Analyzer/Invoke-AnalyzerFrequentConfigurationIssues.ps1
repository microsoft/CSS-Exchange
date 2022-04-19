# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
Function Invoke-AnalyzerFrequentConfigurationIssues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [int]$Order
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $keyFrequentConfigIssues = Get-DisplayResultsGroupingKey -Name "Frequent Configuration Issues"  -DisplayOrder $Order
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $osInformation = $HealthServerObject.OSInformation

    $tcpKeepAlive = $osInformation.NetworkInformation.TCPKeepAlive

    if ($tcpKeepAlive -eq 0) {
        $displayValue = "Not Set `r`n`t`tError: Without this value the KeepAliveTime defaults to two hours, which can cause connectivity and performance issues between network devices such as firewalls and load balancers depending on their configuration. `r`n`t`tMore details: https://aka.ms/HC-TSPerformanceChecklist"
        $displayWriteType = "Red"
    } elseif ($tcpKeepAlive -lt 900000 -or
        $tcpKeepAlive -gt 1800000) {
        $displayValue = "{0} `r`n`t`tWarning: Not configured optimally, recommended value between 15 to 30 minutes (900000 and 1800000 decimal). `r`n`t`tMore details: https://aka.ms/HC-TSPerformanceChecklist" -f $tcpKeepAlive
        $displayWriteType = "Yellow"
    } else {
        $displayValue = $tcpKeepAlive
        $displayWriteType = "Green"
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "TCP/IP Settings" -Details $displayValue `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $tcpKeepAlive `
        -HtmlName "TCPKeepAlive"

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "RPC Min Connection Timeout" -Details ("{0} `r`n`t`tMore Information: https://aka.ms/HC-RPCSetting" -f $osInformation.NetworkInformation.RpcMinConnectionTimeout) `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayTestingValue $osInformation.NetworkInformation.RpcMinConnectionTimeout `
        -HtmlName "RPC Minimum Connection Timeout"

    if ($exchangeInformation.RegistryValues.DisableGranularReplication -ne 0) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "DisableGranularReplication" -Details "$($exchangeInformation.RegistryValues.DisableGranularReplication) - Error this can cause work load management issues." `
            -DisplayGroupingKey $keyFrequentConfigIssues `
            -DisplayWriteType "Red" `
            -DisplayTestingValue $true
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "FIPS Algorithm Policy Enabled" -Details ($exchangeInformation.RegistryValues.FipsAlgorithmPolicyEnabled) `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -HtmlName "FipsAlgorithmPolicy-Enabled"

    $displayValue = $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage
    $displayWriteType = "Green"

    if ($exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage -ne 0) {
        $displayWriteType = "Red"
        $displayValue = "{0} `r`n`t`tError: This can cause an impact to the server's search performance. This should only be used a temporary fix if no other options are available vs a long term solution." -f $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "CTS Processor Affinity Percentage" -Details $displayValue `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue ($exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage) `
        -HtmlName "CtsProcessorAffinityPercentage"

    $displayValue = $exchangeInformation.RegistryValues.DisableAsyncNotification
    $displayWriteType = "Grey"

    if ($displayValue -ne 0) {
        $displayWriteType = "Yellow"
        $displayValue = "$($exchangeInformation.RegistryValues.DisableAsyncNotification) Warning: This value should be set back to 0 after you no longer need it for the workaround described in http://support.microsoft.com/kb/5013118"
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Disable Async Notification" -Details $displayValue `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $true

    $displayValue = $osInformation.CredentialGuardEnabled
    $displayWriteType = "Grey"

    if ($osInformation.CredentialGuardEnabled) {
        $displayValue = "{0} `r`n`t`tError: Credential Guard is not supported on an Exchange Server. This can cause a performance hit on the server." -f $osInformation.CredentialGuardEnabled
        $displayWriteType = "Red"
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Credential Guard Enabled" -Details $displayValue `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayTestingValue $osInformation.CredentialGuardEnabled `
        -DisplayWriteType $displayWriteType

    if ($null -ne $exchangeInformation.ApplicationConfigFileStatus -and
        $exchangeInformation.ApplicationConfigFileStatus.Count -ge 1) {

        foreach ($configKey in $exchangeInformation.ApplicationConfigFileStatus.Keys) {
            $configStatus = $exchangeInformation.ApplicationConfigFileStatus[$configKey]

            $writeType = "Green"
            $writeName = "{0} Present" -f $configKey
            $writeValue = $configStatus.Present

            if (!$configStatus.Present) {
                $writeType = "Red"
                $writeValue = "{0} --- Error" -f $writeValue
            }

            $AnalyzeResults | Add-AnalyzedResultInformation -Name $writeName -Details $writeValue `
                -DisplayGroupingKey $keyFrequentConfigIssues `
                -DisplayWriteType $writeType
        }
    }

    $displayWriteType = "Grey"
    $displayValue = "Not Set"
    $additionalDisplayValue = [string]::Empty

    if ($null -ne $exchangeInformation.WildCardAcceptedDomain) {

        if ($exchangeInformation.WildCardAcceptedDomain -eq "Unknown") {
            $displayValue = "Unknown - Unable to run Get-AcceptedDomain"
            $displayWriteType = "Yellow"
        } else {
            $displayWriteType = "Red"
            $domain = $exchangeInformation.WildCardAcceptedDomain
            $displayValue = "Error --- Accepted Domain `"$($domain.Id)`" is set to a Wild Card (*) Domain Name with a domain type of $($domain.DomainType.ToString()). This is not recommended as this is an open relay for the entire environment.`r`n`t`tMore Information: https://aka.ms/HC-OpenRelayDomain"

            if ($domain.DomainType.ToString() -eq "InternalRelay" -and
                (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016 -and
                    $exchangeInformation.BuildInformation.CU -ge [HealthChecker.ExchangeCULevel]::CU22) -or
                ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019 -and
                $exchangeInformation.BuildInformation.CU -ge [HealthChecker.ExchangeCULevel]::CU11))) {

                $additionalDisplayValue = "`r`n`t`tERROR: You have an open relay set as Internal Replay Type and on a CU that is known to cause issues with transport services crashing. Follow the above article for more information."
            } elseif ($domain.DomainType.ToString() -eq "InternalRelay") {
                $additionalDisplayValue = "`r`n`t`tWARNING: You have an open relay set as Internal Relay Type. You are not on a CU yet that is having issue, recommended to change this prior to upgrading. Follow the above article for more information."
            }
        }
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Open Relay Wild Card Domain" -Details $displayValue `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayWriteType $displayWriteType

    if ($additionalDisplayValue -ne [string]::Empty) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Details $additionalDisplayValue `
            -DisplayGroupingKey $keyFrequentConfigIssues `
            -DisplayWriteType "Red"
    }
}
