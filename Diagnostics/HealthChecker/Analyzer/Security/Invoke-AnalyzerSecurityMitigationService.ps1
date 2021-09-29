# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
Function Invoke-AnalyzerSecurityMitigationService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $exchangeCU = $exchangeInformation.BuildInformation.CU
    $mitigationService = $exchangeInformation.ExchangeEmergencyMitigationService
    #Description: Check for Exchange Emergency Mitigation Service (EEMS)
    #Introduced in: Exchange 2016 CU22, Exchange 2019 CU11
    if (((($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) -and
                ($exchangeCU -ge [HealthChecker.ExchangeCULevel]::CU22)) -or
            (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) -and
                ($exchangeCU -ge [HealthChecker.ExchangeCULevel]::CU11))) -and
        $exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) {

        if (-not([String]::IsNullOrEmpty($mitigationService.MitigationServiceOrgState))) {
            if (($mitigationService.MitigationServiceOrgState) -and
                ($mitigationService.MitigationServiceSrvState)) {
                $eemsWriteType = "Green"
                $eemsOveralState = "Enabled"
            } elseif (($mitigationService.MitigationServiceOrgState -eq $false) -and
                ($mitigationService.MitigationServiceSrvState)) {
                $eemsWriteType = "Yellow"
                $eemsOveralState = "Disabled on org level"
            } elseif (($mitigationService.MitigationServiceSrvState -eq $false) -and
                ($mitigationService.MitigationServiceOrgState)) {
                $eemsWriteType = "Yellow"
                $eemsOveralState = "Disabled on server level"
            } else {
                $eemsWriteType = "Yellow"
                $eemsOveralState = "Disabled"
            }

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Exchange Emergency Mitigation Service" -Details $eemsOveralState `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayWriteType $eemsWriteType

            $eemsWinSrvWriteType = "Yellow"
            if (-not([String]::IsNullOrEmpty($mitigationService.MitigationWinServiceState))) {
                if ($mitigationService.MitigationWinServiceState -eq "Running") {
                    $eemsWinSrvWriteType = "Grey"
                }
                $details = $mitigationService.MitigationWinServiceState
            } else {
                $details = "Unknown"
            }

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Windows service" -Details $details `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType $eemsWinSrvWriteType

            if ($mitigationService.MitigationServiceEndpoint -eq 200) {
                $eemsPatternServiceWriteType = "Grey"
                $eemsPatternServiceStatus = ("{0} - Reachable" -f $mitigationService.MitigationServiceEndpoint)
            } else {
                $eemsPatternServiceWriteType = "Yellow"
                $eemsPatternServiceStatus = "Unreachable`r`n`t`tMore information: https://aka.ms/HelpConnectivityEEMS"
            }
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Pattern service" -Details $eemsPatternServiceStatus `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType $eemsPatternServiceWriteType

            if (-not([String]::IsNullOrEmpty($mitigationService.MitigationsApplied))) {
                foreach ($mitigationApplied in $mitigationService.MitigationsApplied) {
                    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Mitigation applied" -Details $mitigationApplied `
                        -DisplayGroupingKey $DisplayGroupingKey `
                        -DisplayCustomTabNumber 2
                }

                $AnalyzeResults | Add-AnalyzedResultInformation -Details ("Run: 'Get-Mitigations.ps1' from: '{0}' to learn more." -f $exscripts) `
                    -DisplayGroupingKey $DisplayGroupingKey `
                    -DisplayCustomTabNumber 2
            }

            if (-not([String]::IsNullOrEmpty($mitigationService.MitigationsBlocked))) {
                foreach ($mitigationBlocked in $mitigationService.MitigationsBlocked) {
                    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Mitigation blocked" -Details $mitigationBlocked `
                        -DisplayGroupingKey $DisplayGroupingKey `
                        -DisplayCustomTabNumber 2 `
                        -DisplayWriteType "Yellow"
                }
            }

            if (-not([String]::IsNullOrEmpty($mitigationService.DataCollectionEnabled))) {
                $AnalyzeResults | Add-AnalyzedResultInformation -Name "Telemetry enabled" -Details $mitigationService.DataCollectionEnabled `
                    -DisplayGroupingKey $DisplayGroupingKey `
                    -DisplayCustomTabNumber 2
            }
        } else {
            Write-Verbose "Unable to validate Exchange Emergency Mitigation Service state"
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Exchange Emergency Mitigation Service" -Details "Failed to query config" `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayWriteType "Red"
        }
    } else {
        Write-Verbose "Exchange Emergency Mitigation Service feature not available because we are on: $($exchangeInformation.BuildInformation.MajorVersion) $exchangeCU or on Edge Transport Server"
    }
}
