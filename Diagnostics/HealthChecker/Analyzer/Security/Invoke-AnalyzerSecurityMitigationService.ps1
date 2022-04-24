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
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }
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
                $eemsOverallState = "Enabled"
            } elseif (($mitigationService.MitigationServiceOrgState -eq $false) -and
                ($mitigationService.MitigationServiceSrvState)) {
                $eemsWriteType = "Yellow"
                $eemsOverallState = "Disabled on org level"
            } elseif (($mitigationService.MitigationServiceSrvState -eq $false) -and
                ($mitigationService.MitigationServiceOrgState)) {
                $eemsWriteType = "Yellow"
                $eemsOverallState = "Disabled on server level"
            } else {
                $eemsWriteType = "Yellow"
                $eemsOverallState = "Disabled"
            }

            $params = $baseParams + @{
                Name             = "Exchange Emergency Mitigation Service"
                Details          = $eemsOverallState
                DisplayWriteType = $eemsWriteType
            }
            Add-AnalyzedResultInformation @params

            if ($eemsWriteType -ne "Green") {
                $params = $baseParams + @{
                    Details                = "More Information: https://aka.ms/HC-EEMS"
                    DisplayWriteType       = $eemsWriteType
                    DisplayCustomTabNumber = 2
                    AddHtmlDetailRow       = $false
                }
                Add-AnalyzedResultInformation @params
            }

            $eemsWinSrvWriteType = "Yellow"
            if (-not([String]::IsNullOrEmpty($mitigationService.MitigationWinServiceState))) {
                if ($mitigationService.MitigationWinServiceState -eq "Running") {
                    $eemsWinSrvWriteType = "Grey"
                }
                $details = $mitigationService.MitigationWinServiceState
            } else {
                $details = "Unknown"
            }

            $params = $baseParams + @{
                Name                   = "Windows service"
                Details                = $details
                DisplayWriteType       = $eemsWinSrvWriteType
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params

            if ($mitigationService.MitigationServiceEndpoint -eq 200) {
                $eemsPatternServiceWriteType = "Grey"
                $eemsPatternServiceStatus = ("{0} - Reachable" -f $mitigationService.MitigationServiceEndpoint)
            } else {
                $eemsPatternServiceWriteType = "Yellow"
                $eemsPatternServiceStatus = "Unreachable`r`n`t`tMore information: https://aka.ms/HelpConnectivityEEMS"
            }
            $params = $baseParams + @{
                Name                   = "Pattern service"
                Details                = $eemsPatternServiceStatus
                DisplayWriteType       = $eemsPatternServiceWriteType
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params

            if (-not([String]::IsNullOrEmpty($mitigationService.MitigationsApplied))) {
                foreach ($mitigationApplied in $mitigationService.MitigationsApplied) {
                    $params = $baseParams + @{
                        Name                   = "Mitigation applied"
                        Details                = $mitigationApplied
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params
                }

                $params = $baseParams + @{
                    Details                = "Run: 'Get-Mitigations.ps1' from: '$exscripts' to learn more."
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }

            if (-not([String]::IsNullOrEmpty($mitigationService.MitigationsBlocked))) {
                foreach ($mitigationBlocked in $mitigationService.MitigationsBlocked) {
                    $params = $baseParams + @{
                        Name                   = "Mitigation blocked"
                        Details                = $mitigationBlocked
                        DisplayWriteType       = "Yellow"
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params
                }
            }

            if (-not([String]::IsNullOrEmpty($mitigationService.DataCollectionEnabled))) {
                $params = $baseParams + @{
                    Name                   = "Telemetry enabled"
                    Details                = $mitigationService.DataCollectionEnabled
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }
        } else {
            Write-Verbose "Unable to validate Exchange Emergency Mitigation Service state"
            $params = $baseParams + @{
                Name             = "Exchange Emergency Mitigation Service"
                Details          = "Failed to query config"
                DisplayWriteType = "Red"
            }
            Add-AnalyzedResultInformation @params
        }
    } else {
        Write-Verbose "Exchange Emergency Mitigation Service feature not available because we are on: $($exchangeInformation.BuildInformation.MajorVersion) $exchangeCU or on Edge Transport Server"
    }
}
