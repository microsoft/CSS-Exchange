# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1
function Invoke-AnalyzerSecurityMitigationService {
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
    $getExchangeServer = $exchangeInformation.GetExchangeServer
    $mitigationEnabledAtOrg = $HealthServerObject.OrganizationInformation.GetOrganizationConfig.MitigationsEnabled
    $mitigationEnabledAtServer = $getExchangeServer.MitigationsEnabled
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }
    #Description: Check for Exchange Emergency Mitigation Service (EEMS)
    #Introduced in: Exchange 2016 CU22, Exchange 2019 CU11
    if (((Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "Exchange2016" -CU "CU22") -or
        (Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "Exchange2019" -CU "CU11")) -and
        $exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false) {

        if (-not([String]::IsNullOrEmpty($mitigationEnabledAtOrg))) {
            if (($mitigationEnabledAtOrg) -and
                ($mitigationEnabledAtServer)) {
                $eemsWriteType = "Green"
                $eemsOverallState = "Enabled"
            } elseif (($mitigationEnabledAtOrg -eq $false) -and
                ($mitigationEnabledAtServer)) {
                $eemsWriteType = "Yellow"
                $eemsOverallState = "Disabled on org level"
            } elseif (($mitigationEnabledAtServer -eq $false) -and
                ($mitigationEnabledAtOrg)) {
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
            $details = "Unknown"
            $service = $exchangeInformation.DependentServices.Monitor |
                Where-Object { $_.Name -eq "MSExchangeMitigation" }

            if ($null -ne $service) {
                if ($service.Status -eq "Running" -and $service.StartType -eq "Automatic") {
                    $details = "Running"
                    $eemsWinSrvWriteType = "Grey"
                } else {
                    $details = "Investigate"
                }
            }

            $params = $baseParams + @{
                Name                   = "Windows service"
                Details                = $details
                DisplayWriteType       = $eemsWinSrvWriteType
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params

            if ($exchangeInformation.ExchangeEmergencyMitigationServiceResult.StatusCode -eq 200) {
                $eemsPatternServiceWriteType = "Grey"
                $eemsPatternServiceStatus = ("200 - Reachable")
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

            if (-not([String]::IsNullOrEmpty($getExchangeServer.MitigationsApplied))) {
                foreach ($mitigationApplied in $getExchangeServer.MitigationsApplied) {
                    $params = $baseParams + @{
                        Name                   = "Mitigation applied"
                        Details                = $mitigationApplied
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params
                }

                $params = $baseParams + @{
                    Details                = "Run: 'Get-Mitigations.ps1' from: '$ExScripts' to learn more."
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }

            if (-not([String]::IsNullOrEmpty($getExchangeServer.MitigationsBlocked))) {
                foreach ($mitigationBlocked in $getExchangeServer.MitigationsBlocked) {
                    $params = $baseParams + @{
                        Name                   = "Mitigation blocked"
                        Details                = $mitigationBlocked
                        DisplayWriteType       = "Yellow"
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params
                }
            }

            if (-not([String]::IsNullOrEmpty($getExchangeServer.DataCollectionEnabled))) {
                $params = $baseParams + @{
                    Name                   = "Telemetry enabled"
                    Details                = $getExchangeServer.DataCollectionEnabled
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
