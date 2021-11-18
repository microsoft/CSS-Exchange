# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Invoke-AnalyzerSecurityAMSIConfigState {
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
    $osInformation = $HealthServerObject.OSInformation

    # AMSI integration is only available on Windows Server 2016 or higher and only on
    # Exchange Server 2016 CU21+ or Exchange Server 2019 CU10+.
    # AMSI is also not available on Edge Transport Servers.
    if ((($osInformation.BuildInformation.MajorVersion -ge [HealthChecker.OSServerVersion]::Windows2016) -and
        (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) -and
            ($exchangeCU -ge [HealthChecker.ExchangeCULevel]::CU21)) -or
        (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) -and
            ($exchangeCU -ge [HealthChecker.ExchangeCULevel]::CU10))) -and
        ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge)) {

        $amsiInformation = $HealthServerObject.ExchangeInformation.AMSIConfiguration
        $amsiWriteType = "Yellow"

        if ($amsiInformation.QuerySuccessful -eq $true) {
            if ($amsiInformation.Enabled -eq $true) {
                $amsiWriteType = "Green"
            } elseif ($amsiInformation.Enabled -eq $false) {
                Switch ($amsiInformation.OrgWideSetting) {
                    ($true) { $additionalAMSIDisplayValue = "Setting applies to all servers of the organization" }
                    ($false) {
                        $additionalAMSIDisplayValue = "Setting applies to the following server(s) of the organization:"
                        foreach ($server in $amsiInformation.Server) {
                            $additionalAMSIDisplayValue += "`r`n`t`t{0}" -f $server
                        }
                    }
                }
                $additionalAMSIDisplayValue += "`r`n`t`tThis may pose a security risk to your servers"
                $additionalAMSIDisplayValue += "`r`n`t`tMore Information: https://aka.ms/AMSIExchange"
            } else {
                $additionalAMSIDisplayValue = "Exchange AMSI integration state is unknown"
            }
        } else {
            $additionalAMSIDisplayValue = "Unable to query Exchange AMSI integration state"
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "AMSI Enabled" -Details $amsiInformation.Enabled `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayWriteType $amsiWriteType

        if ($null -ne $additionalAMSIDisplayValue) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details $additionalAMSIDisplayValue `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayWriteType $amsiWriteType `
                -DisplayCustomTabNumber 2
        }
    } else {
        Write-Verbose "AMSI integration is not available because we are on: $($exchangeInformation.BuildInformation.MajorVersion) $exchangeCU"
    }
}
