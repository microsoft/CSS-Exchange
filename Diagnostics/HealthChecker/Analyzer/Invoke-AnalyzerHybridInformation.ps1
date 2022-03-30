# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
Function Invoke-AnalyzerHybridInformation {
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
    $keyHybridInformation = Get-DisplayResultsGroupingKey -Name "Hybrid Information"  -DisplayOrder $Order
    $exchangeInformation = $HealthServerObject.ExchangeInformation

    if ($exchangeInformation.BuildInformation.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2013 -and
        $null -ne $exchangeInformation.GetHybridConfiguration) {

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Organization Hybrid enabled" -Details "True" `
            -DisplayGroupingKey $keyHybridInformation

        if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.OnPremisesSmartHost))) {
            $onPremSmartHostDomain = ($exchangeInformation.GetHybridConfiguration.OnPremisesSmartHost).ToString()
            $onPremSmartHostWriteType = "Grey"
        } else {
            $onPremSmartHostDomain = "No on-premises smart host domain configured for hybrid use"
            $onPremSmartHostWriteType = "Yellow"
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "On-Premises Smart Host Domain" -Details $onPremSmartHostDomain `
            -DisplayGroupingKey $keyHybridInformation `
            -DisplayWriteType $onPremSmartHostWriteType

        if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.Domains))) {
            $domainsConfiguredForHybrid = $exchangeInformation.GetHybridConfiguration.Domains
            $domainsConfiguredForHybridWriteType = "Grey"
        } else {
            $domainsConfiguredForHybridWriteType = "Yellow"
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Domain(s) configured for Hybrid use" `
            -DisplayGroupingKey $keyHybridInformation `
            -DisplayWriteType $domainsConfiguredForHybridWriteType

        if ($domainsConfiguredForHybrid.Count -ge 1) {
            foreach ($domain in $domainsConfiguredForHybrid) {
                $AnalyzeResults | Add-AnalyzedResultInformation -Details $domain `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayWriteType $domainsConfiguredForHybridWriteType `
                    -DisplayCustomTabNumber 2
            }
        } else {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details "No domain configured for Hybrid use" `
                -DisplayGroupingKey $keyHybridInformation `
                -DisplayWriteType $domainsConfiguredForHybridWriteType `
                -DisplayCustomTabNumber 2
        }

        if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.EdgeTransportServers))) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Edge Transport Server(s)" `
                -DisplayGroupingKey $keyHybridInformation

            foreach ($edgeServer in $exchangeInformation.GetHybridConfiguration.EdgeTransportServers) {
                $AnalyzeResults | Add-AnalyzedResultInformation -Details $edgeServer `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayCustomTabNumber 2
            }

            if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.ReceivingTransportServers)) -or
            (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.SendingTransportServers)))) {
                $AnalyzeResults | Add-AnalyzedResultInformation -Details "When configuring the EdgeTransportServers parameter, you must configure the ReceivingTransportServers and SendingTransportServers parameter values to null" `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayWriteType "Yellow" `
                    -DisplayCustomTabNumber 2
            }
        } else {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Receiving Transport Server(s)" `
                -DisplayGroupingKey $keyHybridInformation

            if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.ReceivingTransportServers))) {
                foreach ($receivingTransportSrv in $exchangeInformation.GetHybridConfiguration.ReceivingTransportServers) {
                    $AnalyzeResults | Add-AnalyzedResultInformation -Details $receivingTransportSrv `
                        -DisplayGroupingKey $keyHybridInformation `
                        -DisplayCustomTabNumber 2
                }
            } else {
                $AnalyzeResults | Add-AnalyzedResultInformation -Details "No Receiving Transport Server configured for Hybrid use" `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayCustomTabNumber 2 `
                    -DisplayWriteType "Yellow"
            }

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Sending Transport Server(s)" `
                -DisplayGroupingKey $keyHybridInformation

            if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.SendingTransportServers))) {
                foreach ($sendingTransportSrv in $exchangeInformation.GetHybridConfiguration.SendingTransportServers) {
                    $AnalyzeResults | Add-AnalyzedResultInformation -Details $sendingTransportSrv `
                        -DisplayGroupingKey $keyHybridInformation `
                        -DisplayCustomTabNumber 2
                }
            } else {
                $AnalyzeResults | Add-AnalyzedResultInformation -Details "No Sending Transport Server configured for Hybrid use" `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayCustomTabNumber 2 `
                    -DisplayWriteType "Yellow"
            }
        }

        if ($exchangeInformation.GetHybridConfiguration.ServiceInstance -eq 1) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Service Instance" -Details "Office 365 operated by 21Vianet" `
                -DisplayGroupingKey $keyHybridInformation
        } elseif ($exchangeInformation.GetHybridConfiguration.ServiceInstance -ne 0) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Service Instance" -Details ($exchangeInformation.GetHybridConfiguration.ServiceInstance) `
                -DisplayGroupingKey $keyHybridInformation `
                -DisplayWriteType "Red"

            $AnalyzeResults | Add-AnalyzedResultInformation -Details "You are using an invalid value. Please set this value to 0 (null) or re-run HCW" `
                -DisplayGroupingKey $keyHybridInformation `
                -DisplayWriteType "Red"
        }

        if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.TlsCertificateName))) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "TLS Certificate Name" -Details ($exchangeInformation.GetHybridConfiguration.TlsCertificateName).ToString() `
                -DisplayGroupingKey $keyHybridInformation
        } else {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "TLS Certificate Name" -Details "No valid certificate found" `
                -DisplayGroupingKey $keyHybridInformation `
                -DisplayWriteType "Red"
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Feature(s) enabled for Hybrid use" `
            -DisplayGroupingKey $keyHybridInformation

        if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.Features))) {
            foreach ($feature in $exchangeInformation.GetHybridConfiguration.Features) {
                $AnalyzeResults | Add-AnalyzedResultInformation -Details $feature `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayCustomTabNumber 2
            }
        } else {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details "No feature(s) enabled for Hybrid use" `
                -DisplayGroupingKey $keyHybridInformation `
                -DisplayCustomTabNumber 2
        }

        if ($null -ne $exchangeInformation.ExchangeConnectors) {
            foreach ($connector in $exchangeInformation.ExchangeConnectors) {
                $cloudConnectorWriteType = "Yellow"
                if (($connector.TransportRole -ne "HubTransport") -and
                    ($connector.CloudEnabled -eq $true)) {

                    $AnalyzeResults | Add-AnalyzedResultInformation -Details "`r" `
                        -DisplayGroupingKey $keyHybridInformation `
                        -AddHtmlDetailRow $false

                    if (($connector.CertificateMatchDetected) -and
                        ($connector.GoodTlsCertificateSyntax)) {
                        $cloudConnectorWriteType = "Green"
                    }

                    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Connector Name" -Details $connector.Name `
                        -DisplayGroupingKey $keyHybridInformation

                    $cloudConnectorEnabledWriteType = "Gray"
                    if ($connector.Enabled -eq $false) {
                        $cloudConnectorEnabledWriteType = "Yellow"
                    }

                    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Connector Enabled" -Details $connector.Enabled `
                        -DisplayGroupingKey $keyHybridInformation `
                        -DisplayWriteType $cloudConnectorEnabledWriteType

                    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Cloud Mail Enabled" -Details $connector.CloudEnabled `
                        -DisplayGroupingKey $keyHybridInformation

                    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Connector Type" -Details $connector.ConnectorType `
                        -DisplayGroupingKey $keyHybridInformation

                    if (($connector.ConnectorType -eq "Send") -and
                        ($null -ne $connector.TlsAuthLevel)) {
                        $AnalyzeResults | Add-AnalyzedResultInformation -Name "TlsAuthLevel" -Details $connector.TlsAuthLevel `
                            -DisplayGroupingKey $keyHybridInformation
                    }

                    $cloudConnectorTlsCertificateName = "Not set"
                    if ($null -ne $connector.TlsCertificateName) {
                        $cloudConnectorTlsCertificateName = $connector.TlsCertificateName
                    }

                    $AnalyzeResults | Add-AnalyzedResultInformation -Name "TlsCertificateName" -Details $cloudConnectorTlsCertificateName `
                        -DisplayGroupingKey $keyHybridInformation `
                        -DisplayWriteType $cloudConnectorWriteType

                    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Certificate Found On Server" -Details $connector.CertificateMatchDetected `
                        -DisplayGroupingKey $keyHybridInformation `
                        -DisplayWriteType $cloudConnectorWriteType

                    if ($connector.TlsCertificateNameStatus -eq "TlsCertificateNameEmpty") {
                        $AnalyzeResults | Add-AnalyzedResultInformation -Details "There is no Tls Certificate configured for this cloud mail enabled connector. This will cause mail flow issues in hybrid scenarios." `
                            -DisplayGroupingKey $keyHybridInformation `
                            -DisplayWriteType $cloudConnectorWriteType `
                            -DisplayCustomTabNumber 2
                    } elseif ($connector.CertificateMatchDetected -eq $false) {
                        $AnalyzeResults | Add-AnalyzedResultInformation -Details "The configured Tls Certificate was not found on the server. This may cause mail flow issues." `
                            -DisplayGroupingKey $keyHybridInformation `
                            -DisplayWriteType $cloudConnectorWriteType `
                            -DisplayCustomTabNumber 2
                    } else {
                        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Certificate Thumbprint(s)" `
                            -DisplayGroupingKey $keyHybridInformation

                        foreach ($thumbprint in $($connector.CertificateInformation).keys) {
                            $AnalyzeResults | Add-AnalyzedResultInformation -Details $thumbprint `
                                -DisplayGroupingKey $keyHybridInformation `
                                -DisplayCustomTabNumber 2
                        }

                        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Lifetime In Days" `
                            -DisplayGroupingKey $keyHybridInformation

                        foreach ($thumbprint in $($connector.CertificateInformation).keys) {
                            switch ($($connector.CertificateInformation)[$thumbprint]) {
                                { $_ -ge 60 } { $certificateLifetimeWriteType = "Green"; break }
                                { $_ -ge 30 } { $certificateLifetimeWriteType = "Yellow"; break }
                                Default { $certificateLifetimeWriteType = "Red" }
                            }

                            $AnalyzeResults | Add-AnalyzedResultInformation -Details ($connector.CertificateInformation)[$thumbprint] `
                                -DisplayGroupingKey $keyHybridInformation `
                                -DisplayWriteType $certificateLifetimeWriteType `
                                -DisplayCustomTabNumber 2
                        }
                    }

                    $connectorCertificateMatchesHybridCertificateWritingType = "Yellow"
                    if (($connector.TlsCertificateSet) -and
                        (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.TlsCertificateName))) -and
                        ($connector.TlsCertificateName -eq $exchangeInformation.GetHybridConfiguration.TlsCertificateName)) {
                        $connectorCertificateMatchesHybridCertificate = $true
                        $connectorCertificateMatchesHybridCertificateWritingType = "Green"
                    }

                    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Certificate Matches Hybrid Certificate" -Details $connectorCertificateMatchesHybridCertificate `
                        -DisplayGroupingKey $keyHybridInformation `
                        -DisplayWriteType $connectorCertificateMatchesHybridCertificateWritingType

                    if (($connector.TlsCertificateNameStatus -eq "TlsCertificateNameSyntaxInvalid") -or
                        (($connector.GoodTlsCertificateSyntax -eq $false) -and
                            ($null -ne $connector.TlsCertificateName))) {
                        $AnalyzeResults | Add-AnalyzedResultInformation -Name "TlsCertificateName Syntax Invalid" -Details "True" `
                            -DisplayGroupingKey $keyHybridInformation `
                            -DisplayWriteType $cloudConnectorWriteType

                        $AnalyzeResults | Add-AnalyzedResultInformation -Details "The correct syntax is: '<I>X.500Issuer<S>X.500Subject'" `
                            -DisplayGroupingKey $keyHybridInformation `
                            -DisplayWriteType $cloudConnectorWriteType `
                            -DisplayCustomTabNumber 2
                    }
                }
            }
        }
    }
}
