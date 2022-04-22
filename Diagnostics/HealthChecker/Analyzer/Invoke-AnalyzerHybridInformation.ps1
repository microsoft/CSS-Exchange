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

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Organization Hybrid Enabled" -Details "True" `
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

                    if (($connector.CertificateDetails.CertificateMatchDetected) -and
                        ($connector.CertificateDetails.GoodTlsCertificateSyntax)) {
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
                        # Check if send connector is configured to relay mails to the internet via M365
                        Switch ($connector) {
                            { ($_.SmartHosts -like "*.mail.protection.outlook.com") } {
                                $smartHostsPointToExo = $true
                            }
                            { ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($_.AddressSpaces)) } {
                                $addressSpacesContainsWildcard = $true
                            }
                        }

                        if (($smartHostsPointToExo -eq $false) -or
                            ($addressSpacesContainsWildcard -eq $false)) {

                            $tlsAuthLevelWriteType = "Gray"
                            if ($connector.TlsAuthLevel -eq "DomainValidation") {
                                # DomainValidation: In addition to channel encryption and certificate validation,
                                # the Send connector also verifies that the FQDN of the target certificate matches
                                # the domain specified in the TlsDomain parameter. If no domain is specified in the TlsDomain parameter,
                                # the FQDN on the certificate is compared with the recipient's domain.
                                $tlsAuthLevelWriteType = "Green"
                                if ($null -eq $connector.TlsDomain) {
                                    $tlsAuthLevelWriteType = "Yellow"
                                    $tlsAuthLevelAdditionalInfo = "'TlsDomain' is empty which means that the FQDN of the certificate is compared with the recipient's domain.`r`n`t`tMore information: https://aka.ms/HC-HybridConnector"
                                }
                            }

                            $AnalyzeResults | Add-AnalyzedResultInformation -Name "TlsAuthLevel" -Details $connector.TlsAuthLevel `
                                -DisplayGroupingKey $keyHybridInformation `
                                -DisplayWriteType $tlsAuthLevelWriteType

                            if ($null -ne $tlsAuthLevelAdditionalInfo) {
                                $AnalyzeResults | Add-AnalyzedResultInformation -Details $tlsAuthLevelAdditionalInfo `
                                    -DisplayGroupingKey $keyHybridInformation `
                                    -DisplayWriteType $tlsAuthLevelWriteType `
                                    -DisplayCustomTabNumber 2
                            }
                        }
                    }

                    if (($smartHostsPointToExo) -and
                        ($addressSpacesContainsWildcard)) {
                        # Seems like this send connector is configured to relay mails to the internet via M365 - skipping some checks
                        # https://docs.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-to-route-mail#2-set-up-your-email-server-to-relay-mail-to-the-internet-via-microsoft-365-or-office-365
                        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Relay Internet Mails via M365" -Details $true `
                            -DisplayGroupingKey $keyHybridInformation

                        Switch ($connector.TlsAuthLevel) {
                            "EncryptionOnly" {
                                $tlsAuthLevelM365RelayWriteType = "Yellow";
                                break
                            }
                            "CertificateValidation" {
                                $tlsAuthLevelM365RelayWriteType = "Green";
                                break
                            }
                            "DomainValidation" {
                                if ($null -eq $connector.TlsDomain) {
                                    $tlsAuthLevelM365RelayWriteType = "Red"
                                } else {
                                    $tlsAuthLevelM365RelayWriteType = "Green"
                                };
                                break
                            }
                            Default { $tlsAuthLevelM365RelayWriteType = "Red" }
                        }

                        $AnalyzeResults | Add-AnalyzedResultInformation -Name "TlsAuthLevel" -Details $connector.TlsAuthLevel `
                            -DisplayGroupingKey $keyHybridInformation `
                            -DisplayWriteType $tlsAuthLevelM365RelayWriteType

                        if ($tlsAuthLevelM365RelayWriteType -ne "Green") {
                            $AnalyzeResults | Add-AnalyzedResultInformation -Details "'TlsAuthLevel' should be set to 'CertificateValidation'. More information: https://aka.ms/HC-HybridConnector" `
                                -DisplayGroupingKey $keyHybridInformation `
                                -DisplayWriteType $tlsAuthLevelM365RelayWriteType `
                                -DisplayCustomTabNumbermber 2
                        }

                        $requireTlsWriteType = "Red"
                        if ($connector.RequireTLS) {
                            $requireTlsWriteType = "Green"
                        }

                        $AnalyzeResults | Add-AnalyzedResultInformation -Name "RequireTls Enabled" -Details $connector.RequireTLS `
                            -DisplayGroupingKey $keyHybridInformation `
                            -DisplayWriteType $requireTlsWriteType

                        if ($requireTlsWriteType -eq "Red") {
                            $AnalyzeResults | Add-AnalyzedResultInformation -Details "'RequireTLS' must be set to 'true' to ensure a working mail flow. More information: https://aka.ms/HC-HybridConnector" `
                                -DisplayGroupingKey $keyHybridInformation `
                                -DisplayWriteType $requireTlsWriteType `
                                -DisplayCustomTabNumber 2
                        }
                    } else {
                        $cloudConnectorTlsCertificateName = "Not set"
                        if ($null -ne $connector.CertificateDetails.TlsCertificateName) {
                            $cloudConnectorTlsCertificateName = $connector.CertificateDetails.TlsCertificateName
                        }

                        $AnalyzeResults | Add-AnalyzedResultInformation -Name "TlsCertificateName" -Details $cloudConnectorTlsCertificateName `
                            -DisplayGroupingKey $keyHybridInformation `
                            -DisplayWriteType $cloudConnectorWriteType

                        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Certificate Found On Server" -Details $connector.CertificateDetails.CertificateMatchDetected `
                            -DisplayGroupingKey $keyHybridInformation `
                            -DisplayWriteType $cloudConnectorWriteType

                        if ($connector.CertificateDetails.TlsCertificateNameStatus -eq "TlsCertificateNameEmpty") {
                            $AnalyzeResults | Add-AnalyzedResultInformation -Details "There is no 'TlsCertificateName' configured for this cloud mail enabled connector.`r`n`t`tThis will cause mail flow issues in hybrid scenarios. More information: https://aka.ms/HC-HybridConnector" `
                                -DisplayGroupingKey $keyHybridInformation `
                                -DisplayWriteType $cloudConnectorWriteType `
                                -DisplayCustomTabNumber 2
                        } elseif ($connector.CertificateDetails.CertificateMatchDetected -eq $false) {
                            $AnalyzeResults | Add-AnalyzedResultInformation -Details "The configured 'TlsCertificateName' was not found on the server.`r`n`t`tThis may cause mail flow issues. More information: https://aka.ms/HC-HybridConnector" `
                                -DisplayGroupingKey $keyHybridInformation `
                                -DisplayWriteType $cloudConnectorWriteType `
                                -DisplayCustomTabNumber 2
                        } else {
                            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Certificate Thumbprint(s)" `
                                -DisplayGroupingKey $keyHybridInformation

                            foreach ($thumbprint in $($connector.CertificateDetails.CertificateLifetimeInfo).keys) {
                                $AnalyzeResults | Add-AnalyzedResultInformation -Details $thumbprint `
                                    -DisplayGroupingKey $keyHybridInformation `
                                    -DisplayCustomTabNumber 2
                            }

                            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Lifetime In Days" `
                                -DisplayGroupingKey $keyHybridInformation

                            foreach ($thumbprint in $($connector.CertificateDetails.CertificateLifetimeInfo).keys) {
                                switch ($($connector.CertificateDetails.CertificateLifetimeInfo)[$thumbprint]) {
                                    { ($_ -ge 60) } { $certificateLifetimeWriteType = "Green"; break }
                                    { ($_ -ge 30) } { $certificateLifetimeWriteType = "Yellow"; break }
                                    Default { $certificateLifetimeWriteType = "Red" }
                                }

                                $AnalyzeResults | Add-AnalyzedResultInformation -Details ($connector.CertificateDetails.CertificateLifetimeInfo)[$thumbprint] `
                                    -DisplayGroupingKey $keyHybridInformation `
                                    -DisplayWriteType $certificateLifetimeWriteType `
                                    -DisplayCustomTabNumber 2
                            }

                            $connectorCertificateMatchesHybridCertificate = $false
                            $connectorCertificateMatchesHybridCertificateWritingType = "Yellow"
                            if (($connector.CertificateDetails.TlsCertificateSet) -and
                                (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.TlsCertificateName))) -and
                                ($connector.CertificateDetails.TlsCertificateName -eq $exchangeInformation.GetHybridConfiguration.TlsCertificateName)) {
                                $connectorCertificateMatchesHybridCertificate = $true
                                $connectorCertificateMatchesHybridCertificateWritingType = "Green"
                            }

                            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Certificate Matches Hybrid Certificate" -Details $connectorCertificateMatchesHybridCertificate `
                                -DisplayGroupingKey $keyHybridInformation `
                                -DisplayWriteType $connectorCertificateMatchesHybridCertificateWritingType

                            if (($connector.CertificateDetails.TlsCertificateNameStatus -eq "TlsCertificateNameSyntaxInvalid") -or
                                (($connector.CertificateDetails.GoodTlsCertificateSyntax -eq $false) -and
                                    ($null -ne $connector.CertificateDetails.TlsCertificateName))) {
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
    }
}
