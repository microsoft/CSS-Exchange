# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
function Invoke-AnalyzerHybridInformation {
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
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = Get-DisplayResultsGroupingKey -Name "Hybrid Information"  -DisplayOrder $Order
    }
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $getHybridConfiguration = $HealthServerObject.OrganizationInformation.GetHybridConfiguration

    if ($exchangeInformation.BuildInformation.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2013 -and
        $null -ne $getHybridConfiguration) {

        $params = $baseParams + @{
            Name    = "Organization Hybrid Enabled"
            Details = "True"
        }
        Add-AnalyzedResultInformation @params

        if (-not([System.String]::IsNullOrEmpty($getHybridConfiguration.OnPremisesSmartHost))) {
            $onPremSmartHostDomain = ($getHybridConfiguration.OnPremisesSmartHost).ToString()
            $onPremSmartHostWriteType = "Grey"
        } else {
            $onPremSmartHostDomain = "No on-premises smart host domain configured for hybrid use"
            $onPremSmartHostWriteType = "Yellow"
        }

        $params = $baseParams + @{
            Name             = "On-Premises Smart Host Domain"
            Details          = $onPremSmartHostDomain
            DisplayWriteType = $onPremSmartHostWriteType
        }
        Add-AnalyzedResultInformation @params

        if (-not([System.String]::IsNullOrEmpty($getHybridConfiguration.Domains))) {
            $domainsConfiguredForHybrid = $getHybridConfiguration.Domains
            $domainsConfiguredForHybridWriteType = "Grey"
        } else {
            $domainsConfiguredForHybridWriteType = "Yellow"
        }

        $params = $baseParams + @{
            Name             = "Domain(s) configured for Hybrid use"
            DisplayWriteType = $domainsConfiguredForHybridWriteType
        }
        Add-AnalyzedResultInformation @params

        if ($domainsConfiguredForHybrid.Count -ge 1) {
            foreach ($domain in $domainsConfiguredForHybrid) {
                $params = $baseParams + @{
                    Details                = $domain
                    DisplayWriteType       = $domainsConfiguredForHybridWriteType
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }
        } else {
            $params = $baseParams + @{
                Details                = "No domain configured for Hybrid use"
                DisplayWriteType       = $domainsConfiguredForHybridWriteType
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        if (-not([System.String]::IsNullOrEmpty($getHybridConfiguration.EdgeTransportServers))) {
            Add-AnalyzedResultInformation -Name "Edge Transport Server(s)" @baseParams

            foreach ($edgeServer in $getHybridConfiguration.EdgeTransportServers) {
                $params = $baseParams + @{
                    Details                = $edgeServer
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }

            if (-not([System.String]::IsNullOrEmpty($getHybridConfiguration.ReceivingTransportServers)) -or
            (-not([System.String]::IsNullOrEmpty($getHybridConfiguration.SendingTransportServers)))) {
                $params = $baseParams + @{
                    Details                = "When configuring the EdgeTransportServers parameter, you must configure the ReceivingTransportServers and SendingTransportServers parameter values to null"
                    DisplayWriteType       = "Yellow"
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }
        } else {
            Add-AnalyzedResultInformation -Name "Receiving Transport Server(s)" @baseParams

            if (-not([System.String]::IsNullOrEmpty($getHybridConfiguration.ReceivingTransportServers))) {
                foreach ($receivingTransportSrv in $getHybridConfiguration.ReceivingTransportServers) {
                    $params = $baseParams + @{
                        Details                = $receivingTransportSrv
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params
                }
            } else {
                $params = $baseParams + @{
                    Details                = "No Receiving Transport Server configured for Hybrid use"
                    DisplayWriteType       = "Yellow"
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }

            Add-AnalyzedResultInformation -Name "Sending Transport Server(s)" @baseParams

            if (-not([System.String]::IsNullOrEmpty($getHybridConfiguration.SendingTransportServers))) {
                foreach ($sendingTransportSrv in $getHybridConfiguration.SendingTransportServers) {
                    $params = $baseParams + @{
                        Details                = $sendingTransportSrv
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params
                }
            } else {
                $params = $baseParams + @{
                    Details                = "No Sending Transport Server configured for Hybrid use"
                    DisplayWriteType       = "Yellow"
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }
        }

        if ($getHybridConfiguration.ServiceInstance -eq 1) {
            $params = $baseParams + @{
                Name    = "Service Instance"
                Details = "Office 365 operated by 21Vianet"
            }
            Add-AnalyzedResultInformation @params
        } elseif ($getHybridConfiguration.ServiceInstance -ne 0) {
            $params = $baseParams + @{
                Name             = "Service Instance"
                Details          = $getHybridConfiguration.ServiceInstance
                DisplayWriteType = "Red"
            }
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Details          = "You are using an invalid value. Please set this value to 0 (null) or re-run HCW"
                DisplayWriteType = "Red"
            }
            Add-AnalyzedResultInformation @params
        }

        if (-not([System.String]::IsNullOrEmpty($getHybridConfiguration.TlsCertificateName))) {
            $params = $baseParams + @{
                Name    = "TLS Certificate Name"
                Details = ($getHybridConfiguration.TlsCertificateName).ToString()
            }
            Add-AnalyzedResultInformation @params
        } else {
            $params = $baseParams + @{
                Name             = "TLS Certificate Name"
                Details          = "No valid certificate found"
                DisplayWriteType = "Red"
            }
            Add-AnalyzedResultInformation @params
        }

        Add-AnalyzedResultInformation -Name "Feature(s) enabled for Hybrid use" @baseParams

        if (-not([System.String]::IsNullOrEmpty($getHybridConfiguration.Features))) {
            foreach ($feature in $getHybridConfiguration.Features) {
                $params = $baseParams + @{
                    Details                = $feature
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }
        } else {
            $params = $baseParams + @{
                Details                = "No feature(s) enabled for Hybrid use"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        if ($null -ne $exchangeInformation.ExchangeConnectors) {
            foreach ($connector in $exchangeInformation.ExchangeConnectors) {
                $cloudConnectorWriteType = "Yellow"
                if (($connector.TransportRole -ne "HubTransport") -and
                    ($connector.CloudEnabled -eq $true)) {

                    $params = $baseParams + @{
                        Details          = "`r"
                        AddHtmlDetailRow = $false
                    }
                    Add-AnalyzedResultInformation @params

                    if (($connector.CertificateDetails.CertificateMatchDetected) -and
                        ($connector.CertificateDetails.GoodTlsCertificateSyntax)) {
                        $cloudConnectorWriteType = "Green"
                    }

                    $params = $baseParams + @{
                        Name    = "Connector Name"
                        Details = $connector.Name
                    }
                    Add-AnalyzedResultInformation @params

                    $cloudConnectorEnabledWriteType = "Gray"
                    if ($connector.Enabled -eq $false) {
                        $cloudConnectorEnabledWriteType = "Yellow"
                    }

                    $params = $baseParams + @{
                        Name             = "Connector Enabled"
                        Details          = $connector.Enabled
                        DisplayWriteType = $cloudConnectorEnabledWriteType
                    }
                    Add-AnalyzedResultInformation @params

                    $params = $baseParams + @{
                        Name    = "Cloud Mail Enabled"
                        Details = $connector.CloudEnabled
                    }
                    Add-AnalyzedResultInformation @params

                    $params = $baseParams + @{
                        Name    = "Connector Type"
                        Details = $connector.ConnectorType
                    }
                    Add-AnalyzedResultInformation @params

                    if (($connector.ConnectorType -eq "Send") -and
                        ($null -ne $connector.TlsAuthLevel)) {
                        # Check if send connector is configured to relay mails to the internet via M365
                        switch ($connector) {
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

                            $params = $baseParams + @{
                                Name             = "TlsAuthLevel"
                                Details          = $connector.TlsAuthLevel
                                DisplayWriteType = $tlsAuthLevelWriteType
                            }
                            Add-AnalyzedResultInformation @params

                            if ($null -ne $tlsAuthLevelAdditionalInfo) {
                                $params = $baseParams + @{
                                    Details                = $tlsAuthLevelAdditionalInfo
                                    DisplayWriteType       = $tlsAuthLevelWriteType
                                    DisplayCustomTabNumber = 2
                                }
                                Add-AnalyzedResultInformation @params
                            }
                        }
                    }

                    if (($smartHostsPointToExo) -and
                        ($addressSpacesContainsWildcard)) {
                        # Seems like this send connector is configured to relay mails to the internet via M365 - skipping some checks
                        # https://docs.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-to-route-mail#2-set-up-your-email-server-to-relay-mail-to-the-internet-via-microsoft-365-or-office-365
                        $params = $baseParams + @{
                            Name    = "Relay Internet Mails via M365"
                            Details = $true
                        }
                        Add-AnalyzedResultInformation @params

                        switch ($connector.TlsAuthLevel) {
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
                            default { $tlsAuthLevelM365RelayWriteType = "Red" }
                        }

                        $params = $baseParams + @{
                            Name             = "TlsAuthLevel"
                            Details          = $connector.TlsAuthLevel
                            DisplayWriteType = $tlsAuthLevelM365RelayWriteType
                        }
                        Add-AnalyzedResultInformation @params

                        if ($tlsAuthLevelM365RelayWriteType -ne "Green") {
                            $params = $baseParams + @{
                                Details                = "'TlsAuthLevel' should be set to 'CertificateValidation'. More information: https://aka.ms/HC-HybridConnector"
                                DisplayWriteType       = $tlsAuthLevelM365RelayWriteType
                                DisplayCustomTabNumber = 2
                            }
                            Add-AnalyzedResultInformation @params
                        }

                        $requireTlsWriteType = "Red"
                        if ($connector.RequireTLS) {
                            $requireTlsWriteType = "Green"
                        }

                        $params = $baseParams + @{
                            Name             = "RequireTls Enabled"
                            Details          = $connector.RequireTLS
                            DisplayWriteType = $requireTlsWriteType
                        }
                        Add-AnalyzedResultInformation @params

                        if ($requireTlsWriteType -eq "Red") {
                            $params = $baseParams + @{
                                Details                = "'RequireTLS' must be set to 'true' to ensure a working mail flow. More information: https://aka.ms/HC-HybridConnector"
                                DisplayWriteType       = $requireTlsWriteType
                                DisplayCustomTabNumber = 2
                            }
                            Add-AnalyzedResultInformation @params
                        }
                    } else {
                        $cloudConnectorTlsCertificateName = "Not set"
                        if ($null -ne $connector.CertificateDetails.TlsCertificateName) {
                            $cloudConnectorTlsCertificateName = $connector.CertificateDetails.TlsCertificateName
                        }

                        $params = $baseParams + @{
                            Name             = "TlsCertificateName"
                            Details          = $cloudConnectorTlsCertificateName
                            DisplayWriteType = $cloudConnectorWriteType
                        }
                        Add-AnalyzedResultInformation @params

                        $params = $baseParams + @{
                            Name             = "Certificate Found On Server"
                            Details          = $connector.CertificateDetails.CertificateMatchDetected
                            DisplayWriteType = $cloudConnectorWriteType
                        }
                        Add-AnalyzedResultInformation @params

                        if ($connector.CertificateDetails.TlsCertificateNameStatus -eq "TlsCertificateNameEmpty") {
                            $params = $baseParams + @{
                                Details                = "There is no 'TlsCertificateName' configured for this cloud mail enabled connector.`r`n`t`tThis will cause mail flow issues in hybrid scenarios. More information: https://aka.ms/HC-HybridConnector"
                                DisplayWriteType       = $cloudConnectorWriteType
                                DisplayCustomTabNumber = 2
                            }
                            Add-AnalyzedResultInformation @params
                        } elseif ($connector.CertificateDetails.CertificateMatchDetected -eq $false) {
                            $params = $baseParams + @{
                                Details                = "The configured 'TlsCertificateName' was not found on the server.`r`n`t`tThis may cause mail flow issues. More information: https://aka.ms/HC-HybridConnector"
                                DisplayWriteType       = $cloudConnectorWriteType
                                DisplayCustomTabNumber = 2
                            }
                            Add-AnalyzedResultInformation @params
                        } else {
                            Add-AnalyzedResultInformation -Name "Certificate Thumbprint(s)" @baseParams

                            foreach ($thumbprint in $($connector.CertificateDetails.CertificateLifetimeInfo).keys) {
                                $params = $baseParams + @{
                                    Details                = $thumbprint
                                    DisplayCustomTabNumber = 2
                                }
                                Add-AnalyzedResultInformation @params
                            }

                            Add-AnalyzedResultInformation -Name "Lifetime In Days" @baseParams

                            foreach ($thumbprint in $($connector.CertificateDetails.CertificateLifetimeInfo).keys) {
                                switch ($($connector.CertificateDetails.CertificateLifetimeInfo)[$thumbprint]) {
                                    { ($_ -ge 60) } { $certificateLifetimeWriteType = "Green"; break }
                                    { ($_ -ge 30) } { $certificateLifetimeWriteType = "Yellow"; break }
                                    default { $certificateLifetimeWriteType = "Red" }
                                }

                                $params = $baseParams + @{
                                    Details                = ($connector.CertificateDetails.CertificateLifetimeInfo)[$thumbprint]
                                    DisplayWriteType       = $certificateLifetimeWriteType
                                    DisplayCustomTabNumber = 2
                                }
                                Add-AnalyzedResultInformation @params
                            }

                            $connectorCertificateMatchesHybridCertificate = $false
                            $connectorCertificateMatchesHybridCertificateWritingType = "Yellow"
                            if (($connector.CertificateDetails.TlsCertificateSet) -and
                                (-not([System.String]::IsNullOrEmpty($getHybridConfiguration.TlsCertificateName))) -and
                                ($connector.CertificateDetails.TlsCertificateName -eq $getHybridConfiguration.TlsCertificateName)) {
                                $connectorCertificateMatchesHybridCertificate = $true
                                $connectorCertificateMatchesHybridCertificateWritingType = "Green"
                            }

                            $params = $baseParams + @{
                                Name             = "Certificate Matches Hybrid Certificate"
                                Details          = $connectorCertificateMatchesHybridCertificate
                                DisplayWriteType = $connectorCertificateMatchesHybridCertificateWritingType
                            }
                            Add-AnalyzedResultInformation @params

                            if (($connector.CertificateDetails.TlsCertificateNameStatus -eq "TlsCertificateNameSyntaxInvalid") -or
                                (($connector.CertificateDetails.GoodTlsCertificateSyntax -eq $false) -and
                                    ($null -ne $connector.CertificateDetails.TlsCertificateName))) {
                                $params = $baseParams + @{
                                    Name             = "TlsCertificateName Syntax Invalid"
                                    Details          = "True"
                                    DisplayWriteType = $cloudConnectorWriteType
                                }
                                Add-AnalyzedResultInformation @params

                                $params = $baseParams + @{
                                    Details                = "The correct syntax is: '<I>X.500Issuer<S>X.500Subject'"
                                    DisplayWriteType       = $cloudConnectorWriteType
                                    DisplayCustomTabNumber = 2
                                }
                                Add-AnalyzedResultInformation @params
                            }
                        }
                    }
                }
            }
        }
    }
}
