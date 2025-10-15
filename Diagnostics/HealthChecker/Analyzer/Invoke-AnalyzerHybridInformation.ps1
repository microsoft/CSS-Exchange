# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

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

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = Get-DisplayResultsGroupingKey -Name "Hybrid Information"  -DisplayOrder $Order
    }

    $guidRegEx = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $getHybridConfiguration = $HealthServerObject.OrganizationInformation.GetHybridConfiguration
    $getPartnerApplication = $HealthServerObject.OrganizationInformation.GetPartnerApplication

    [array]$evoStsAuthServer = $HealthServerObject.OrganizationInformation.GetAuthServer | Where-Object {
        $null -ne $_.Type -and
        $_.Type.ToString() -eq "AzureAD" -and
        $_.Enabled -eq $true
    }

    [array]$acsAuthServer = $HealthServerObject.OrganizationInformation.GetAuthServer | Where-Object {
        $null -ne $_.Type -and
        $_.Type.ToString() -eq "MicrosoftACS" -and
        $_.Enabled -eq $true
    }

    # Exchange Online first-party application
    [array]$exchangeOnlinePartnerApplication = $getPartnerApplication | Where-Object {
        $_.ApplicationIdentifier -eq "00000002-0000-0ff1-ce00-000000000000" -and
        $_.Enabled -eq $true
    }

    # Legacy Skype for Business online first-party application
    [array]$legacySkypeForBusinessPartnerApplication = $getPartnerApplication | Where-Object {
        $_.ApplicationIdentifier -eq "00000004-0000-0ff1-ce00-000000000000" -and
        $_.Enabled -eq $true
    }

    # Teams Scheduler first-party application
    [array]$teamsSchedulerPartnerApplication = $getPartnerApplication | Where-Object {
        $_.ApplicationIdentifier -eq "7557eb47-c689-4224-abcf-aef9bd7573df" -and
        $_.Enabled -eq $true
    }

    # Cloud Voicemail first-party application
    [array]$cloudVoicemailPartnerApplication = $getPartnerApplication | Where-Object {
        $_.ApplicationIdentifier -eq "db7de2b5-2149-435e-8043-e080dd50afae" -and
        $_.Enabled -eq $true
    }

    [array]$dedicatedHybridAppOverride = $HealthServerObject.OrganizationInformation.GetSettingOverride | Where-Object {
        $_.ComponentName -eq "Global" -and
        $_.SectionName -eq "ExchangeOnpremAsThirdPartyAppId"
    }

    # We assume that oAuth between on-prem and online is configured if these two conditions apply
    # See: https://learn.microsoft.com/exchange/configure-oauth-authentication-between-exchange-and-exchange-online-organizations-exchange-2013-help
    $oAuthConfigured = (($evoStsAuthServer.Count -or $acsAuthServer.Count) -gt 0) -and ($exchangeOnlinePartnerApplication.Count -gt 0)

    # Check if the server is configured as sending or receiving transport server - if it is, the certificate used for hybrid mail flow must exist on the machine
    $certificateShouldExistOnServer = $getHybridConfiguration.SendingTransportServers.DistinguishedName -contains $exchangeInformation.GetExchangeServer.DistinguishedName -or
    $getHybridConfiguration.ReceivingTransportServers.DistinguishedName -contains $exchangeInformation.GetExchangeServer.DistinguishedName

    if ($exchangeInformation.BuildInformation.VersionInformation.BuildVersion -ge "15.0.0.0" -and
        ($null -ne $getHybridConfiguration -and
        @($getHybridConfiguration.PSObject.Properties).Count -ne 0) -or
        $oAuthConfigured) {

        $params = $baseParams + @{
            Name    = "Hybrid Configuration Detected"
            Details = "True"
        }
        Add-AnalyzedResultInformation @params

        if ($null -ne $getHybridConfiguration -and
            @($getHybridConfiguration.PSObject.Properties).Count -ne 0) {

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
        }

        $params = $baseParams + @{
            Name    = "OAuth between Exchange Server and Exchange Online"
            Details = $oAuthConfigured
        }
        Add-AnalyzedResultInformation @params

        Add-AnalyzedResultInformation -Name "Dedicated Exchange Hybrid Application" @baseParams

        $dedicatedHybridAppWriteType = "Yellow"
        $dedicatedHybridAppAuthServerObjects = 0

        if ($dedicatedHybridAppOverride.Count -ge 1) {
            # We can't determine the status if we find multiple SO - show error
            if ($dedicatedHybridAppOverride.Count -gt 1) {
                $dedicatedHybridAppShowMoreInformation = $true
                $dedicatedHybridAppWriteType = "Red"

                $params = $baseParams + @{
                    Details                = "Multiple SettingOverrides detected - unable to determine status of the feature"
                    DisplayCustomTabNumber = 2
                    DisplayWriteType       = $dedicatedHybridAppWriteType
                    TestingName            = "MultipleSettingOverrides"
                    DisplayTestingValue    = $true
                }
                Add-AnalyzedResultInformation @params
            }

            # Filter any evoSTS auth servers which have the application identifier set to a guid as this indicates the dedicated hybrid app is configured
            $dedicatedHybridAppAuthServer = $evoStsAuthServer | Where-Object { $_.ApplicationIdentifier -match $guidRegEx }

            if ($dedicatedHybridAppAuthServer.Count -ge 1) {
                foreach ($authServer in $dedicatedHybridAppAuthServer) {
                    $dedicatedHybridAppAuthServerObjects++

                    $authServerDetails = "AuthServer: $($authServer.Id)`r`n`t`tTenantId: $($authServer.Realm)`r`n`t`tAppId: $($authServer.ApplicationIdentifier)`r`n`t`tDomain(s): $([System.String]::Join(", ", [array]$authServer.DomainName))"

                    if ($dedicatedHybridAppAuthServerObjects -lt $dedicatedHybridAppAuthServer.Count) {
                        $authServerDetails = $authServerDetails + "`r`n`r`n"
                    }

                    $params = $baseParams + @{
                        Details                = $authServerDetails
                        DisplayCustomTabNumber = 2
                        TestingName            = "AuthServer - $dedicatedHybridAppAuthServerObjects"
                        DisplayTestingValue    = [PSCustomObject]@{
                            Id         = $authServer.Id
                            Realm      = $authServer.Realm
                            AppId      = $authServer.ApplicationIdentifier
                            DomainName = $authServer.DomainName
                        }
                    }
                    Add-AnalyzedResultInformation @params
                }
            }

            if ($dedicatedHybridAppAuthServerObjects -eq 0) {
                $dedicatedHybridAppShowMoreInformation = $true
                $dedicatedHybridAppWriteType = "Red"

                $params = $baseParams + @{
                    Details                = "No valid AuthServer object was found that supports the dedicated Exchange Hybrid Application"
                    DisplayCustomTabNumber = 2
                    DisplayWriteType       = $dedicatedHybridAppWriteType
                    TestingName            = "NoValidAuthServer"
                    DisplayTestingValue    = $true
                }
                Add-AnalyzedResultInformation @params
            }
        }

        if ($dedicatedHybridAppOverride.Count -eq 0) {
            $dedicatedHybridAppShowMoreInformation = $true
            $params = $baseParams + @{
                Details                = "Configure the dedicated hybrid app to ensure hybrid features continue working in the future"
                DisplayCustomTabNumber = 2
                DisplayWriteType       = $dedicatedHybridAppWriteType
                TestingName            = "DedicatedHybridAppNotConfigured"
                DisplayTestingValue    = $true
            }
            Add-AnalyzedResultInformation @params
        }

        if ($dedicatedHybridAppShowMoreInformation) {
            $params = $baseParams + @{
                Details                = "More information: https://aka.ms/HC-ExchangeHybridApplication"
                DisplayCustomTabNumber = 2
                DisplayWriteType       = $dedicatedHybridAppWriteType
                TestingName            = "DedicatedHybridAppShowMoreInformation"
                DisplayTestingValue    = $true
            }
            Add-AnalyzedResultInformation @params
        }

        $params = $baseParams + @{
            Name    = "OAuth between Exchange Server and Microsoft Teams"
            Details = $legacySkypeForBusinessPartnerApplication -or $cloudVoicemailPartnerApplication -or $teamsSchedulerPartnerApplication
        }
        Add-AnalyzedResultInformation @params

        if ($legacySkypeForBusinessPartnerApplication -and
            (-not $cloudVoicemailPartnerApplication -and
            -not $teamsSchedulerPartnerApplication)) {

            # Customers must take action and create new partner applications for Cloud Voicemail and/or Teams Scheduler
            # See: https://learn.microsoft.com/skypeforbusiness/deploy/integrate-with-exchange-server/oauth-with-online-and-on-premises
            $params = $baseParams + @{
                Details                = "Legacy Skype for Business Online Partner Application detected"
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Red"
                TestingName            = "LegacySfBPartnerApp"
                DisplayTestingValue    = $true
            }
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Details                = "Follow the instructions to configure the new dedicated Partner Applications`r`n`t`thttps://aka.ms/HC-SfBLegacyPartnerApp"
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Red"
            }
            Add-AnalyzedResultInformation @params
        }

        if ($null -ne $exchangeInformation.ExchangeCustomConnector) {

            $exchangeConnectors = $exchangeInformation.ExchangeCustomConnector

            foreach ($connector in $exchangeConnectors) {
                $cloudConnectorWriteType = "Yellow"
                $smartHostsPointToExo = $false
                $addressSpacesContainsWildcard = $false

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
                                $tlsAuthLevelM365RelayWriteType = "Yellow"
                                break
                            }
                            "CertificateValidation" {
                                $tlsAuthLevelM365RelayWriteType = "Green"
                                break
                            }
                            "DomainValidation" {
                                if ($null -eq $connector.TlsDomain) {
                                    $tlsAuthLevelM365RelayWriteType = "Red"
                                } else {
                                    $tlsAuthLevelM365RelayWriteType = "Green"
                                }
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

                        Write-Verbose "Server is configured for hybrid mail flow and the transport certificate should exist on this server? $certificateShouldExistOnServer"

                        if ($null -ne $connector.CertificateDetails.TlsCertificateName) {
                            $cloudConnectorTlsCertificateName = $connector.CertificateDetails.TlsCertificateName
                        }

                        $params = $baseParams + @{
                            Name             = "TlsCertificateName"
                            Details          = $cloudConnectorTlsCertificateName
                            DisplayWriteType = $cloudConnectorWriteType
                        }
                        Add-AnalyzedResultInformation @params

                        # Don't perform the following checks if the server is not a sending or receiving transport server configured for hybrid mail flow (there is a high chance that the certificate didn't exist which is by design)
                        if ($certificateShouldExistOnServer) {
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
    Write-Verbose "Completed: $($MyInvocation.MyCommand) and took $($stopWatch.Elapsed.TotalSeconds) seconds"
}
