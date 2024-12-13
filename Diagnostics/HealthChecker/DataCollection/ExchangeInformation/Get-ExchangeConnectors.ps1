# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
function Get-ExchangeConnectors {
    [CmdletBinding()]
    [OutputType("System.Object[]")]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName,
        [Parameter(Mandatory = $false)]
        [object]
        $CertificateObject
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed - ComputerName: $ComputerName"
        function ExchangeConnectorObjectFactory {
            [CmdletBinding()]
            [OutputType("System.Object")]
            param(
                [Parameter(Mandatory = $true)]
                [object]
                $ConnectorObject
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $exchangeFactoryConnectorReturnObject = [PSCustomObject]@{
                Identity           = $ConnectorObject.Identity
                Name               = $ConnectorObject.Name
                Fqdn               = $ConnectorObject.Fqdn
                Enabled            = $ConnectorObject.Enabled
                CloudEnabled       = $false
                ConnectorType      = $null
                TransportRole      = $null
                SmartHosts         = $null
                AddressSpaces      = $null
                RequireTLS         = $false
                TlsAuthLevel       = $null
                TlsDomain          = $null
                CertificateDetails = [PSCustomObject]@{
                    CertificateMatchDetected = $false
                    GoodTlsCertificateSyntax = $false
                    TlsCertificateName       = $null
                    TlsCertificateNameStatus = $null
                    TlsCertificateSet        = $false
                    CertificateLifetimeInfo  = $null
                }
            }

            Write-Verbose ("Creating object for Exchange connector: '{0}'" -f $ConnectorObject.Identity)
            if ($null -ne $ConnectorObject.Server) {
                Write-Verbose "Exchange ReceiveConnector detected"
                $exchangeFactoryConnectorReturnObject.ConnectorType =  "Receive"
                $exchangeFactoryConnectorReturnObject.TransportRole = $ConnectorObject.TransportRole
                if (-not([System.String]::IsNullOrEmpty($ConnectorObject.TlsDomainCapabilities))) {
                    $exchangeFactoryConnectorReturnObject.CloudEnabled = $true
                }
            } else {
                Write-Verbose "Exchange SendConnector detected"
                $exchangeFactoryConnectorReturnObject.ConnectorType = "Send"
                $exchangeFactoryConnectorReturnObject.CloudEnabled = $ConnectorObject.CloudServicesMailEnabled
                $exchangeFactoryConnectorReturnObject.TlsDomain = $ConnectorObject.TlsDomain
                if ($null -ne $ConnectorObject.TlsAuthLevel) {
                    $exchangeFactoryConnectorReturnObject.TlsAuthLevel = $ConnectorObject.TlsAuthLevel
                }

                if ($null -ne $ConnectorObject.SmartHosts) {
                    $exchangeFactoryConnectorReturnObject.SmartHosts = $ConnectorObject.SmartHosts
                }

                if ($null -ne $ConnectorObject.AddressSpaces) {
                    $exchangeFactoryConnectorReturnObject.AddressSpaces = $ConnectorObject.AddressSpaces
                }
            }

            if ($null -ne $ConnectorObject.TlsCertificateName) {
                Write-Verbose "TlsCertificateName is configured on this connector"
                $exchangeFactoryConnectorReturnObject.CertificateDetails.TlsCertificateSet = $true
                $exchangeFactoryConnectorReturnObject.CertificateDetails.TlsCertificateName = ($ConnectorObject.TlsCertificateName).ToString()
            } else {
                Write-Verbose "TlsCertificateName is not configured on this connector"
                $exchangeFactoryConnectorReturnObject.CertificateDetails.TlsCertificateNameStatus = "TlsCertificateNameEmpty"
            }

            $exchangeFactoryConnectorReturnObject.RequireTLS = $ConnectorObject.RequireTLS

            return $exchangeFactoryConnectorReturnObject
        }

        function NormalizeTlsCertificateName {
            [CmdletBinding()]
            [OutputType("System.Object")]
            param(
                [Parameter(Mandatory = $true)]
                [string]
                $TlsCertificateName
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            try {
                Write-Verbose ("TlsCertificateName that was passed: '{0}'" -f $TlsCertificateName)
                # RegEx to match the recommended value which is "<I>X.500Issuer<S>X.500Subject"
                if ($TlsCertificateName -match "(<i>).*(<s>).*") {
                    $expectedTlsCertificateNameDetected = $true
                    $issuerIndex = $TlsCertificateName.IndexOf("<I>", [System.StringComparison]::OrdinalIgnoreCase)
                    $subjectIndex = $TlsCertificateName.IndexOf("<S>", [System.StringComparison]::OrdinalIgnoreCase)

                    Write-Verbose "TlsCertificateName that matches the expected syntax was passed"
                } else {
                    # Failsafe to detect cases where <I> and <S> are missing in TlsCertificateName
                    $issuerIndex = $TlsCertificateName.IndexOf("CN=", [System.StringComparison]::OrdinalIgnoreCase)
                    $subjectIndex = $TlsCertificateName.LastIndexOf("CN=", [System.StringComparison]::OrdinalIgnoreCase)

                    Write-Verbose "TlsCertificateName with bad syntax was passed"
                }

                # We stop processing if Issuer OR Subject index is -1 (no match found)
                if (($issuerIndex -ne -1) -and
                    ($subjectIndex -ne -1)) {
                    if ($expectedTlsCertificateNameDetected) {
                        $issuer = $TlsCertificateName.Substring(($issuerIndex + 3), ($subjectIndex - 3))
                        $subject = $TlsCertificateName.Substring($subjectIndex + 3)
                    } else {
                        $issuer  = $TlsCertificateName.Substring($issuerIndex, $subjectIndex)
                        $subject = $TlsCertificateName.Substring($subjectIndex)
                    }
                }

                if (($null -ne $issuer) -and
                    ($null -ne $subject)) {
                    return [PSCustomObject]@{
                        Issuer     = $issuer
                        Subject    = $subject
                        GoodSyntax = $expectedTlsCertificateNameDetected
                    }
                }
            } catch {
                Write-Verbose "We hit an exception while parsing the TlsCertificateName string"
                Invoke-CatchActions
            }
        }

        function FindMatchingExchangeCertificate {
            [CmdletBinding()]
            [OutputType("System.Object")]
            param(
                [Parameter(Mandatory = $true)]
                [object]
                $CertificateObject,
                [Parameter(Mandatory = $true)]
                [object]
                $ConnectorCustomObject
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            try {
                Write-Verbose ("{0} connector object(s) was/were passed to process" -f $ConnectorCustomObject.Count)
                foreach ($connectorObject in $ConnectorCustomObject) {

                    if ($null -ne $ConnectorObject.CertificateDetails.TlsCertificateName) {
                        $connectorTlsCertificateNormalizedObject = NormalizeTlsCertificateName `
                            -TlsCertificateName $ConnectorObject.CertificateDetails.TlsCertificateName

                        if ($null -eq $connectorTlsCertificateNormalizedObject) {
                            Write-Verbose "Unable to normalize TlsCertificateName - could be caused by an invalid TlsCertificateName configuration"
                            $connectorObject.CertificateDetails.TlsCertificateNameStatus = "TlsCertificateNameSyntaxInvalid"
                        } else {
                            if ($connectorTlsCertificateNormalizedObject.GoodSyntax) {
                                $connectorObject.CertificateDetails.GoodTlsCertificateSyntax = $connectorTlsCertificateNormalizedObject.GoodSyntax
                            }

                            $certificateMatches = 0
                            $certificateLifetimeInformation = @{}
                            foreach ($certificate in $CertificateObject) {
                                if (($certificate.Issuer -eq $connectorTlsCertificateNormalizedObject.Issuer) -and
                                    ($certificate.Subject -eq $connectorTlsCertificateNormalizedObject.Subject)) {
                                    Write-Verbose ("Certificate: '{0}' matches Connectors: '{1}' TlsCertificateName: '{2}'" -f $certificate.Thumbprint, $connectorObject.Identity, $connectorObject.CertificateDetails.TlsCertificateName)
                                    $connectorObject.CertificateDetails.CertificateMatchDetected = $true
                                    $connectorObject.CertificateDetails.TlsCertificateNameStatus = "TlsCertificateMatch"
                                    $certificateLifetimeInformation.Add($certificate.Thumbprint, $certificate.LifetimeInDays)

                                    $certificateMatches++
                                }
                            }

                            if ($certificateMatches -eq 0) {
                                Write-Verbose "No matching certificate was found on the server"
                                $connectorObject.CertificateDetails.TlsCertificateNameStatus = "TlsCertificateNotFound"
                            } else {
                                Write-Verbose ("We found: '{0}' matching certificates on the server" -f $certificateMatches)
                                $connectorObject.CertificateDetails.CertificateLifetimeInfo = $certificateLifetimeInformation
                            }
                        }
                    }
                }
            } catch {
                Write-Verbose "Hit an exception while trying to locate the configured certificate on the system"
                Invoke-CatchActions
            }

            return $ConnectorCustomObject
        }
    }
    process {
        Write-Verbose ("Trying to query Exchange connectors for server: '{0}'" -f $ComputerName)
        try {
            $allReceiveConnectors = Get-ReceiveConnector -Server $ComputerName -ErrorAction Stop
            $allSendConnectors = Get-SendConnector -ErrorAction Stop
            $connectorCustomObject = @()

            foreach ($receiveConnector in $allReceiveConnectors) {
                $connectorCustomObject += ExchangeConnectorObjectFactory -ConnectorObject $receiveConnector
            }

            foreach ($sendConnector in $allSendConnectors) {
                $connectorCustomObject += ExchangeConnectorObjectFactory -ConnectorObject $sendConnector
            }

            if (($null -ne $connectorCustomObject) -and
                ($null -ne $CertificateObject)) {
                $connectorReturnObject = FindMatchingExchangeCertificate `
                    -CertificateObject $CertificateObject `
                    -ConnectorCustomObject $connectorCustomObject
            } else {
                Write-Verbose "No connector object which can be processed was returned"
                $connectorReturnObject = $connectorCustomObject
            }
        } catch {
            Write-Verbose "Hit an exception while processing the Exchange Send-/Receive Connectors"
            Invoke-CatchActions
        }
    }
    end {
        return $connectorReturnObject
    }
}
