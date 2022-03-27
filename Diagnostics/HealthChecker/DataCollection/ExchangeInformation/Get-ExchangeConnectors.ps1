# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Invoke-CatchActions.ps1
Function Get-ExchangeConnectors {
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
        Write-Verbose "Passed - Computername: $ComputerName"
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
                Identity                 = $ConnectorObject.Identity
                Name                     = $ConnectorObject.Name
                Enabled                  = $ConnectorObject.Enabled
                CloudEnabled             = $false
                ConnectorType            = "N/A"
                TransportRole            = "N/A"
                CertificateMatchDetected = $false
                GoodTlsCertificateSyntax = $false
                TlsCertificateName       = "N/A"
                TlsCertificateNameStatus = "N/A"
                TlsCertificateSet        = $false
                TlsAuthLevel             = "N/A"
                CertificateInformation   = $null
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
                if ($null -ne $ConnectorObject.TlsAuthLevel) {
                    $exchangeFactoryConnectorReturnObject.TlsAuthLevel = $ConnectorObject.TlsAuthLevel
                }
            }

            if ($null -ne $ConnectorObject.TlsCertificateName) {
                Write-Verbose "TlsCertificateName is configured on this connector"
                $exchangeFactoryConnectorReturnObject.TlsCertificateSet = $true
                $exchangeFactoryConnectorReturnObject.TlsCertificateName = ($ConnectorObject.TlsCertificateName).ToString()
            } else {
                Write-Verbose "TlsCertificateName is not configured on this connector"
                $exchangeFactoryConnectorReturnObject.TlsCertificateNameStatus = "TlsCertificateNameEmpty"
            }

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
                    $issuerIndex = $TlsCertificateName.IndexOf("CN=", [System.StringComparison]::OrdinalIgnoreCase)
                    $subjectIndex = $TlsCertificateName.LastIndexOf("CN=", [System.StringComparison]::OrdinalIgnoreCase)

                    Write-Verbose "TlsCertificateName with bad syntax was passed"
                }

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

                    if ($ConnectorObject.TlsCertificateName -ne "N/A") {
                        $connectorTlsCertificateNormalizedObject = NormalizeTlsCertificateName `
                            -TlsCertificateName $ConnectorObject.TlsCertificateName

                        if ($null -eq $connectorTlsCertificateNormalizedObject) {
                            Write-Verbose "Unable to normalize TlsCertificateName - could be caused by an invalid TlsCertificateName configuration"
                            $connectorObject.TlsCertificateNameStatus = "TlsCertificateNameSyntaxInvalid"
                        } else {
                            if ($connectorTlsCertificateNormalizedObject.GoodSyntax) {
                                $connectorObject.GoodTlsCertificateSyntax = $connectorTlsCertificateNormalizedObject.GoodSyntax
                            }

                            $certificateMatches = 0
                            $certificateInformation = @{}
                            foreach ($certificate in $CertificateObject) {
                                if (($certificate.Issuer -eq $connectorTlsCertificateNormalizedObject.Issuer) -and
                                    ($certificate.Subject -eq $connectorTlsCertificateNormalizedObject.Subject)) {
                                    Write-Verbose ("Certificate: '{0}' matches Connectors: '{1}' TlsCertificateName: '{2}'" -f $certificate.Thumbprint, $connectorObject.Identity, $connectorObject.TlsCertificateName)
                                    $connectorObject.CertificateMatchDetected = $true
                                    $connectorObject.TlsCertificateNameStatus = "TlsCertificateMatch"
                                    $certificateInformation.Add($certificate.Thumbprint, $certificate.LifetimeInDays)

                                    $certificateMatches++
                                }
                            }

                            if ($certificateMatches -eq 0) {
                                Write-Verbose "No matching certificate was found on the server"
                                $connectorObject.TlsCertificateNameStatus = "TlsCertificateNotFound"
                            } else {
                                Write-Verbose ("We found: '{0}' matching certificates on the server" -f $certificateMatches)
                                $connectorObject.CertificateInformation = $certificateInformation
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
