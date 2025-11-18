# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ExchangeConnectorCustomObject {
    [CmdletBinding()]
    param(
        [object[]]$Connector,

        [object[]]$Certificate
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $currentTime = Get-Date
    }
    process {
        foreach ($currentConnector in $Connector) {

            if (@($currentConnector.PSObject.Properties).Count -eq 0) {
                continue
            }

            if ($null -ne $currentConnector.Server) {
                $connectorType = "Receive"
                $cloudEnabled = -not ([System.String]::IsNullOrEmpty($currentConnector.TlsDomainCapabilities))
            } else {
                $connectorType = "Send"
                $cloudEnabled = $currentConnector.CloudServicesMailEnabled
            }

            $tlsCertificateName = $null
            $certificateMatchDetected = $false
            $goodTlsCertificateSyntax = $false
            $tlsCertificateNameStatus = "TlsCertificateNameEmpty"
            $certificateLifetimeInformation = @{}
            $tlsAuthLevel = $null

            if ($null -ne $currentConnector.TlsCertificateName) {

                try {
                    $tlsCertificateName = $currentConnector.TlsCertificateName.ToString()
                    # RegEx to match the recommended value which is "<I>X.500Issuer<S>X.500Subject"
                    $expectedCertificateNameDetection = $tlsCertificateName -match "(<i>).*(<s>).*"
                    $padding = 0

                    if ($expectedCertificateNameDetection) {
                        $issuerIndex = $tlsCertificateName.IndexOf("<I>", [System.StringComparison]::OrdinalIgnoreCase)
                        $subjectIndex = $tlsCertificateName.IndexOf("<S>", [System.StringComparison]::OrdinalIgnoreCase)
                        $padding = 3
                        $goodTlsCertificateSyntax = $true -and $null -ne $Certificate
                    } else {
                        # Failsafe to detect cases where <I> and <S> are missing in TlsCertificateName
                        $issuerIndex = $tlsCertificateName.IndexOf("CN=", [System.StringComparison]::OrdinalIgnoreCase)
                        $subjectIndex = $tlsCertificateName.LastIndexOf("CN=", [System.StringComparison]::OrdinalIgnoreCase)
                    }

                    $tlsCertificateNameStatus = "TlsCertificateNameSyntaxInvalid"
                    $issuer = $null
                    $subject = $null
                    $certificateMatches = 0
                    if ($issuerIndex -ne -1 -and
                        $subjectIndex -ne -1) {
                        $issuer = $tlsCertificateName.Substring(($issuerIndex + $padding), ($subjectIndex - $padding))
                        $subject = $tlsCertificateName.Substring(($subjectIndex + $padding))

                        foreach ($cert in $Certificate) {
                            if ($cert.Issuer -eq $issuer -and $cert.Subject -eq $subject) {
                                Write-Verbose "Certificate: '$($cert.Thumbprint)' matches Connectors: '$($currentConnector.Identity)' TlsCertificateName: '$($currentConnector.TlsCertificateName)'"
                                $certificateMatchDetected = $true
                                $tlsCertificateNameStatus = "TlsCertificateMatch"
                                $certificateMatches++
                                $lifeTime = ([System.Convert]::ToDateTime($cert.NotAfter, [System.Globalization.DateTimeFormatInfo]::InvariantInfo) - $currentTime).Days
                                $certificateLifetimeInformation.Add($cert.Thumbprint, $lifeTime)
                            }
                        }

                        if ($certificateMatches -eq 0) {
                            Write-Verbose "No matching certificate was found on the server"
                            $tlsCertificateNameStatus = "TlsCertificateNotFound"
                        } else {
                            Write-Verbose "We found $certificateMatches matching certificates on the server"
                        }
                    }
                } catch {
                    Write-Verbose "We hit an exception while parsing the TlsCertificateName string: '$tlsCertificateName'. Inner Exception $_"
                    Invoke-CatchActions
                }
            }

            if ($null -ne $currentConnector.TlsAuthLevel) {
                $tlsAuthLevel = $currentConnector.TlsAuthLevel.ToString()
            }

            [PSCustomObject]@{
                Identity           = $currentConnector.Identity
                Name               = $currentConnector.Name
                Fqdn               = $currentConnector.Fqdn
                Enabled            = $currentConnector.Enabled
                CloudEnabled       = $cloudEnabled
                ConnectorType      = $connectorType
                TransportRole      = $currentConnector.TransportRole
                SmartHosts         = $currentConnector.SmartHosts
                AddressSpaces      = $currentConnector.AddressSpaces
                RequireTls         = $currentConnector.RequireTls
                TlsAuthLevel       = $tlsAuthLevel
                TlsDomain          = $currentConnector.TlsDomain
                CertificateDetails = [PSCustomObject]@{
                    CertificateMatchDetected = $certificateMatchDetected
                    GoodTlsCertificateSyntax = $goodTlsCertificateSyntax
                    TlsCertificateName       = $tlsCertificateName
                    TlsCertificateNameStatus = $tlsCertificateNameStatus
                    TlsCertificateSet        = $null -ne $tlsCertificateName
                    CertificateLifetimeInfo  = $certificateLifetimeInformation
                }
            }
        }
    }
}
