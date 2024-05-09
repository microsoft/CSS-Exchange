# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-AnalyzerSecurityExchangeCertificates {
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
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }

    foreach ($certificate in $exchangeInformation.ExchangeCertificates) {

        if ($certificate.LifetimeInDays -ge 60) {
            $displayColor = "Green"
        } elseif ($certificate.LifetimeInDays -ge 30) {
            $displayColor = "Yellow"
        } else {
            $displayColor = "Red"
        }

        $params = $baseParams + @{
            Name                   = "Certificate"
            DisplayCustomTabNumber = 1
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Name                   = "FriendlyName"
            Details                = $certificate.FriendlyName
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Name                   = "Thumbprint"
            Details                = $certificate.Thumbprint
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Name                   = "Lifetime in days"
            Details                = $certificate.LifetimeInDays
            DisplayCustomTabNumber = 2
            DisplayWriteType       = $displayColor
        }
        Add-AnalyzedResultInformation @params

        $displayValue = $false
        $displayWriteType = "Grey"
        if ($certificate.LifetimeInDays -lt 0) {
            $displayValue = $true
            $displayWriteType = "Red"
        }

        $params = $baseParams + @{
            Name                   = "Certificate has expired"
            Details                = $displayValue
            DisplayWriteType       = $displayWriteType
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params

        $certStatusWriteType = [string]::Empty

        if ($null -ne $certificate.Status) {
            switch ($certificate.Status) {
                ("Unknown") { $certStatusWriteType = "Yellow" }
                ("Valid") { $certStatusWriteType = "Grey" }
                ("Revoked") { $certStatusWriteType = "Red" }
                ("DateInvalid") { $certStatusWriteType = "Red" }
                ("Untrusted") { $certStatusWriteType = "Yellow" }
                ("Invalid") { $certStatusWriteType = "Red" }
                ("RevocationCheckFailure") { $certStatusWriteType = "Yellow" }
                ("PendingRequest") { $certStatusWriteType = "Yellow" }
                default { $certStatusWriteType = "Yellow" }
            }

            $params = $baseParams + @{
                Name                   = "Certificate status"
                Details                = $certificate.Status
                DisplayCustomTabNumber = 2
                DisplayWriteType       = $certStatusWriteType
            }
            Add-AnalyzedResultInformation @params
        } else {
            $params = $baseParams + @{
                Name                   = "Certificate status"
                Details                = "Unknown"
                DisplayWriteType       = "Yellow"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        # We show the 'Key Size' if a certificate is RSA or DSA based but not for ECC certificates where it would be displayed with a value of 0
        # More information: https://stackoverflow.com/questions/32873851/load-a-certificate-using-x509certificate2-with-ecc-public-key
        if ($certificate.PublicKeySize -lt 2048 -and
            -not($certificate.IsEccCertificate)) {
            $params = $baseParams + @{
                Name                   = "Key size"
                Details                = $certificate.PublicKeySize
                DisplayWriteType       = "Red"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Details                = "It's recommended to use a key size of at least 2048 bit"
                DisplayWriteType       = "Red"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        } elseif (-not($certificate.IsEccCertificate)) {
            $params = $baseParams + @{
                Name                   = "Key size"
                Details                = $certificate.PublicKeySize
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        $params = $baseParams + @{
            Name                   = "ECC Certificate"
            Details                = $certificate.IsEccCertificate
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params

        if ($certificate.SignatureHashAlgorithmSecure -eq 1) {
            $shaDisplayWriteType = "Yellow"
        } else {
            $shaDisplayWriteType = "Grey"
        }

        $params = $baseParams + @{
            Name                   = "Signature Algorithm"
            Details                = $certificate.SignatureAlgorithm
            DisplayWriteType       = $shaDisplayWriteType
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Name                   = "Signature Hash Algorithm"
            Details                = $certificate.SignatureHashAlgorithm
            DisplayWriteType       = $shaDisplayWriteType
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params

        if ($shaDisplayWriteType -eq "Yellow") {
            $params = $baseParams + @{
                Details                = "It's recommended to use a hash algorithm from the SHA-2 family `r`n`t`tMore information: https://aka.ms/HC-SSLBP"
                DisplayWriteType       = $shaDisplayWriteType
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        if ($null -ne $certificate.Services) {
            $params = $baseParams + @{
                Name                   = "Bound to services"
                Details                = $certificate.Services
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        if ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false) {
            $params = $baseParams + @{
                Name                   = "Internal Transport Certificate"
                Details                = $certificate.IsInternalTransportCertificate
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Name                   = "Current Auth Certificate"
                Details                = $certificate.IsCurrentAuthConfigCertificate
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Name                   = "Next Auth Certificate"
                Details                = $certificate.IsNextAuthConfigCertificate
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        $params = $baseParams + @{
            Name                   = "SAN Certificate"
            Details                = $certificate.IsSanCertificate
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Name                   = "Namespaces"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params

        foreach ($namespace in $certificate.Namespaces) {
            $params = $baseParams + @{
                Details                = $namespace
                DisplayCustomTabNumber = 3
            }
            Add-AnalyzedResultInformation @params
        }

        if ($certificate.IsInternalTransportCertificate) {
            $internalTransportCertificate = $certificate
        }

        if ($certificate.IsCurrentAuthConfigCertificate -eq $true) {
            $currentAuthCertificate = $certificate
        } elseif ($certificate.IsNextAuthConfigCertificate -eq $true) {
            $nextAuthCertificate = $certificate
            $nextAuthCertificateEffectiveDate = $certificate.SetAsActiveAuthCertificateOn
        }
    }

    if ($null -ne $internalTransportCertificate) {
        if ($internalTransportCertificate.LifetimeInDays -gt 0) {
            $params = $baseParams + @{
                Name                   = "Valid Internal Transport Certificate Found On Server"
                Details                = $true
                DisplayWriteType       = "Green"
                DisplayCustomTabNumber = 1
            }
            Add-AnalyzedResultInformation @params
        } else {
            $params = $baseParams + @{
                Name                   = "Valid Internal Transport Certificate Found On Server"
                Details                = $false
                DisplayWriteType       = "Red"
                DisplayCustomTabNumber = 1
            }
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Details                = "Internal Transport Certificate has expired `r`n`t`tMore Information: https://aka.ms/HC-InternalTransportCertificate"
                DisplayWriteType       = "Red"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }
    } elseif ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $true) {
        $params = $baseParams + @{
            Name                   = "Valid Internal Transport Certificate Found On Server"
            Details                = $false
            DisplayCustomTabNumber = 1
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Details                = "We can't check for Internal Transport Certificate on Edge Transport Servers"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    } else {
        $params = $baseParams + @{
            Name                   = "Valid Internal Transport Certificate Found On Server"
            Details                = $false
            DisplayWriteType       = "Red"
            DisplayCustomTabNumber = 1
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Details                = "No Internal Transport Certificate found. This may cause several problems. `r`n`t`tMore Information: https://aka.ms/HC-InternalTransportCertificate"
            DisplayWriteType       = "Red"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }

    if ($null -ne $currentAuthCertificate) {
        if ($currentAuthCertificate.LifetimeInDays -gt 0) {
            $params = $baseParams + @{
                Name                   = "Valid Auth Certificate Found On Server"
                Details                = $true
                DisplayWriteType       = "Green"
                DisplayCustomTabNumber = 1
            }
            Add-AnalyzedResultInformation @params
        } else {
            $params = $baseParams + @{
                Name                   = "Valid Auth Certificate Found On Server"
                Details                = $false
                DisplayWriteType       = "Red"
                DisplayCustomTabNumber = 1
            }
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Details                = "Auth Certificate has expired `r`n`t`tMore Information: https://aka.ms/HC-OAuthExpired"
                DisplayWriteType       = "Red"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        if ($null -ne $nextAuthCertificate) {
            $params = $baseParams + @{
                Name                   = "Next Auth Certificate Staged For Rotation"
                Details                = $true
                DisplayCustomTabNumber = 1
            }
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Name                   = "Next Auth Certificate Effective Date"
                Details                = $nextAuthCertificateEffectiveDate
                DisplayCustomTabNumber = 1
            }
            Add-AnalyzedResultInformation @params
        }
    } elseif ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $true) {
        $params = $baseParams + @{
            Name                   = "Valid Auth Certificate Found On Server"
            Details                = $false
            DisplayCustomTabNumber = 1
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Details                = "We can't check for Auth Certificates on Edge Transport Servers"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    } else {
        $params = $baseParams + @{
            Name                   = "Valid Auth Certificate Found On Server"
            Details                = $false
            DisplayWriteType       = "Red"
            DisplayCustomTabNumber = 1
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Details                = "No valid Auth Certificate found. This may cause several problems. `r`n`t`tMore Information: https://aka.ms/HC-FindOAuthHybrid"
            DisplayWriteType       = "Red"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }
}
