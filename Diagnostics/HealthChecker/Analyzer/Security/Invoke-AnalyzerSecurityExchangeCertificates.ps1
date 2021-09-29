# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Invoke-AnalyzerSecurityExchangeCertificates {
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

    foreach ($certificate in $exchangeInformation.ExchangeCertificates) {

        if ($certificate.LifetimeInDays -ge 60) {
            $displayColor = "Green"
        } elseif ($certificate.LifetimeInDays -ge 30) {
            $displayColor = "Yellow"
        } else {
            $displayColor = "Red"
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Certificate" `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 1

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "FriendlyName" -Details $certificate.FriendlyName `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 2

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Thumbprint" -Details $certificate.Thumbprint `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 2

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Lifetime in days" -Details $certificate.LifetimeInDays `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType $displayColor

        if ($certificate.LifetimeInDays -lt 0) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Certificate has expired" -Details $true `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red"
        } else {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Certificate has expired" -Details $false `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2
        }

        $certStatusWriteType = [string]::Empty

        if ($null -ne $certificate.Status) {
            Switch ($certificate.Status) {
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

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Certificate status" -Details $certificate.Status `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType $certStatusWriteType
        } else {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Certificate status" -Details "Unknown" `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow"
        }

        if ($certificate.PublicKeySize -lt 2048) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Key size" -Details $certificate.PublicKeySize `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red"

            $AnalyzeResults | Add-AnalyzedResultInformation -Details "It's recommended to use a key size of at least 2048 bit" `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red"
        } else {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Key size" -Details $certificate.PublicKeySize `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2
        }

        if ($certificate.SignatureHashAlgorithmSecure -eq 1) {
            $shaDisplayWriteType = "Yellow"
        } else {
            $shaDisplayWriteType = "Grey"
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Signature Algorithm" -Details $certificate.SignatureAlgorithm `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType $shaDisplayWriteType

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Signature Hash Algorithm" -Details $certificate.SignatureHashAlgorithm `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType $shaDisplayWriteType

        if ($shaDisplayWriteType -eq "Yellow") {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details "It's recommended to use a hash algorithm from the SHA-2 family `r`n`t`tMore information: https://aka.ms/HC-SSLBP" `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType $shaDisplayWriteType
        }

        if ($null -ne $certificate.Services) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Bound to services" -Details $certificate.Services `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2
        }

        if ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Current Auth Certificate" -Details $certificate.IsCurrentAuthConfigCertificate `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "SAN Certificate" -Details $certificate.IsSanCertificate `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 2

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Namespaces" `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 2

        foreach ($namespace in $certificate.Namespaces) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details $namespace `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 3
        }

        if ($certificate.IsCurrentAuthConfigCertificate -eq $true) {
            $currentAuthCertificate = $certificate
        }
    }

    if ($null -ne $currentAuthCertificate) {
        if ($currentAuthCertificate.LifetimeInDays -gt 0) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Valid Auth Certificate Found On Server" -Details $true `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 1 `
                -DisplayWriteType "Green"
        } else {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Valid Auth Certificate Found On Server" -Details $false `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 1 `
                -DisplayWriteType "Red"

            $renewExpiredAuthCert = "Auth Certificate has expired `r`n`t`tMore Information: https://aka.ms/HC-OAuthExpired"
            $AnalyzeResults | Add-AnalyzedResultInformation -Details $renewExpiredAuthCert `
                -DisplayGroupingKey $DisplayGroupingKey `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red"
        }
    } elseif ($exchangeInformation.BuildInformation.ServerRole -eq [HealthChecker.ExchangeServerRole]::Edge) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Valid Auth Certificate Found On Server" -Details $false `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 1

        $AnalyzeResults | Add-AnalyzedResultInformation -Details "We can't check for Auth Certificates on Edge Transport Servers" `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 2
    } else {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Valid Auth Certificate Found On Server" -Details $false `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 1 `
            -DisplayWriteType "Red"

        $createNewAuthCert = "No valid Auth Certificate found. This may cause several problems. `r`n`t`tMore Information: https://aka.ms/HC-FindOAuthHybrid"
        $AnalyzeResults | Add-AnalyzedResultInformation -Details $createNewAuthCert `
            -DisplayGroupingKey $DisplayGroupingKey `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType "Red"
    }
}
