# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ExchangeCertificateCustomObject {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [object[]]$Certificate,

        [object]$InternalTransportCertificate,

        [object]$AuthConfig
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $currentTime = Get-Date
    }
    process {
        foreach ($cert in $Certificate) {
            try {
                $certificateLifetime = ([System.Convert]::ToDateTime($cert.NotAfter, [System.Globalization.DateTimeFormatInfo]::InvariantInfo) - $currentTime).Days
                $certFriendlyName = $cert.FriendlyName
                $certDnsNameList = $cert.DnsNameList

                if ($null -eq $cert.DnsNameList) {
                    $certDnsNameList = "None"
                }

                if ($null -ne $AuthConfig) {
                    $isAuthConfigInfo = $cert.Thumbprint -eq $AuthConfig.CurrentCertificateThumbprint
                    $isNextAuthCertificate = $cert.Thumbprint -eq $AuthConfig.NextCertificateThumbprint
                } else {
                    $isAuthConfigInfo = "InvalidAuthConfig"
                    $isNextAuthCertificate = "InvalidAuthConfig"
                }

                if ([string]::IsNullOrEmpty($certFriendlyName)) {
                    $certFriendlyName = ($certDnsNameList[0]).ToString()
                }

                if ([string]::IsNullOrEmpty($cert.Status)) {
                    $certStatus = "Unknown"
                } else {
                    $certStatus = ($cert.Status).ToString()
                }

                if ([String]::IsNullOrEmpty($cert.SignatureAlgorithm.FriendlyName)) {
                    $certSignatureAlgorithm = "Unknown"
                    $certSignatureHashAlgorithm = "Unknown"
                    $certSignatureHashAlgorithmSecure = 0
                } else {
                    $certSignatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
                    <#
                        OID Table
                        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad
                        SignatureHashAlgorithmSecure = Unknown 0
                        SignatureHashAlgorithmSecure = Insecure/Weak 1
                        SignatureHashAlgorithmSecure = Secure 2
                    #>
                    switch ($cert.SignatureAlgorithm.Value) {
                        "1.2.840.113549.1.1.5" { $certSignatureHashAlgorithm = "sha1"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.2.840.113549.1.1.4" { $certSignatureHashAlgorithm = "md5"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.2.840.10040.4.3" { $certSignatureHashAlgorithm = "sha1"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.3.14.3.2.29" { $certSignatureHashAlgorithm = "sha1"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.3.14.3.2.15" { $certSignatureHashAlgorithm = "sha1"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.3.14.3.2.3" { $certSignatureHashAlgorithm = "md5"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.2.840.113549.1.1.2" { $certSignatureHashAlgorithm = "md2"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.2.840.113549.1.1.3" { $certSignatureHashAlgorithm = "md4"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.3.14.3.2.2" { $certSignatureHashAlgorithm = "md4"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.3.14.3.2.4" { $certSignatureHashAlgorithm = "md4"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.3.14.7.2.3.1" { $certSignatureHashAlgorithm = "md2"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.3.14.3.2.13" { $certSignatureHashAlgorithm = "sha1"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.3.14.3.2.27" { $certSignatureHashAlgorithm = "sha1"; $certSignatureHashAlgorithmSecure = 1 }
                        "2.16.840.1.101.2.1.1.19" { $certSignatureHashAlgorithm = "mosaicSignature"; $certSignatureHashAlgorithmSecure = 0 }
                        "1.3.14.3.2.26" { $certSignatureHashAlgorithm = "sha1"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.2.840.113549.2.5" { $certSignatureHashAlgorithm = "md5"; $certSignatureHashAlgorithmSecure = 1 }
                        "2.16.840.1.101.3.4.2.1" { $certSignatureHashAlgorithm = "sha256"; $certSignatureHashAlgorithmSecure = 2 }
                        "2.16.840.1.101.3.4.2.2" { $certSignatureHashAlgorithm = "sha384"; $certSignatureHashAlgorithmSecure = 2 }
                        "2.16.840.1.101.3.4.2.3" { $certSignatureHashAlgorithm = "sha512"; $certSignatureHashAlgorithmSecure = 2 }
                        "1.2.840.113549.1.1.11" { $certSignatureHashAlgorithm = "sha256"; $certSignatureHashAlgorithmSecure = 2 }
                        "1.2.840.113549.1.1.12" { $certSignatureHashAlgorithm = "sha384"; $certSignatureHashAlgorithmSecure = 2 }
                        "1.2.840.113549.1.1.13" { $certSignatureHashAlgorithm = "sha512"; $certSignatureHashAlgorithmSecure = 2 }
                        "1.2.840.113549.1.1.10" { $certSignatureHashAlgorithm = "rsassa-pss"; $certSignatureHashAlgorithmSecure = 2 }
                        "1.2.840.10045.4.1" { $certSignatureHashAlgorithm = "sha1"; $certSignatureHashAlgorithmSecure = 1 }
                        "1.2.840.10045.4.3.2" { $certSignatureHashAlgorithm = "sha256"; $certSignatureHashAlgorithmSecure = 2 }
                        "1.2.840.10045.4.3.3" { $certSignatureHashAlgorithm = "sha384"; $certSignatureHashAlgorithmSecure = 2 }
                        "1.2.840.10045.4.3.4" { $certSignatureHashAlgorithm = "sha512"; $certSignatureHashAlgorithmSecure = 2 }
                        "1.2.840.10045.4.3" { $certSignatureHashAlgorithm = "sha256"; $certSignatureHashAlgorithmSecure = 2 }
                        default { $certSignatureHashAlgorithm = "Unknown"; $certSignatureHashAlgorithmSecure = 0 }
                    }
                }

                # Place it back onto the pipeline
                [PSCustomObject]@{
                    Issuer                         = $cert.Issuer
                    Subject                        = $cert.Subject
                    FriendlyName                   = $certFriendlyName
                    Thumbprint                     = $cert.Thumbprint
                    PublicKeySize                  = $cert.PublicKey.Key.KeySize
                    IsEccCertificate               = $cert.PublicKey.Oid.Value -eq "1.2.840.10045.2.1" # WellKnownOid for ECC
                    SignatureAlgorithm             = $certSignatureAlgorithm
                    SignatureHashAlgorithm         = $certSignatureHashAlgorithm
                    SignatureHashAlgorithmSecure   = $certSignatureHashAlgorithmSecure
                    IsSanCertificate               = $null -ne $cert.DnsNameList -and ($cert.DnsNameList).Count -gt 1
                    Namespaces                     = $certDnsNameList
                    Services                       = $cert.Services
                    IsInternalTransportCertificate = $null -ne $InternalTransportCertificate -and $cert.Thumbprint -eq $InternalTransportCertificate.Thumbprint
                    IsCurrentAuthConfigCertificate = $isAuthConfigInfo
                    IsNextAuthConfigCertificate    = $isNextAuthCertificate
                    SetAsActiveAuthCertificateOn   = if ($isNextAuthCertificate) { $authConfig.NextCertificateEffectiveDate } else { $null }
                    LifetimeInDays                 = $certificateLifetime
                    Status                         = $certStatus
                    CertificateObject              = $cert
                }
            } catch {
                Write-Verbose "Unable to process certificate: $($cert.Thumbprint)"
                Invoke-CatchActions
            }
        }
    }
}
