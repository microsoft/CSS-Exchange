# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
function Get-ExchangeServerCertificates {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    function NewCertificateExclusionEntry {
        [OutputType("System.Object")]
        param(
            [Parameter(Mandatory = $true)]
            [string]
            $IssuerOrSubjectPattern,
            [Parameter(Mandatory = $true)]
            [bool]
            $IsSelfSigned
        )

        return [PSCustomObject]@{
            IorSPattern  = $IssuerOrSubjectPattern
            IsSelfSigned = $IsSelfSigned
        }
    }

    function ShouldCertificateBeSkipped {
        [OutputType("System.Boolean")]
        param (
            [Parameter(Mandatory = $true)]
            [PSCustomObject]
            $Exclusions,
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $Certificate
        )

        $certificateMatch = $Exclusions | Where-Object {
            ((($Certificate.Subject -match $_.IorSPattern) -or
            ($Certificate.Issuer -match $_.IorSPattern)) -and
            ($Certificate.IsSelfSigned -eq $_.IsSelfSigned))
        } | Select-Object -First 1

        if ($null -ne $certificateMatch) {
            return $certificateMatch.IsSelfSigned -eq $Certificate.IsSelfSigned
        }
        return $false
    }

    try {
        Write-Verbose "Build certificate exclusion list"
        # Add the certificates that should be excluded from the Exchange certificate check (we don't return an object for them)
        # Exclude "MS-Organization-P2P-Access [YYYY]" certificate with one day lifetime on Azure hosted machines.
        # See: What are the MS-Organization-P2P-Access certificates present on our Windows 10/11 devices?
        # https://docs.microsoft.com/azure/active-directory/devices/faq
        # Exclude "DC=Windows Azure CRP Certificate Generator" (TenantEncryptionCertificate)
        # The certificates are built by the Azure fabric controller and passed to the Azure VM Agent.
        # If you stop and start the VM every day, the fabric controller might create a new certificate.
        # These certificates can be deleted. The Azure VM Agent re-creates certificates if needed.
        # https://docs.microsoft.com/azure/virtual-machines/extensions/features-windows
        $certificatesToExclude = @(
            NewCertificateExclusionEntry "CN=MS-Organization-P2P-Access \[[12][0-9]{3}\]$" $false
            NewCertificateExclusionEntry "DC=Windows Azure CRP Certificate Generator" $true
        )
        Write-Verbose "Trying to receive certificates from Exchange server: $($Server)"
        $exchangeServerCertificates = Get-ExchangeCertificate -Server $Server -ErrorAction Stop

        if ($null -ne $exchangeServerCertificates) {
            try {
                $authConfig = Get-AuthConfig -ErrorAction Stop
                $authConfigDetected = $true
            } catch {
                $authConfigDetected = $false
                Invoke-CatchActions
            }

            [array]$certObject = @()
            foreach ($cert in $exchangeServerCertificates) {
                try {
                    $certificateLifetime = ([System.Convert]::ToDateTime($cert.NotAfter, [System.Globalization.DateTimeFormatInfo]::InvariantInfo) - (Get-Date)).Days
                    $sanCertificateInfo = $false

                    $excludeCertificate = ShouldCertificateBeSkipped -Exclusions $certificatesToExclude -Certificate $cert

                    if ($excludeCertificate) {
                        Write-Verbose "Excluding certificate $($cert.Subject). Moving to next certificate"
                        continue
                    }

                    $currentErrors = $Error.Count
                    if ($null -ne $cert.DnsNameList -and
                        ($cert.DnsNameList).Count -gt 1) {
                        $sanCertificateInfo = $true
                        $certDnsNameList = $cert.DnsNameList
                    } elseif ($null -eq $cert.DnsNameList) {
                        $certDnsNameList = "None"
                    } else {
                        $certDnsNameList = $cert.DnsNameList
                    }
                    if ($currentErrors -lt $Error.Count) {
                        $i = 0
                        while ($i -lt ($Error.Count - $currentErrors)) {
                            Invoke-CatchActions $Error[$i]
                            $i++
                        }
                    }

                    if ($authConfigDetected) {
                        $isAuthConfigInfo = $false

                        if ($cert.Thumbprint -eq $authConfig.CurrentCertificateThumbprint) {
                            $isAuthConfigInfo = $true
                        }
                    } else {
                        $isAuthConfigInfo = "InvalidAuthConfig"
                    }

                    if ([String]::IsNullOrEmpty($cert.FriendlyName)) {
                        $certFriendlyName = ($certDnsNameList[0]).ToString()
                    } else {
                        $certFriendlyName = $cert.FriendlyName
                    }

                    if ([String]::IsNullOrEmpty($cert.Status)) {
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

                    $certInformationObj = New-Object PSCustomObject
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "Issuer" -Value $cert.Issuer
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "Subject" -Value $cert.Subject
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $certFriendlyName
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "Thumbprint" -Value $cert.Thumbprint
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "PublicKeySize" -Value $cert.PublicKey.Key.KeySize
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "SignatureAlgorithm" -Value $certSignatureAlgorithm
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "SignatureHashAlgorithm" -Value $certSignatureHashAlgorithm
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "SignatureHashAlgorithmSecure" -Value $certSignatureHashAlgorithmSecure
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "IsSanCertificate" -Value $sanCertificateInfo
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "Namespaces" -Value $certDnsNameList
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "Services" -Value $cert.Services
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "IsCurrentAuthConfigCertificate" -Value $isAuthConfigInfo
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "LifetimeInDays" -Value $certificateLifetime
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "Status" -Value $certStatus
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "CertificateObject" -Value $cert

                    $certObject += $certInformationObj
                } catch {
                    Write-Verbose "Unable to process certificate: $($cert.Thumbprint)"
                    Invoke-CatchActions
                }
            }
            Write-Verbose "Processed: $($certObject.Count) certificates"
            return $certObject
        } else {
            Write-Verbose "Failed to find any Exchange certificates"
            return $null
        }
    } catch {
        Write-Verbose "Failed to run Get-ExchangeCertificate. Error: $($Error[0].Exception)."
        Invoke-CatchActions
    }
}
