# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Confirm-Administrator.ps1

function New-ExchangeSelfSignedCertificate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Certificate creation is intentional and controlled')]
    [CmdletBinding()]
    param(
        [ValidateScript({ $_.Length -lt 64 })]
        [string]$SubjectName = $env:COMPUTERNAME,

        [string[]]$DomainName,

        [string]$FriendlyName = "Microsoft Exchange",

        [ValidateScript({ $_ -gt 0 })]
        [int]$LifetimeInDays = 365,

        [ValidateSet("RSA", "ECC")]
        [string]$AlgorithmType = "RSA",

        [bool]$UseRSACryptoServiceProvider = $false,

        [ValidateSet(1024, 2048, 4096)]
        [int]$KeySize = 2048,

        [ValidateSet("nistP256", "nistP384", "nistP521")]
        [string]$CurveName = "nistP384",

        [ValidateSet("SHA256", "SHA384", "SHA512")]
        [string]$HashAlgorithm = "SHA256",

        [switch]$AddSubjectKeyIdentifier,

        [switch]$TrustCertificate
    )

    <#
        Generates a self-signed certificate for Exchange with support for RSA/ECC, SANs, and optional import to trusted root store.
        This function supports both legacy CSP and modern CNG key generation models. While CSP (Cryptographic Service Provider) is compatible with older systems,
        CNG (Cryptography Next Generation) offers enhanced algorithm support like ECC and better key storage flexibility.
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        if (-not(Confirm-Administrator)) {
            Write-Host "Insufficient permissions to perform the certificate operation" -ForegroundColor Red

            return
        }
    } process {
        # Generate the X500DistinguishedName for the certificate
        $subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new(
            $(if ($SubjectName.IndexOf("cn=") -eq -1) { "cn=$SubjectName" } else { $SubjectName }),
            [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseUTF8Encoding
        )
        Write-Verbose "Subject: $($subject.Name)"

        # Assign UTF-8 encoded FriendlyName to support non-ASCII characters in multilingual environments
        $utf8FriendlyName = [System.Text.Encoding]::UTF8.GetString([System.Text.Encoding]::UTF8.GetBytes($FriendlyName))
        Write-Verbose "FriendlyName: $utf8FriendlyName"

        # Convert the user-specified hash algorithm string into a HashAlgorithmName object required by the CertificateRequest constructor for digital signature generation
        $hashAlgorithmName = [System.Security.Cryptography.HashAlgorithmName]::new($HashAlgorithm)
        Write-Verbose "HashAlgorithm: $($hashAlgorithmName.Name)"

        # Generate a unique name for the key container
        $keyContainerName = "MonitorExchangeAuthCertificate_$((New-Guid).Guid.ToString())"
        Write-Verbose "Key container name is: $keyContainerName"

        if ($AlgorithmType -eq "ECC") {
            Write-Verbose "ECC-based certificate will be created"

            # Generate the public/private ECC key pair
            $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
            Write-Verbose "Public/private key pair SignatureAlgorithm: $($ecdsa.SignatureAlgorithm) KeySize: $($ecdsa.KeySize)"

            $curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName($CurveName)
            Write-Verbose "ECC Curve: $($curve.Oid.FriendlyName)"

            try {
                Write-Verbose "Generating key by using $CurveName curve"
                $ecdsa.GenerateKey($curve)

                # Generate the ECC CertificateRequest
                Write-Verbose "Generating the ECC CertificateRequest..."

                # Initializes a new instance of the CertificateRequest class using the specified subject name, ECDSA key, and hash algorithm
                $certificateRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    $subject,
                    $ecdsa,
                    $hashAlgorithmName
                )
            } catch {
                Write-Host "Something went wrong while creating the CertificateRequest. Exception $_" -ForegroundColor Red

                return
            }
        } else {
            Write-Verbose "RSA-based certificate will be created..."

            if ($UseRSACryptoServiceProvider) {
                Write-Verbose "Initializing the CspParameters..."

                # Initializes a new instance of CspParameters
                $cspParams = [System.Security.Cryptography.CspParameters]::new()

                # Parameters that are passed to the Cryptographic Service Provider (CSP)
                #cspell:disable
                $cspParams.Flags = [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
                $cspParams.ProviderType = 24 # PROV_RSA_FULL
                $cspParams.KeyNumber = 1 # AT_KEYEXCHANGE
                $cspParams.KeyContainerName = $keyContainerName
                #cspell:enable

                Write-Verbose "Generating the public/private RSA key pair..."
                # Initializes a new instance of RSACryptoServiceProvider to generate a new key pair, pass KeySize and CspParameters
                $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(
                    $KeySize,
                    $cspParams
                )

                # Ensure the RSA private key persists beyond the current session (stores the key in the cryptographic service provider container)
                $rsa.PersistKeyInCsp = $true
            } else {
                Write-Verbose "Initializing the CngKeyCreationParameters..."

                # Initializes a new instance of CngKeyCreationParameters
                $cngKeyCreationParameters = [System.Security.Cryptography.CngKeyCreationParameters]::new()

                # Parameters that are passed to the Cryptography Next Generation (CNG)
                $cngKeyCreationParameters.Provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
                $cngKeyCreationParameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::OverwriteExistingKey
                $cngKeyCreationParameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowExport

                # Add RSA-specific CngProperty for the key size
                Write-Verbose "RSA key size: $KeySize"
                $cngKeyLengthProperty = [System.Security.Cryptography.CngProperty]::new(
                    "Length", # Property name
                    [BitConverter]::GetBytes($KeySize), # Property value bytes
                    [System.Security.Cryptography.CngPropertyOptions]::None
                )

                Write-Verbose "Adding RSA-specific KeyLength property"
                $cngKeyCreationParameters.Parameters.Add($cngKeyLengthProperty)

                # Create a new RSA key pair and store it in the CNG key store with the specified parameters
                Write-Verbose "Creating the RSA-based CngKey..."
                $cngKey = [System.Security.Cryptography.CngKey]::Create(
                    [System.Security.Cryptography.CngAlgorithm]::Rsa, # Specifies RSA algorithm
                    $keyContainerName, # Name of the key container
                    $cngKeyCreationParameters # Creation options
                )

                # Wrap the existing CNG key in an RSACng object for cryptographic operations
                Write-Verbose "Generating the public/private RSA key pair..."
                $rsa = [System.Security.Cryptography.RSACng]::new($cngKey)
            }

            try {
                Write-Verbose "Generating the RSA CertificateRequest..."

                # Initializes a new instance of the CertificateRequest class using the specified subject name, RSA key, hash algorithm, and using PKCS #1 v1.5 padding
                $certificateRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    $subject,
                    $rsa,
                    $hashAlgorithmName,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
                )
            } catch {
                Write-Host "Something went wrong while creating the CertificateRequest. Exception $_" -ForegroundColor Red

                return
            }
        }

        # Add SubjectAlternativeNames if some were passed via DomainName parameter
        if ($DomainName.Count -gt 0) {
            Write-Verbose "DomainNames that will be added to the certificate: $([System.String]::Join(", ", $DomainName))"

            $sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()

            foreach ($name in $DomainName) {
                Write-Verbose "Adding DnsName: $name"
                $sanBuilder.AddDnsName($name)
            }

            $certificateRequest.CertificateExtensions.Add(
                $sanBuilder.Build($true)
            )
        }

        try {
            Write-Verbose "Processing certificate extensions..."

            # Specify the X509KeyUsageExtension
            $keyUsageExtensions = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor # DigitalSignature: The certificate's public key can be used to verify digital signatures
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment, # KeyEncipherment: The public key can also be used to encrypt symmetric keys
                $true # critical: marked as critical
            )

            $certificateRequest.CertificateExtensions.Add($keyUsageExtensions)

            # Specify the X509EnhancedKeyUsageExtension
            $oids = [System.Security.Cryptography.OidCollection]::new()
            $oids.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1")) | Out-Null  # Server Authentication OID

            $extendedKeyUsageExtension = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
                $oids, # OID for Server Authentication
                $false # not critical: marked as not critical
            )

            $certificateRequest.CertificateExtensions.Add($extendedKeyUsageExtension)

            # Specify the X509BasicConstraintsExtension
            $basicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
                $false, # certificateAuthority: this is not a CA
                $false, # hasPathLengthConstraint: we don't want to enforce one
                0, # pathLengthConstraint: ignored since hasPathLengthConstraint is false
                $true # critical: marked as critical
            )

            $certificateRequest.CertificateExtensions.Add($basicConstraints)

            # Add the Subject Key Identifier (SKI) as a non-critical extensions if AddSubjectKeyIdentifier parameter was set to true
            if ($AddSubjectKeyIdentifier) {
                $subjectKeyIdentifier = [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new(
                    $certificateRequest.PublicKey,
                    $false
                )

                $certificateRequest.CertificateExtensions.Add($subjectKeyIdentifier)
            }
        } catch {
            Write-Host "Something went wrong while processing certificate extensions. Exception: $_" -ForegroundColor Red

            return
        }

        try {
            # Create the self-signed certificate
            Write-Verbose "Creating the self-signed certificate with a lifetime of $LifetimeInDays days"

            $notBefore = [System.DateTimeOffset]::UtcNow
            $notAfter = $notBefore.AddDays($LifetimeInDays)
            $certificate = $certificateRequest.CreateSelfSigned(
                $notBefore,
                $notAfter
            )

            if (-not([System.String]::IsNullOrEmpty($utf8FriendlyName))) {
                $certificate.FriendlyName = $utf8FriendlyName
            }

            $certificateThumbprint = $certificate.Thumbprint

            Write-Verbose "Certificate was created successfully - Thumbprint: $certificateThumbprint Subject: $($subject.Name)"
        } catch {
            Write-Host "Something went wrong while creating the self-signed certificate. Exception: $_" -ForegroundColor Red

            return
        }

        try {
            # To make the certificate and its private key exportable, we must export and re-import it with the Exportable flag
            Write-Verbose "Exporting and re-importing certificate with Exportable flag to make it exportable..."

            $pfxBytes = $certificate.Export(
                [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx
            )
            $certificateWithExportableKey = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $certificateWithExportableKey.Import(
                $pfxBytes,
                $null,
                ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet)
            )

            # Add it to the LocalMachine store
            Write-Verbose "Adding the certificate to the My/LocalMachine certificate store..."

            $machineStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                "My",
                "LocalMachine"
            )
            $machineStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $machineStore.Add($certificateWithExportableKey)
            $machineStore.Close()

            # Add the certificate to the Trusted Root Certification Authorities if explicitly specified via TrustCertificate parameter
            if ($TrustCertificate) {
                Write-Verbose "Adding the certificate to the Root/LocalMachine store to make it a trusted certificate..."

                $trustedRootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                    "Root",
                    "LocalMachine"
                )
                $trustedRootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $trustedRootStore.Add($certificateWithExportableKey)
                $trustedRootStore.Close()
            }
        } catch {
            Write-Host "Something went wrong while adding the certificate to the store. Exception: $_" -ForegroundColor Red

            return
        } finally {
            if ($null -ne $pfxBytes) {
                Write-Verbose "Overwriting temporary .pfx with random data..."

                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($pfxBytes)
                $pfxBytes = $null
            }

            if ($null -ne $certificateWithExportableKey) {
                Write-Verbose "Disposing certificate from memory..."

                $certificateWithExportableKey.Dispose()
            }
        }
    } end {
        if ($null -ne $certificate) {
            Write-Verbose "Disposing X509Certificate2 object..."
            # Call Dispose() to release all resources used by the X509Certificate object
            $certificate.Dispose()
        }

        if ($null -ne $rsa) {
            Write-Verbose "Clearing and disposing RSA key object..."
            # Call Clear() to release resources and delete the key from the container
            $rsa.Clear()
        }

        if ($null -ne $ecdsa) {
            # Call Clear() to release resources and delete the key from the container
            Write-Verbose "Clearing and disposing ECDsa key object..."
            $ecdsa.Clear()
        }

        if ($null -ne $cngKey) {
            # Call Delete() to remove the key that is associated with the object
            Write-Verbose "Deleting CngKey object..."
            $cngKey.Delete()
        }

        return [PSCustomObject]@{
            Subject    = $subject.Name
            Thumbprint = $certificateThumbprint
        }
    }
}
