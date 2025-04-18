# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    .SYNOPSIS
    Exports a given certificate to the memory of the computer.

    .DESCRIPTION
    This function takes a certificate object of type [System.Security.Cryptography.X509Certificates.X509Certificate2] and exports it to the memory of the computer.
    It creates a memory stream to hold the certificate data and returns a custom object containing the certificate's thumbprint, Base64-encoded data, and raw bytes.

    .PARAMETER Certificate
    The certificate object to be exported.

    .NOTES
    If the provided certificate is null, the function outputs a message indicating that a valid certificate object must be provided and then exits.
    If an exception occurs during the export process, it outputs an error message with the exception details.
    The memory stream is disposed of to free up resources.

    .EXAMPLE
    $cert = Get-Item Cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678
    $certObject = Export-CertificateToMemory -Certificate $cert
#>
function Export-CertificateToMemory {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if ($null -eq $Certificate) {
        Write-Verbose "The provided certificate object is null. Please ensure you pass a valid X509Certificate2 object to the function"
        return
    }

    $memoryStream = New-Object System.IO.MemoryStream

    try {
        $certificateBytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert, $memoryStream)

        $certificateObject = [PSCustomObject]@{
            CertificateThumbprint = $Certificate.thumbprint
            CertificateBase64     = [Convert]::ToBase64String($certificateBytes)
            CertificateBytes      = $certificateBytes
        }
    } catch {
        Write-Verbose "An exception occurred during the export process: $_"
    } finally {
        $memoryStream.Dispose()
    }

    return $certificateObject
}
