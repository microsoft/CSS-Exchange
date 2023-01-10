# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Import-ExchangeCertificateFromRawData {
    [CmdletBinding()]
    param(
        [System.Object[]]$ExchangeCertificates
    )

    <#
        This helper function must be used if Serialization Data Signing is enabled, but the Auth Certificate
        which is configured has expired or isn't available on the system where the script runs.
        The 'Get-ExchangeCertificate' cmdlet fails to deserialize and so, only RawData (byte[]) will be returned.
        To workaround, we initialize the X509Certificate2 class and import the data by using the Import() method.
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $exchangeCertificatesList = New-Object 'System.Collections.Generic.List[object]'
    } process {
        if ($ExchangeCertificates.Count -ne 0) {
            Write-Verbose ("Going to process '$($ExchangeCertificates.Count )' Exchange certificates")

            foreach ($c in $ExchangeCertificates) {
                # Initialize X509Certificate2 class
                $certObject = New-Object 'System.Security.Cryptography.X509Certificates.X509Certificate2'
                # Use the Import() method to import byte[] RawData
                $certObject.Import($c.RawData)

                if ($null -ne $certObject.Thumbprint) {
                    Write-Verbose ("Certificate with thumbprint: $($certObject.Thumbprint) imported successfully")
                    $exchangeCertificatesList.Add($certObject)
                }
            }
        }
    } end {
        return $exchangeCertificatesList
    }
}
