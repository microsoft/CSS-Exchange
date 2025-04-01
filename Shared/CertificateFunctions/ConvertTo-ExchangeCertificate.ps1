# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    This function will attempt to convert the information provided to Microsoft.Exchange.Management.SystemConfigurationTasks.ExchangeCertificate.
    If it is unable to do this, it will convert the data to a normal System.Security.Cryptography.X509Certificates.X509Certificate2.
    If this fails, we will throw to the caller for bad data.
#>
function ConvertTo-ExchangeCertificate {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [object[]]$CertificateObject,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $typeIsNotLoaded = $false

        try {
            $CertificateObject[0] -isnot [Microsoft.Exchange.Management.SystemConfigurationTasks.ExchangeCertificate] | Out-Null
        } catch {
            Write-Verbose "Type is not loaded to be able to convert."
            $typeIsNotLoaded = $true
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    process {

        foreach ($cert in $CertificateObject) {
            if ($null -eq $cert.Thumbprint) {
                # Certificate isn't properly loaded likely due to deserialization. Need to convert.
                if ($null -eq $cert.RawData) {
                    throw "Failed to provide a valid certificate object to be able to convert."
                }
                $certObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2

                try {
                    $certObject.Import($cert.RawData)
                } catch {
                    Write-Verbose "Failed to Import the RawData into the X509Certificate2 object. Inner Exception: $_"
                    Invoke-CatchActionError $CatchActionFunction
                }

                if (-not $typeIsNotLoaded) {
                    $certObject = [Microsoft.Exchange.Management.SystemConfigurationTasks.ExchangeCertificate]$certObject
                }
                # Place back onto the pipeline
                $certObject
            } elseif (-not $typeIsNotLoaded) {
                # Attempt to convert and place on the pipeline
                $certObject = [Microsoft.Exchange.Management.SystemConfigurationTasks.ExchangeCertificate]$cert
                $certObject
            } else {
                # just place the current object onto the pipeline
                $cert
            }
        }
    }
}
