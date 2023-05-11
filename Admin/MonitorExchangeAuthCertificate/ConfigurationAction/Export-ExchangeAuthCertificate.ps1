# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Invoke-CatchActionError.ps1

function Export-ExchangeAuthCertificate {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$Password,
        [ScriptBlock]$CatchActionFunction
    )

    <#
        This function exports the current Auth Certificate and (if configured) the next Auth Certificate.
        The certificates will be stored as password protected .pfx file.
    #>

    try {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $certificatesReadyToExportList = New-Object 'System.Collections.Generic.List[object]'
        $certificatesUnableToExportList = New-Object 'System.Collections.Generic.List[string]'
        $currentAuthConfig = Get-AuthConfig -ErrorAction Stop
        $allExchangeCertificates = Get-ExchangeCertificate -Server $env:COMPUTERNAME -ErrorAction SilentlyContinue

        if ($null -ne $currentAuthConfig) {
            $currentAuthCertThumbprint = $currentAuthConfig.CurrentCertificateThumbprint
            $nextAuthCertThumbprint = $currentAuthConfig.NextCertificateThumbprint

            if (-not([System.String]::IsNullOrEmpty($currentAuthCertThumbprint))) {
                Write-Verbose ("CurrentCertificateThumbprint is: $($currentAuthCertThumbprint) - trying to find it on the local computer")
                $currentAuthCertificate = $allExchangeCertificates | Where-Object {
                    ($_.Thumbprint -eq $currentAuthCertThumbprint)
                }

                if (($null -eq $currentAuthCertificate) -or
                    ($currentAuthCertificate.HasPrivateKey -eq $false) -or
                    ($currentAuthCertificate.PrivateKeyExportable -eq $false)) {
                    Write-Verbose ("Current Auth Certificate doesn't fullfil the requirements to be exportable on this machine")
                    $certificatesUnableToExportList.Add($currentAuthCertThumbprint)
                } else {
                    Write-Verbose ("Current Auth Certificate was detected on the local machine and is ready to be exported")
                    $certificatesReadyToExportList.Add($currentAuthCertificate)
                }
            }

            if (-not([System.String]::IsNullOrEmpty($nextAuthCertThumbprint))) {
                Write-Verbose ("NextCertificateThumbprint is: $($nextAuthCertThumbprint) - trying to find it on the local computer")
                $nextAuthCertificate = $allExchangeCertificates | Where-Object {
                    ($_.Thumbprint -eq $nextAuthCertThumbprint)
                }

                if (($null -eq $nextAuthCertificate) -or
                    ($nextAuthCertificate.HasPrivateKey -eq $false) -or
                    ($nextAuthCertificate.PrivateKeyExportable -eq $false)) {
                    Write-Verbose ("Next Auth Certificate doesn't fullfil the requirements to be exportable on this machine")
                    $certificatesUnableToExportList.Add($nextAuthCertThumbprint)
                } else {
                    Write-Verbose ("Next Auth Certificate was detected on the local machine and is ready to be exported")
                    $certificatesReadyToExportList.Add($nextAuthCertificate)
                }
            }

            Write-Verbose ("There are: $($certificatesReadyToExportList.Count) certificates on the list that will be exported now")
            $dateTimeAppendix = (Get-Date -Format "yyyyMMddhhmmss")
            foreach ($cert in $certificatesReadyToExportList) {
                Write-Verbose ("Exporting the certificate with thumbprint: $($cert.Thumbprint) now...")
                try {
                    if ($PSCmdlet.ShouldProcess($cert.Thumbprint, "Export-ExchangeCertificate")) {
                        $authCert = Export-ExchangeCertificate -Thumbprint $cert.Thumbprint -BinaryEncoded -Password $Password
                    }
                    $certExportPath = "$($PSScriptRoot)\$($cert.Thumbprint)-$($dateTimeAppendix).pfx"
                    if ($PSCmdlet.ShouldProcess("Export certificate: $($cert.Thumbprint) To: $certExportPath", "[System.IO.File]::WriteAllBytes")) {
                        [System.IO.File]::WriteAllBytes($certExportPath, $authCert.FileData)
                    }
                    Write-Verbose ("Certificate exported to: $certExportPath")
                } catch {
                    Write-Verbose ("We hit an issue during certificate export - Exception $($Error[0].Exception.Message)")
                    $certificatesUnableToExportList.Add($authCert.Thumbprint)
                    Invoke-CatchActionError $CatchActionFunction
                }
            }
        } else {
            Write-Verbose ("No valid Auth Config returned")
            return
        }
    } catch {
        Write-Verbose ("Unable to query the Exchange Auth Config - Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
    }

    return [PSCustomObject]@{
        CertificatesAvailableToExport      = ($certificatesReadyToExportList.Count -gt 0)
        ExportSuccessful                   = (($certificatesReadyToExportList.Count -gt 0) -and ($certificatesUnableToExportList.Count -eq 0))
        NumberOfCertificatesToExport       = $certificatesReadyToExportList.Count
        NumberOfCertificatesUnableToExport = $certificatesUnableToExportList.Count
        UnableToExportCertificatesList     = $certificatesUnableToExportList
    }
}
