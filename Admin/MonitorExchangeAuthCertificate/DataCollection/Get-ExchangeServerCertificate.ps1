# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\CertificateFunctions\Import-ExchangeCertificateFromRawData.ps1

function Get-ExchangeServerCertificate {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [string]$Server = $env:COMPUTERNAME,
        [string]$Thumbprint = $null
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $allExchangeCertificates = New-Object 'System.Collections.Generic.List[object]'
    } process {
        $getExchangeCertificateParams = @{
            Server      = $Server
            ErrorAction = "Stop"
        }

        if (-not([System.String]::IsNullOrEmpty($Thumbprint))) {
            $getExchangeCertificateParams.Add("Thumbprint", $Thumbprint)
        }

        $exchangeCertificates = Get-ExchangeCertificate @getExchangeCertificateParams

        if ($null -ne $exchangeCertificates) {
            if ($null -ne $exchangeCertificates[0].Thumbprint) {
                Write-Verbose ("Deserialization of the Exchange certificates was successful")
                foreach ($c in $exchangeCertificates) {
                    $allExchangeCertificates.Add($c)
                }
            } else {
                Write-Verbose ("Deserialization of the Exchange certificates failed - trying to import from RawData")
                foreach ($c in $exchangeCertificates) {
                    $allExchangeCertificates.Add($(Import-ExchangeCertificateFromRawData $c))
                }
            }

            Write-Verbose ("$($allExchangeCertificates.Count) Exchange Server certificates were returned")
        }
    } end {
        return $allExchangeCertificates
    }
}
