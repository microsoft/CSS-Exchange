# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\ActiveDirectoryFunctions\Get-InternalTransportCertificateFromServer.ps1
. $PSScriptRoot\..\Invoke-CatchActionError.ps1
. $PSScriptRoot\ConvertTo-ExchangeCertificate.ps1

function Get-ExchangeServerCertificateInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )
    begin {
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

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Build certificate exclusion list"
        <#
                Add the certificates that should be excluded from the Exchange certificate check (we don't return an object for them)
                Exclude "MS-Organization-P2P-Access [YYYY]" certificate with one day lifetime on Azure hosted machines.
                See: What are the MS-Organization-P2P-Access certificates present on our Windows 10/11 devices?
                https://docs.microsoft.com/azure/active-directory/devices/faq
                Exclude "DC=Windows Azure CRP Certificate Generator" (TenantEncryptionCertificate)
                The certificates are built by the Azure fabric controller and passed to the Azure VM Agent.
                If you stop and start the VM every day, the fabric controller might create a new certificate.
                These certificates can be deleted. The Azure VM Agent re-creates certificates if needed.
                https://docs.microsoft.com/azure/virtual-machines/extensions/features-windows
            #>
        $certificatesToExclude = @(
            NewCertificateExclusionEntry "CN=MS-Organization-P2P-Access \[[12][0-9]{3}\]$" $false
            NewCertificateExclusionEntry "DC=Windows Azure CRP Certificate Generator" $true
        )
        $certObject = New-Object System.Collections.Generic.List[object]
    }
    process {
        try {
            Write-Verbose "Trying to receive certificates from Exchange server: $($Server)"
            $exchangeServerCertificates = Get-ExchangeCertificate -Server $Server -ErrorAction Stop | ConvertTo-ExchangeCertificate -CatchActionFunction $CatchActionFunction

            Write-Verbose "Trying to query internal transport certificate from AD for this server"
            $internalTransportCertificate = Get-InternalTransportCertificateFromServer -ComputerName $Server -CatchActionFunction $CatchActionFunction
        } catch {
            Write-Verbose "Failed to collect the Exchange Server Certificate Information on $server. Inner Exception: $_"
            Invoke-CatchActionError $CatchActionFunction
        }

        foreach ($cert in $exchangeServerCertificates) {
            if ((ShouldCertificateBeSkipped -Exclusions $certificatesToExclude -Certificate $cert)) {
                continue
            }

            $certObject.Add($cert)
        }
    }
    end {
        return [PSCustomObject]@{
            Certificates        = $certObject
            InternalCertificate = $internalTransportCertificate
        }
    }
}
