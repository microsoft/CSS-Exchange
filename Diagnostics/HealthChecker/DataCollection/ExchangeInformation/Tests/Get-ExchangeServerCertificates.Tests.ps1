# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Get-ExchangeServerCertificates.ps1
    . $PSScriptRoot\..\..\..\..\..\.build\Load-Module.ps1

    if (-not (Load-Module -Name "Microsoft.PowerShell.Security" -MinimumVersion "7.0.0.0")) {
        throw "Failed to load required security module"
    }

    function Invoke-CatchActions {
        param()
    }

    function Get-AuthConfig {
        param()
    }

    function Get-ExchangeCertificate {
        param()
    }
}

Describe "Testing Get-ExchangeServerCertificates.ps1" {

    BeforeAll {
        Mock Get-AuthConfig -MockWith { return Import-Clixml $Script:parentPath\Tests\DataCollection\GetAuthConfig.xml }
        Mock Get-ExchangeCertificate -MockWith { return Import-Clixml $Script:parentPath\Tests\DataCollection\GetExchangeCertificate.xml }
        Mock Get-Date -MockWith { return ([System.Convert]::ToDateTime("01/01/2022", [System.Globalization.DateTimeFormatInfo]::InvariantInfo).ToUniversalTime()) }
    }

    Context "Valid Exchange Server Certificates Detected" {
        BeforeAll {
            $Script:results = Get-ExchangeServerCertificates -Server $Script:Server
        }

        It "Valid Auth Certificate (using weak SHA1 Hash Algorithm) Detected" {
            $results[0].FriendlyName | Should -Be "Microsoft Exchange Server Auth Certificate"
            $results[0].Thumbprint | Should -Be "2D10A746D6BB8D795F1679AEBD89D5D2AE583CB7"
            $results[0].IsCurrentAuthConfigCertificate | Should -Be $true
            $results[0].SignatureAlgorithm | Should -Be "sha1RSA"
            $results[0].SignatureHashAlgorithm | Should -Be "sha1"
            $results[0].SignatureHashAlgorithmSecure | Should -Be 1
            $results[0].IsSanCertificate | Should -Be $false
            $results[0].PublicKeySize | Should -Be 2048
            $results[0].IsEccCertificate | Should -Be $false
        }

        It "Valid SAN Certificate (using weak SHA1 Hash Algorithm) Detected" {
            $results[1].FriendlyName | Should -Be "WIN-CTD3L0RGen4"
            $results[1].Thumbprint | Should -Be "611C687DFC4343A5A03E0005A1EC6E9B6AFF586D"
            $results[1].IsCurrentAuthConfigCertificate | Should -Be $false
            $results[1].SignatureAlgorithm | Should -Be "sha1RSA"
            $results[1].SignatureHashAlgorithm | Should -Be "sha1"
            $results[1].SignatureHashAlgorithmSecure | Should -Be 1
            $results[1].IsSanCertificate | Should -Be $true
            ($results[1].Namespaces).Count | Should -Be 2
            $results[1].PublicKeySize | Should -Be 2048
            $results[1].IsEccCertificate | Should -Be $false
        }

        It "Valid Certificate (using strong SHA256 Hash Algorithm) Detected" {
            $results[3].FriendlyName | Should -Be "WMSvc-SHA2-WIN-CTD3L0RGen4"
            $results[3].Thumbprint | Should -Be "3341CEAF3DF4D3A9527EC98BDD53C54ECC3E0620"
            $results[3].PublicKeySize | Should -Be 2048
            $results[3].IsEccCertificate | Should -Be $false
            $results[3].SignatureAlgorithm | Should -Be "sha256RSA"
            $results[3].SignatureHashAlgorithm | Should -Be "sha256"
            $results[3].SignatureHashAlgorithmSecure | Should -Be 2
        }
    }

    Context "No Matching Auth Certificate Found" {
        BeforeAll {
            Mock Get-ExchangeCertificate -MockWith { return Import-Clixml $Script:parentPath\Tests\DataCollection\GetExchangeCertificateWithoutAuth.xml }
            $Script:results = Get-ExchangeServerCertificates -Server $Script:Server
        }

        It "Get Auth Config But No Matching Certificate" {
            foreach ($result in $results) {
                Write-Verbose ("Validating if Certificate: '{0}' is Auth Certificate" -f $result.FriendlyName)
                Write-Verbose ("Is current Auth Config Certificate? '{0}'" -f $result.IsCurrentAuthConfigCertificate)

                $result.IsCurrentAuthConfigCertificate | Should -Be $false
            }
        }
    }

    Context "Auth Configuration Call Failed" {
        BeforeAll {
            Mock Get-AuthConfig -MockWith { throw "Bad thing happened - Get-AuthConfig" }
            $Script:results = Get-ExchangeServerCertificates -Server $Script:Server
        }

        It "Unable To Find Valid Auth Certificate" {
            foreach ($result in $results) {
                Write-Verbose ("Validating if Certificate: '{0}' is Auth Certificate" -f $result.FriendlyName)
                Write-Verbose ("Status: '{0}'" -f $result.IsCurrentAuthConfigCertificate)

                $result.IsCurrentAuthConfigCertificate | Should -Be "InvalidAuthConfig"
            }
            $error[0].Exception.Message | Should -Be "Bad thing happened - Get-AuthConfig"
        }
    }

    Context "No Exchange Server Certificate Returned" {
        BeforeAll {
            Mock Get-ExchangeCertificate -MockWith { return $null }
            $Script:results = Get-ExchangeServerCertificates -Server $Script:Server
        }

        It "No Custom certificate Object Returned" {
            $results | Should -Be $null
        }
    }

    Context "Exchange Server Certificate Returned In Raw Format" {
        BeforeAll {
            Mock Get-ExchangeCertificate { Import-Clixml $Script:parentPath\Tests\DataCollection\GetExchangeCertificateBroken.xml }
            $Script:results = Get-ExchangeServerCertificates -Server $Script:Server
        }

        It "Should Successfully Import Certificates From RawData" {
            $results.Count | Should -Be 4
            $results.GetType().FullName | Should -Be 'System.Object[]'
            $results[1].Namespaces.Count | Should -Be 4
            $results[1].IsSanCertificate | Should -Be $true
            $results[1].LifetimeInDays | Should -BeGreaterThan 2000
            $results[1].Thumbprint | Should -Be '2759456DC53C76E3DED093B567B6D8DAA42C0ADD'
            $results[1].Subject | Should -Be 'CN=mail.contoso.lab'
        }
    }

    Context "Get-ExchangeCertificate Call Hit An Exception" {
        BeforeAll {
            Mock Get-ExchangeCertificate -MockWith { throw "Bad thing happened - Get-ExchangeCertificate" }
            $Script:results = Get-ExchangeServerCertificates -Server $Script:Server
        }

        It "No Custom Certificate Object Returned And Exception Logged" {
            $results | Should -Be $null
            $error[0].Exception.Message | Should -Be "Bad thing happened - Get-ExchangeCertificate"
        }
    }

    Context "Check If Certificates On SkipList Are Skipped" {
        BeforeAll {
            Mock Get-ExchangeCertificate -MockWith { return Import-Clixml $Script:parentPath\Tests\DataCollection\GetExchangeCertificateOnAzure.xml }
            $Script:results = Get-ExchangeServerCertificates -Server $Script:Server
        }

        It "Should Not Return The 'Windows Azure CRP Certificate Generator' Certificate" {
            $results | Should -Not -Be $null
            foreach ($r in $results) {
                $r.FriendlyName | Should -Not -Be "TenantEncryptionCert"
                $r.Issuer | Should -Not -Be "DC=Windows Azure CRP Certificate Generator"
                $r.Subject | Should -Not -Be "DC=Windows Azure CRP Certificate Generator"
            }
        }
    }
}
