# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Get-ExchangeServerCertificate.ps1

    function Get-ExchangeCertificate {
        param()
    }
}

Describe "Testing Get-ExchangeServerCertificate.ps1" {

    Context "Get-ExchangeServerCertificate Without Any Parameter" {
        BeforeAll {
            Mock Get-ExchangeCertificate { Import-Clixml $Script:parentPath\Tests\Data\GetExchangeCertificate.xml }
            $Script:results = Get-ExchangeServerCertificate
        }

        It "Should Return All Exchange Certificates" {
            $results.Count | Should -Be 8
            $results.GetType().FullName | Should -Be 'System.Object[]'
            $results[6].Thumbprint | Should -Be '2759456DC53C76E3DED093B567B6D8DAA42C0ADD'
            $results[6].Subject | Should -Be 'CN=mail.contoso.lab'
        }
    }

    Context "Get-ExchangeServerCertificate In Misconfigured SerializedDataSigning State" {
        BeforeAll {
            Mock Get-ExchangeCertificate { Import-Clixml $Script:parentPath\Tests\Data\GetExchangeCertificateBroken.xml }
            $Script:results = Get-ExchangeServerCertificate
        }

        It "Should Successfully Import Certificates From RawData" {
            $results.Count | Should -Be 5
            $results.GetType().FullName | Should -Be 'System.Object[]'
            $results[2].Thumbprint | Should -Be '2759456DC53C76E3DED093B567B6D8DAA42C0ADD'
            $results[2].Subject | Should -Be 'CN=mail.contoso.lab'
        }
    }

    Context "Exception While Calling Get-ExchangeServerCertificate" {
        BeforeAll {
            Mock Get-ExchangeCertificate { return $null }
            $Script:results = Get-ExchangeServerCertificate
        }

        It "Should Not Return Anything" {
            $results | Should -Be $null
        }
    }
}
