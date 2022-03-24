# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Get-ExchangeConnectors.ps1

    Function Invoke-CatchActions {
        param()
    }

    Function Get-ExchangeCertificate {
        param()
    }

    Function Get-ReceiveConnector {
        param()
    }

    Function Get-SendConnector {
        param()
    }
}

Describe "Testing Get-ExchangeConnectors.ps1" {

    BeforeAll {
        Mock Get-ExchangeCertificate -MockWith { return Import-Clixml $Script:parentPath\Tests\GetExchangeCertificate.xml }
        Mock Get-SendConnector -MockWith { return Import-Clixml $Script:parentPath\Tests\GetSendConnector.xml }
        $Script:exchangeCertificates = Get-ExchangeCertificate -ComputerName $Server
    }

    Context "Validate Exchange Connectors Return Object" {
        BeforeAll {
            Mock Get-ReceiveConnector -MockWith { return Import-Clixml $Script:parentPath\Tests\GetReceiveConnector.xml }
            $Script:results = Get-ExchangeConnectors -ComputerName $Server -CertificateObject $exchangeCertificates
        }

        It "Should Return 6 Connector Objects For Each Connector" {
            $results.Count | Should -Be 6
        }

        It "Should Return 2 Cloud Enabled Connectors" {
            $i = 0
            foreach ($result in $results) {
                if ($result.CloudEnabled) {
                    $i++
                }
            }

            $i | Should -Be 2
        }

        It "Should Return 1 Send Connector" {
            $i = 0
            foreach ($result in $results) {
                if ($result.ConnectorType -eq "Send") {
                    $i++
                }
            }

            $i | Should -Be 1
        }

        It "Should Return 5 Receive Connectors - 2 FrontEnd And 3 HubTransport" {
            $i = 0
            $frontEndCounter = 0
            $hubTransportCounter = 0
            foreach ($result in $results) {
                if ($result.ConnectorType -eq "Receive") {
                    $i++
                    if (($result.TransportRole).ToString() -eq "HubTransport") {
                        $hubTransportCounter++
                    }

                    if (($result.TransportRole).ToString() -eq "FrontendTransport") {
                        $frontEndCounter++
                    }
                }
            }

            $i | Should -Be 5
            $hubTransportCounter | Should -Be 2
            $frontEndCounter | Should -Be 3
        }

        It "Connectors Without TlsCertificateName Should Be Set To " {
            $i = 0
            foreach ($result in $results) {
                if ($result.TlsCertificateSet -eq $false) {
                    $i++
                    $result.TlsCertificateNameStatus | Should -Be "TlsCertificateNameEmpty"
                }
            }

            $i | Should -Be 4
        }

        It "Cloud Mail Connectors Should Return Valid TlsCertificateName Configuration" {
            [array]$cloudConnectors = $null
            foreach ($result in $results) {
                if ($result.CloudEnabled) {
                    $cloudConnectors += $result
                }
            }
            $cloudConnectors[0].CertificateThumbprint | Should -Be "611C687DFC4343A5A03E0005A1EC6E9B6AFF586D"
            $cloudConnectors[0].TlsCertificateName | Should -Be "<I>CN=WIN-CTD3L0RGEN4<S>CN=WIN-CTD3L0RGEN4"
            $cloudConnectors[0].TlsCertificateNameStatus | Should -Be "TlsCertificateMatch"
            $cloudConnectors[0].GoodTlsCertificateSyntax | Should -Be $true
            $cloudConnectors[1].CertificateThumbprint | Should -Be "E267D459A0FB53D0EF225C11FAC062D522648C09"
            $cloudConnectors[1].TlsCertificateName | Should -Be "<I>CN=localhost<S>CN=localhost"
            $cloudConnectors[1].TlsCertificateNameStatus | Should -Be "TlsCertificateMatch"
            $cloudConnectors[1].GoodTlsCertificateSyntax | Should -Be $true
        }

        Context "Cloud Mail Enabled But No TlsCertificateName Set On Receive Connector" {
            BeforeAll {
                Mock Get-ReceiveConnector -MockWith { return Import-Clixml $Script:parentPath\Tests\GetReceiveConnectorEmptyTlsCertificateName.xml }
                $Script:results = Get-ExchangeConnectors -ComputerName $Server -CertificateObject $exchangeCertificates
            }

            It "Cloud Mail Connector Has Empty TlsCertificateName" {

                [array]$cloudConnectors = $null
                foreach ($result in $results) {
                    if ($result.CloudEnabled) {
                        $cloudConnectors += $result
                    }
                }
                $cloudConnectors[0].CertificateThumbprint | Should -Be "N/A"
                $cloudConnectors[0].TlsCertificateName | Should -Be "N/A"
                $cloudConnectors[0].TlsCertificateNameStatus | Should -Be "TlsCertificateNameEmpty"
                $cloudConnectors[0].GoodTlsCertificateSyntax | Should -Be $false
                $cloudConnectors[1].CertificateThumbprint | Should -Be "E267D459A0FB53D0EF225C11FAC062D522648C09"
                $cloudConnectors[1].TlsCertificateName | Should -Be "<I>CN=localhost<S>CN=localhost"
                $cloudConnectors[1].TlsCertificateNameStatus | Should -Be "TlsCertificateMatch"
                $cloudConnectors[1].GoodTlsCertificateSyntax | Should -Be $true
            }
        }

        Context "No Connector Processed" {
            BeforeAll {
                Mock Get-ReceiveConnector -MockWith { return $null }
                Mock Get-SendConnector -MockWith { return $null }
                $Script:results = Get-ExchangeConnectors -ComputerName $Server -CertificateObject $exchangeCertificates
            }

            It "No Object Should Be Returned" {
                $results.Count | Should -Be 0
            }
        }
    }
}
