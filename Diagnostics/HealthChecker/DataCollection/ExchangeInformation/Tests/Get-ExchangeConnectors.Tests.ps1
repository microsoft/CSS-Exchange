# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Get-ExchangeConnectors.ps1
    . $Script:parentPath\Get-ExchangeServerCertificates.ps1

    function Invoke-CatchActions {
        param()
    }

    function Get-ExchangeCertificate {
        param()
    }

    function Get-ReceiveConnector {
        param()
    }

    function Get-SendConnector {
        param()
    }
}

Describe "Testing Get-ExchangeConnectors.ps1" {
    BeforeAll {
        Mock Get-Date -MockWith { return ([System.Convert]::ToDateTime("01/01/2022", [System.Globalization.DateTimeFormatInfo]::InvariantInfo).ToUniversalTime()) }
        Mock Get-ExchangeCertificate -MockWith { return Import-Clixml $Script:parentPath\Tests\GetExchangeCertificate.xml }
        Mock Get-SendConnector -MockWith { return Import-Clixml $Script:parentPath\Tests\GetSendConnector.xml }
        Mock Get-ReceiveConnector -MockWith { return Import-Clixml $Script:parentPath\Tests\GetReceiveConnector.xml }
        $Script:exchangeCertificates = Get-ExchangeServerCertificates -Server $Script:Server
    }

    Context "Validate Exchange Connectors Return Object" {
        BeforeAll {
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

        It "Should Return 5 Receive Connectors - 2 FrontendTransport And 3 HubTransport" {
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

        It "Connectors Without TlsCertificateName Should Be Set To TlsCertificateNameEmpty" {
            $i = 0
            foreach ($result in $results) {
                if ($result.CertificateDetails.TlsCertificateSet -eq $false) {
                    $i++
                    $result.CertificateDetails.TlsCertificateNameStatus | Should -Be "TlsCertificateNameEmpty"
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
            $cloudConnectors[0].CertificateDetails.CertificateLifetimeInfo.keys | Should -Be "611C687DFC4343A5A03E0005A1EC6E9B6AFF586D"
            $cloudConnectors[0].CertificateDetails.TlsCertificateName | Should -Be "<I>CN=WIN-CTD3L0RGEN4<S>CN=WIN-CTD3L0RGEN4"
            $cloudConnectors[0].CertificateDetails.TlsCertificateNameStatus | Should -Be "TlsCertificateMatch"
            $cloudConnectors[0].CertificateDetails.GoodTlsCertificateSyntax | Should -Be $true
            $cloudConnectors[1].CertificateDetails.CertificateLifetimeInfo.keys | Should -Be "E267D459A0FB53D0EF225C11FAC062D522648C09"
            $cloudConnectors[1].CertificateDetails.TlsCertificateName | Should -Be "<I>CN=localhost<S>CN=localhost"
            $cloudConnectors[1].CertificateDetails.TlsCertificateNameStatus | Should -Be "TlsCertificateMatch"
            $cloudConnectors[1].CertificateDetails.GoodTlsCertificateSyntax | Should -Be $true
        }
    }

    Context "Multiple Matching Certificate Found On The System" {
        BeforeAll {
            Mock Get-ExchangeCertificate -MockWith { return Import-Clixml $Script:parentPath\Tests\GetExchangeCertificateMultipleMatches.xml }
            $Script:multipleMatchingExchangeCertificates = Get-ExchangeServerCertificates -Server $Script:Server
            $Script:results = Get-ExchangeConnectors -ComputerName $Server -CertificateObject $multipleMatchingExchangeCertificates
        }

        It "Should Return Multiple Certificate Thumbprints And Lifetime Information" {
            ($results[5].CertificateDetails.CertificateLifetimeInfo).Count | Should -Be 2
            foreach ($key in ($results[5].CertificateDetails.CertificateLifetimeInfo).keys) {
                if ($key -eq "E267D459A0FB53D0EF225C11FAC062D522648C09") {
                    ($results[5].CertificateDetails.CertificateLifetimeInfo)[$key] | Should -Not -Be $null
                }

                if ($key -eq "03221367D3A3E863698501592A9B9C420D8D3F4E") {
                    ($results[5].CertificateDetails.CertificateLifetimeInfo)[$key] | Should -Not -Be $null
                }
            }
        }
    }

    Context "Cloud Mail Enabled And TlsCertificateName Set But Certificate Not On The System" {
        BeforeAll {
            Mock Get-ExchangeCertificate -MockWith { return Import-Clixml $Script:parentPath\Tests\GetExchangeCertificateIncomplete.xml }
            $Script:missingExchangeCertificate = Get-ExchangeServerCertificates -Server $Script:Server
            $Script:results = Get-ExchangeConnectors -ComputerName $Server -CertificateObject $missingExchangeCertificate

            [array]$cloudConnectors = $null
            foreach ($result in $results) {
                if ($result.CloudEnabled) {
                    $cloudConnectors += $result
                }
            }
        }

        It "Should Return TlsCertificateNotFound For The First Certificate" {
            $cloudConnectors[0].CertificateDetails.TlsCertificateNameStatus | Should -Be "TlsCertificateNotFound"
        }

        It "Should Return TlsCertificateMatch For The Second Certificate" {
            $cloudConnectors[1].CertificateDetails.TlsCertificateNameStatus | Should -Be "TlsCertificateMatch"
        }
    }

    Context "No Certificate Object Was Passed To The Function" {
        BeforeAll {
            Mock Get-ExchangeCertificate -MockWith { return $null }
            $Script:emptyExchangeCertificate = Get-ExchangeServerCertificates -Server $Script:Server
            $Script:results = Get-ExchangeConnectors -ComputerName $Server -CertificateObject $emptyExchangeCertificate
        }

        It "Should Return Objects For Each Connector" {
            $results.Count | Should -Be 6
        }

        It "Should Return Connector Objects With Some Placeholder Certificate Information" {
            foreach ($connector in $results) {
                $connector.CertificateDetails.CertificateMatchDetected | Should -Be $false
                $connector.CertificateDetails.GoodTlsCertificateSyntax | Should -Be $false
                $connector.CertificateDetails.CertificateLifetimeInfo | Should -Be $null
            }
        }
    }

    Context "Cloud Mail Enabled But No TlsCertificateName Set On Receive Connector" {
        BeforeAll {
            Mock Get-ReceiveConnector -MockWith { return Import-Clixml $Script:parentPath\Tests\GetReceiveConnectorEmptyTlsCertificateName.xml }
            $Script:results = Get-ExchangeConnectors -ComputerName $Server -CertificateObject $exchangeCertificates

            [array]$cloudConnectors = $null
            foreach ($result in $results) {
                if ($result.CloudEnabled) {
                    $cloudConnectors += $result
                }
            }
        }

        It "Cloud Mail Receive Connector Has Empty TlsCertificateName" {
            $cloudConnectors[0].ConnectorType | Should -Be "Receive"
            $cloudConnectors[0].CertificateDetails.CertificateLifetimeInfo | Should -Be $null
            $cloudConnectors[0].CertificateDetails.TlsCertificateName | Should -Be $null
            $cloudConnectors[0].CertificateDetails.TlsCertificateNameStatus | Should -Be "TlsCertificateNameEmpty"
            $cloudConnectors[0].CertificateDetails.GoodTlsCertificateSyntax | Should -Be $false
        }

        It "Cloud Mail Send Connector Has TlsCertificateName Set" {
            $cloudConnectors[1].ConnectorType | Should -Be "Send"
            $cloudConnectors[1].CertificateDetails.CertificateLifetimeInfo.keys | Should -Be "E267D459A0FB53D0EF225C11FAC062D522648C09"
            $cloudConnectors[1].CertificateDetails.TlsCertificateName | Should -Be "<I>CN=localhost<S>CN=localhost"
            $cloudConnectors[1].CertificateDetails.TlsCertificateNameStatus | Should -Be "TlsCertificateMatch"
            $cloudConnectors[1].CertificateDetails.GoodTlsCertificateSyntax | Should -Be $true
        }

        It "Certificate Lifetime Should Be 0 For Connectors Without TlsCertificateName Set" {
            $cloudConnectors[0].CertificateDetails.TlsCertificateNameStatus | Should -Be "TlsCertificateNameEmpty"
            $cloudConnectors[0].CertificateDetails.CertificateLifetimeInfo | Should -Be $null
        }

        It "Certificate Limetime Should Be Returned For Connectors With TlsCertificateName Set" {
            $cloudConnectors[1].CertificateDetails.TlsCertificateNameStatus | Should -Be "TlsCertificateMatch"
            $cloudConnectors[1].CertificateDetails.CertificateLifetimeInfo.values | Should -Not -Be $null
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

    Context "Relay Mails To The Internet Via M365 Send Connector" {
        BeforeAll {
            Mock Get-SendConnector -MockWith { return Import-Clixml $Script:parentPath\Tests\GetSendConnectorConfiguredToRelayToM365.xml }
            $Script:results = Get-ExchangeConnectors -ComputerName $Server -CertificateObject $exchangeCertificates
        }

        It "Send Connector Configured As Expected For Relaying Via M365" {
            switch ($results) {
                { ($_.SmartHosts -like "*.mail.protection.outlook.com") } {
                    $smartHostsPointToExo = $true;
                    $_.Name | Should -Be "My company to Office 365";
                    $_.RequireTLS | Should -Be $true;
                    # 1 = EncryptionOnly; 2 = CertificateValidation; 3 = DomainValidation
                    $_.TlsAuthLevel | Should -Be 2
                }
                { ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($_.AddressSpaces)) } {
                    $addressSpacesContainsWildcard = $true
                }
            }

            $smartHostsPointToExo | Should -Be $true
            $addressSpacesContainsWildcard | Should -Be $true
        }
    }
}
