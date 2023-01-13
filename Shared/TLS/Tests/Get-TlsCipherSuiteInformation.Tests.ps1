# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

Describe "Testing Get-TlsCipherSuiteInformation.ps1" {

    BeforeAll {
        $script:parentPath = (Split-Path -Parent $PSScriptRoot)
        . $PSScriptRoot\..\Get-TlsCipherSuiteInformation.ps1

        function Invoke-CatchActions {
            param()

            $Error.Clear()
        }
    }

    Context "Testing Tls ciphers returned via Get-TlsCipherSuite cmdlet call" {

        BeforeAll {
            Mock Get-TlsCipherSuite -MockWith { return Import-Clixml $script:parentPath\Tests\Data\GetTlsCipherSuite.xml }
            $script:results = Get-TlsCipherSuiteInformation
        }

        It "Should return an object" {
            $results | Should -Not -Be $null
            $results.GetType() | Should -Be "System.Object[]"
        }

        It "Should return Tls cipher suites with additional details" {
            $results.Count | Should -Be 8
            $results[0].Name | Should -Be "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            $results[0].CipherSuite | Should -Be 49196
            $results[0].Cipher | Should -Be "AES"
            $results[0].Certificate | Should -Be "ECDSA"
        }
    }

    Context "Testing Tls ciphers returned via registry call" {

        BeforeAll {
            Mock Get-TlsCipherSuite -MockWith { throw }
        }

        It "Tls cipher suites are configured via GPO and so taking precedence over local Tls cipher suites" {
            Mock Get-RemoteRegistryValue -ParameterFilter { $SubKey -like "*Policies*" } -MockWith { return Import-Clixml $script:parentPath\Tests\Data\TlsCipherGPOPath.xml }
            $script:results = Get-TlsCipherSuiteInformation

            $results | Should -Not -Be $null
            $results.GetType() | Should -Be "System.Object[]"
            $results.Count | Should -Be 9
            $results.Name.Contains("TLS_RSA_WITH_3DES_EDE_CBC_SHA") | Should -Be $true
            $results.Name.Contains("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA") | Should -Be $false
        }

        It "Tls cipher suites are not configured via GPO - locally configured cipher suites should be returned" {
            Mock Get-RemoteRegistryValue -ParameterFilter { $SubKey -like "*Policies*" } -MockWith { return $null }
            Mock Get-RemoteRegistryValue -ParameterFilter { $SubKey -like "*CurrentControlSet*" } -MockWith { return Import-Clixml $script:parentPath\Tests\Data\TlsCipherLocalPath.xml }
            $script:results = Get-TlsCipherSuiteInformation

            $results | Should -Not -Be $null
            $results.GetType() | Should -Be "System.Object[]"
            $results.Count | Should -Be 40
            $results.Name.Contains("TLS_RSA_WITH_3DES_EDE_CBC_SHA") | Should -Be $true
            $results.Name.Contains("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA") | Should -Be $true
        }
    }

    Context "All calls are failing and nothing is returned" {

        BeforeAll {
            Mock Get-TlsCipherSuite -MockWith { throw }
            Mock Get-RemoteRegistryValue -MockWith { $null }
        }

        It "Should properly handle the failed calls and shouldn't return anything" {
            $Error.Clear()
            $script:results = Get-TlsCipherSuiteInformation -CatchActionFunction ${Function:Invoke-CatchActions}
            $Error.Count | Should -Be 0
            $results | Should -Be $null
        }
    }
}
