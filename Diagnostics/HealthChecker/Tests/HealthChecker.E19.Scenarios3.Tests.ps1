# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

Describe "Exchange 2019 Scenarios testing 3" {
    # ToDo: Extend scenario 3 by adding additional hybrid checks

    BeforeAll {
        . $PSScriptRoot\HealthCheckerTests.ImportCode.NotPublished.ps1
        $Script:MockDataCollectionRoot = "$Script:parentPath\Tests\DataCollection\E19"
        . $PSScriptRoot\HealthCheckerTest.CommonMocks.NotPublished.ps1

        $Script:guidRegEx = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        # Save the original reference before mocking
        $Script:originalGetAuthServer = Get-Command Get-AuthServer -CommandType Function
    }

    Context "Scenario 1" {
        BeforeAll {
            Mock Get-HybridConfiguration -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetHybridConfiguration.xml" }

            SetDefaultRunOfHealthChecker "Debug_Hybrid_Configuration_Scenario1_Results.xml"
        }

        It "Hybrid Configuration Detected" {
            SetActiveDisplayGrouping "Hybrid Information"

            # ToDo: Add additional general hybrid tests here
            # cSpell:disable
            GetObject "Organization Hybrid Enabled" | Should -Be $true
            GetObject "On-Premises Smart Host Domain" | Should -Be "mail.contoso.com"
            GetObject "TLS Certificate Name" | Should -Be "<I>CN=GeoTrust TLS RSA CA G1, OU=www.digicert.com, O=DigiCert Inc, C=US<S>CN=mail.contoso.com"
            # cSpell:enable
        }
    }

    Context "Scenario 2" {
        BeforeAll {
            Mock Get-HybridConfiguration -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetHybridConfiguration.xml" }
            Mock Get-SettingOverride -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetSettingOverride2.xml" }

            SetDefaultRunOfHealthChecker "Debug_Hybrid_Configuration_Scenario2_Results.xml"
        }

        It "Dedicated Hybrid App Configured As Expected" {
            SetActiveDisplayGrouping "Hybrid Information"

            $dedicatedHybridApp = GetObject "AuthServer - 1"
            $dedicatedHybridApp.Id | Should -Match "^EvoSts - $Script:guidRegEx"
            $dedicatedHybridApp.Realm | Should -Match $Script:guidRegEx
            $dedicatedHybridApp.AppId | Should -Match $Script:guidRegEx
            $dedicatedHybridApp.DomainName | Should -Contain "contoso.mail.onmicrosoft.com"
        }
    }

    Context "Scenario 3" {
        BeforeAll {
            Mock Get-HybridConfiguration -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetHybridConfiguration.xml" }
            Mock Get-SettingOverride -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetSettingOverride2.xml" }
            Mock Get-AuthServer -MockWith { & $Script:originalGetAuthServer -Type "ACS" }

            SetDefaultRunOfHealthChecker "Debug_Hybrid_Configuration_Scenario3_Results.xml"
        }

        It "Dedicated Hybrid App Configured But AuthServer Is Missing" {
            SetActiveDisplayGrouping "Hybrid Information"

            GetObject "NoValidAuthServer" | Should -Be $true
            GetObject "DedicatedHybridAppShowMoreInformation" | Should -Be $true
        }
    }

    Context "Scenario 4" {
        BeforeAll {
            Mock Get-HybridConfiguration -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetHybridConfiguration.xml" }
            Mock Get-SettingOverride -MockWith { return $null }

            SetDefaultRunOfHealthChecker "Debug_Hybrid_Configuration_Scenario4_Results.xml"
        }

        It "Dedicated Hybrid App Not Enabled Via SettingOverride" {
            SetActiveDisplayGrouping "Hybrid Information"

            GetObject "DedicatedHybridAppNotConfigured" | Should -Be $true
            GetObject "DedicatedHybridAppShowMoreInformation" | Should -Be $true
        }
    }
}
