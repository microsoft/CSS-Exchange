# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Get-ExchangeAMSIConfigurationState.ps1

    function Get-SettingOverride {
        param()
    }

    function Invoke-CatchActions {
        param()
    }
}

Describe "Testing Get-ExchangeAMSIConfigurationState.ps1" {

    Context "AMSI Configuration Default State" {
        BeforeAll {
            Mock Get-SettingOverride -MockWith { return $null }
            $Script:results = Get-ExchangeAMSIConfigurationState
        }

        It "AMSI Query Successful" {
            $results.QuerySuccessful | Should -Be $true
        }

        It "AMSI Interface Enabled" {
            $results.Enabled | Should -Be $true
        }
    }

    Context "AMSI Configuration Disabled On Organizational Level" {
        BeforeAll {
            Mock Get-SettingOverride -MockWith { return Import-Clixml $Script:parentPath\Tests\GetSettingOverrideDisabledOnOrg.xml }
            $Script:results = Get-ExchangeAMSIConfigurationState
        }

        It "AMSI Query Successful" {
            $results.QuerySuccessful | Should -Be $true
        }

        It "AMSI Interface Disabled" {
            $results.Enabled | Should -Be $false
        }

        It "AMSI Is Disabled On Organizational Level" {
            $results.Server | Should -Be $null
            $results.OrgWideSetting | Should -Be $true
        }
    }

    Context "AMSI Configuration Disabled On Server Level State" {
        BeforeAll {
            Mock Get-SettingOverride -MockWith { return Import-Clixml $Script:parentPath\Tests\GetSettingOverrideDisabledOnSrv.xml }
            $Script:results = Get-ExchangeAMSIConfigurationState
        }

        It "AMSI Query Successful" {
            $results.QuerySuccessful | Should -Be $true
        }

        It "AMSI Interface Disabled" {
            $results.Enabled | Should -Be $false
        }

        It "AMSI Is Disabled On Organizational Level" {
            $results.Server | Should -Not -Be $null
            $results.OrgWideSetting | Should -Be $false
        }
    }

    Context "Multiple AMSI Configurations" {
        BeforeAll {
            Mock Get-SettingOverride -MockWith { return Import-Clixml $Script:parentPath\Tests\GetSettingOverrideMultiConfigs.xml }
            $Script:results = Get-ExchangeAMSIConfigurationState
        }

        It "Multiple AMSI Configuration States Returned" {
            $results.count | Should -Be 2
        }
    }

    Context "Exception While Calling AMSI Configuration" {
        BeforeAll {
            Mock Get-SettingOverride -MockWith { throw "Bad thing happened" }
            $Script:results = Get-ExchangeAMSIConfigurationState
        }

        It "AMSI Query Failed" {
            $results.QuerySuccessful | Should -Be $false
        }

        It "AMSI State Unknown" {
            $results.Enabled | Should -Be "Unknown"
        }
    }
}
