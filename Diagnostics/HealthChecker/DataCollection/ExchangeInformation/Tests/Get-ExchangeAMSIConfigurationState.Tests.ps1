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
}

Describe "Testing Get-ExchangeAMSIConfigurationState.ps1" {

    Context "AMSI Configuration Default State" {
        BeforeAll {
            $Script:results = Get-ExchangeAMSIConfigurationState -GetSettingOverride $null
        }

        It "AMSI Interface Enabled" {
            $results.Enabled | Should -Be $true
        }
    }

    Context "AMSI Configuration Disabled On Organizational Level" {
        BeforeAll {
            $r = Import-Clixml $Script:parentPath\Tests\DataCollection\GetSettingOverrideDisabledOnOrg.xml
            $Script:results = Get-ExchangeAMSIConfigurationState -GetSettingOverride $r
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
            $r = Import-Clixml $Script:parentPath\Tests\DataCollection\GetSettingOverrideDisabledOnSrv.xml
            $Script:results = Get-ExchangeAMSIConfigurationState -GetSettingOverride $r
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
            $r = Import-Clixml $Script:parentPath\Tests\DataCollection\GetSettingOverrideMultiConfigs.xml
            $Script:results = Get-ExchangeAMSIConfigurationState -GetSettingOverride $r
        }

        It "Multiple AMSI Configuration States Returned" {
            $results.count | Should -Be 2
        }
    }

    Context "Exception While Calling AMSI Configuration" {
        BeforeAll {
            $Script:results = Get-ExchangeAMSIConfigurationState -GetSettingOverride "Unknown"
        }

        It "AMSI Query Failed" {
            $results.FailedQuery | Should -Be $true
        }
    }
}
