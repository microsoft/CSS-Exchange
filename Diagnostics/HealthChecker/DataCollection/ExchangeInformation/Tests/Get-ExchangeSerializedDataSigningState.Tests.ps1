# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Get-ExchangeSerializedDataSigningState.ps1
}

Describe "Testing Get-ExchangeSerializedDataSigningState.ps1" {

    Context "PowerShell Serialization Payload Signing Default State" {
        BeforeAll {
            $Script:results = Get-ExchangeSerializedDataSigningState -GetSettingOverride $null
        }

        It "PowerShell Serialization Payload Signing Disabled" {
            $results.Enabled | Should -Be $false
        }
    }

    Context "PowerShell Serialization Payload Signing Enabled On Organizational Level" {
        BeforeAll {
            $r = Import-Clixml $Script:parentPath\Tests\DataCollection\GetSettingOverridePSSigningEnabledOnOrg.xml
            $Script:results = Get-ExchangeSerializedDataSigningState -GetSettingOverride $r
        }

        It "PowerShell Serialization Payload Signing Enabled" {
            $results.Enabled | Should -Be $true
        }

        It "PowerShell Serialization Payload Signing Enabled On Organizational Level" {
            $results.Server | Should -Be $null
            $results.OrgWideSetting | Should -Be $true
        }
    }

    Context "PowerShell Serialization Payload Signing Enabled On Server Level State" {
        BeforeAll {
            $r = Import-Clixml $Script:parentPath\Tests\DataCollection\GetSettingOverridePSSigningEnabledOnSrv.xml
            $Script:results = Get-ExchangeSerializedDataSigningState -GetSettingOverride $r
        }

        It "PowerShell Serialization Payload Signing Enabled" {
            $results.Enabled | Should -Be $true
        }

        It "PowerShell Serialization Payload Signing Enabled Is Disabled On Organizational Level" {
            $results.Server | Should -Not -Be $null
            $results.OrgWideSetting | Should -Be $false
        }
    }

    Context "Multiple PowerShell Serialization Payload Signing Configurations" {
        BeforeAll {
            $r = Import-Clixml $Script:parentPath\Tests\DataCollection\GetSettingOverridePSSigningMultipleOverrides.xml
            $Script:results = Get-ExchangeSerializedDataSigningState -GetSettingOverride $r
        }

        It "Multiple PowerShell Serialization Payload Signing Configurations States Returned" {
            $results.count | Should -Be 2
        }
    }

    Context "Exception While Calling PowerShell Serialization Payload Signing Configuration" {
        BeforeAll {
            $Script:results = Get-ExchangeSerializedDataSigningState -GetSettingOverride "Unknown"
        }

        It "PowerShell Serialization Payload Signing Query Failed" {
            $results.FailedQuery | Should -Be $true
        }
    }
}
