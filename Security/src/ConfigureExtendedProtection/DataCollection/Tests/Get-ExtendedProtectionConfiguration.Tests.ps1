# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Get-ExtendedProtectionConfiguration.ps1

    function Invoke-CatchActions {
        param()
    }

    function LoadApplicationHostConfig {
        [CmdletBinding()]
        [OutputType("System.Xml.XmlNode")]
        param(
            [string]$Path
        )

        $appHostConfig = New-Object -TypeName Xml
        try {
            $appHostConfig.Load($Path)
        } catch {
            throw "Failed to loaded application host config file. $_"
            $appHostConfig = $null
        }
        return $appHostConfig
    }

    function TestUnsupportedNotConfiguredExtendedProtection {
        param(
            [object]$TestingExtendedProtectionResults
        )

        $TestingExtendedProtectionResults.SupportedVersionForExtendedProtection | Should -Be $false
        $TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
            Where-Object { $_.ExtendedProtection -ne "None" } |
            Should -Be $null
        $TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
            Where-Object { $_.ExpectedExtendedConfiguration -ne "None" } |
            Should -Be $null
        $TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
            Where-Object { $_.SupportedExtendedProtection -eq $false } |
            Should -Be $null
    }

    function TestSupportedConfiguredExtendedProtection {
        param(
            [object]$TestingExtendedProtectionResults
        )

        $TestingExtendedProtectionResults.SupportedVersionForExtendedProtection | Should -Be $true
        ($TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
            Where-Object { $_.ExtendedProtection -ne "None" }).count |
                Should -Be 21
        ($TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
            Where-Object { $_.ExpectedExtendedConfiguration -ne "None" }).count |
                Should -Be 21
        $TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
            Where-Object { $_.SupportedExtendedProtection -eq $false } |
            Should -Be $null
        # Special configs
        $allow = $TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
            Where-Object { $_.ExtendedProtection -eq "Allow" }
        $null -ne $allow | Should -Be $true
        $allow.configuration.NodePath | Should -Be "Default Web Site/EWS"

        $none = $TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
            Where-Object { $_.ExtendedProtection -eq "None" }
        $null -ne $none | Should -Be $true
        $none.Count | Should -Be 2
        $none.Configuration.NodePath.Contains("Default Web Site/Autodiscover") | Should -Be $true
        $none.Configuration.NodePath.Contains("Exchange Back End/Autodiscover") | Should -Be $true
    }

    $Script:E15_NotConfigured_Both_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E15_NotConfigured_Both_ApplicationHost.config
    $Script:E15_NotConfigured_Cas_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E15_NotConfigured_Cas_ApplicationHost.config
    $Script:E15_NotConfigured_Mbx_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E15_NotConfigured_Mbx_ApplicationHost.config
    $Script:E16_NotConfigured_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E16_NotConfigured_ApplicationHost.config
    $Script:E19_NotConfigured_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E19_NotConfigured_ApplicationHost.config

    $Script:E16_Configured_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E16_Configured_ApplicationHost.config
    $Script:E19_Configured_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E19_Configured_ApplicationHost.config

    $Script:E19_MisConfigured_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E19_MisConfigured_ApplicationHost.config
}

Describe "Testing Get-ExtendedProtectionConfiguration.ps1" {

    Context "No ExSetupVersion Passed To The Function" {
        BeforeAll {
            Mock Get-Command { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetCommand.xml }

            $mockParams = @{
                ComputerName          = $Server
                ApplicationHostConfig = $E16_NotConfigured_ApplicationHost
            }

            $Script:extendedProtectionResults = Get-ExtendedProtectionConfiguration @mockParams
        }

        It "Should Return The Extended Protection Custom Object" {
            $extendedProtectionResults.Count | Should -Be 1
            $extendedProtectionResults.ExtendedProtectionConfiguration.Count | Should -Be 23
        }

        It "Should Return The applicationHost.config As Xml" {
            $extendedProtectionResults.ApplicationHostConfig.GetType() | Should -Be "xml"
        }

        It "TestUnsupportedNotConfiguredExtendedProtection" {
            TestUnsupportedNotConfiguredExtendedProtection $extendedProtectionResults
        }
    }

    Context "Extended Protection Is Not Configured On Unsupported Exchange Version" {

        It "Exchange 2013 CAS/MBX" {
            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = "15.00.1497.036"
                ApplicationHostConfig = $E15_NotConfigured_Both_ApplicationHost
            }
            TestUnsupportedNotConfiguredExtendedProtection (Get-ExtendedProtectionConfiguration @mockParams)
        }

        It "Exchange 2013 CAS" {
            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = "15.00.1497.036"
                ApplicationHostConfig = $E15_NotConfigured_Cas_ApplicationHost
            }
            TestUnsupportedNotConfiguredExtendedProtection (Get-ExtendedProtectionConfiguration @mockParams)
        }

        It "Exchange 2013 Mbx" {
            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = "15.00.1497.036"
                ApplicationHostConfig = $E15_NotConfigured_Mbx_ApplicationHost
            }
            TestUnsupportedNotConfiguredExtendedProtection (Get-ExtendedProtectionConfiguration @mockParams)
        }

        It "Exchange 2016" {
            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = "15.01.2507.009"
                ApplicationHostConfig = $E16_NotConfigured_ApplicationHost
            }
            TestUnsupportedNotConfiguredExtendedProtection (Get-ExtendedProtectionConfiguration @mockParams)
        }

        It "Exchange 2019" {
            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = "15.02.1118.009"
                ApplicationHostConfig = $E19_NotConfigured_ApplicationHost
            }
            TestUnsupportedNotConfiguredExtendedProtection (Get-ExtendedProtectionConfiguration @mockParams)
        }
    }

    Context "Extended Protection Is Configured On Supported Exchange Version" {
        It "Exchange 2016" {
            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = "15.1.2375.29"
                ApplicationHostConfig = $E16_Configured_ApplicationHost
            }
            TestSupportedConfiguredExtendedProtection (Get-ExtendedProtectionConfiguration @mockParams)
        }

        It "Exchange 2019" {
            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = "15.2.1118.29"
                ApplicationHostConfig = $E19_Configured_ApplicationHost
            }
            TestSupportedConfiguredExtendedProtection (Get-ExtendedProtectionConfiguration @mockParams)
        }
    }
}
