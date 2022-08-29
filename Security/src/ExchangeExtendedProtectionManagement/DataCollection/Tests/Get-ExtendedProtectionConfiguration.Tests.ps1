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
            [object]$TestingExtendedProtectionResults,
            [int]$ExtendedProtectionNoneCount = 21,
            [int]$ExpectedExtendedProtectionNoneCount = 21,
            [bool]$SkipAllow = $false,
            [bool]$SkipAutoDiscover = $false,
            [bool]$IPFilterEnabled = $false,
            [string]$IPFilteredvDir = $null,
            [string[]]$AllowedIpAddresses
        )

        $TestingExtendedProtectionResults.SupportedVersionForExtendedProtection | Should -Be $true
        ($TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
            Where-Object { $_.ExtendedProtection -ne "None" }).count |
                Should -Be $ExtendedProtectionNoneCount
        ($TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
            Where-Object { $_.ExpectedExtendedConfiguration -ne "None" }).count |
                Should -Be $ExpectedExtendedProtectionNoneCount
        if ($IPFilterEnabled -eq $false) {
            $TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
                Where-Object { $_.SupportedExtendedProtection -eq $false } |
                Should -Be $null
        } else {
            ($TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
                Where-Object { $_.SupportedExtendedProtection -eq $false }).Count |
                    Should -Be 1
        }
        # Special configs
        if (-not $SkipAllow) {
            $allow = $TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
                Where-Object { $_.ExtendedProtection -eq "Allow" }
            $null -ne $allow | Should -Be $true
            $allow.Count | Should -Be 2
            $allow.configuration.NodePath.Contains("Default Web Site/EWS") | Should -Be $true
            $allow.configuration.NodePath.Contains("Default Web Site/Microsoft-Server-ActiveSync") | Should -Be $true
        }

        if (-not $SkipAutoDiscover) {
            $none = $TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
                Where-Object { $_.ExtendedProtection -eq "None" }
            $null -ne $none | Should -Be $true
            $none.Count | Should -Be 2
            $none.Configuration.NodePath.Contains("Default Web Site/Autodiscover") | Should -Be $true
            $none.Configuration.NodePath.Contains("Exchange Back End/Autodiscover") | Should -Be $true
        }

        if ($IPFilterEnabled) {
            $ipFilter = $TestingExtendedProtectionResults.ExtendedProtectionConfiguration |
                Where-Object {
                    ($_.ExtendedProtection -eq "None") -and
                    ($_.VirtualDirectoryName -eq $IPFilteredvDir)
                }
            $ipFilter.MitigationEnabled | Should -Be $true
            $ipFilter.ProperlySecuredConfiguration | Should -Be $true
            $ipFilter.Configuration.MitigationSettings.AllowUnlisted | Should -Be "false"
            $ipFilter.Configuration.MitigationSettings.Restrictions.keys.Count | Should -Be $AllowedIpAddresses.Count
            ($ipFilter.Configuration.MitigationSettings.Restrictions.GetEnumerator() |
                Where-Object { $_.key -in $AllowedIpAddresses }).Count | Should -Be $AllowedIpAddresses.Count
            $ipFilter.Configuration.MitigationSettings.Restrictions.values | Should -Not -Contain "false"
        }
    }

    $Script:E15_NotConfigured_Both_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E15_NotConfigured_Both_ApplicationHost.config
    $Script:E15_NotConfigured_Cas_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E15_NotConfigured_Cas_ApplicationHost.config
    $Script:E15_NotConfigured_Mbx_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E15_NotConfigured_Mbx_ApplicationHost.config
    $Script:E16_NotConfigured_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E16_NotConfigured_ApplicationHost.config
    $Script:E19_NotConfigured_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E19_NotConfigured_ApplicationHost.config

    $Script:E15_Configured_Both_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E15_Configured_Both_ApplicationHost.config
    $Script:E15_Configured_Cas_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E15_Configured_Cas_ApplicationHost.config
    $Script:E15_Configured_Mbx_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E15_Configured_Mbx_ApplicationHost.config
    $Script:E16_Configured_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E16_Configured_ApplicationHost.config
    $Script:E16_Configured_IPFilter_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E16_Configured_IPFilter_ApplicationHost.config
    $Script:E19_Configured_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E19_Configured_ApplicationHost.config
    $Script:E19_Configured_IPFilter_ApplicationHost = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E19_Configured_IPFilter_ApplicationHost.config

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
                IsMailboxServer       = $false
                ApplicationHostConfig = $E15_NotConfigured_Cas_ApplicationHost
            }
            TestUnsupportedNotConfiguredExtendedProtection (Get-ExtendedProtectionConfiguration @mockParams)
        }

        It "Exchange 2013 Mbx" {
            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = "15.00.1497.036"
                IsClientAccessServer  = $false
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
        It "Exchange 2013 Mbx/Cas" {
            $mockParams = @{
                ComputerName          = $server
                ExSetupVersion        = "15.00.1497.038"
                ApplicationHostConfig = $E15_Configured_Both_ApplicationHost
            }
            TestSupportedConfiguredExtendedProtection -TestingExtendedProtectionResults (Get-ExtendedProtectionConfiguration @mockParams) -ExtendedProtectionNoneCount 19 -ExpectedExtendedProtectionNoneCount 19
        }

        It "Exchange 2013 Cas" {
            $mockParams = @{
                ComputerName          = $server
                ExSetupVersion        = "15.00.1497.038"
                IsMailboxServer       = $false
                ApplicationHostConfig = $E15_Configured_Cas_ApplicationHost
            }
            TestSupportedConfiguredExtendedProtection -TestingExtendedProtectionResults (Get-ExtendedProtectionConfiguration @mockParams) -ExtendedProtectionNoneCount 9 -ExpectedExtendedProtectionNoneCount 9 -SkipAutoDiscover $true
        }

        It "Exchange 2013 Mbx" {
            $mockParams = @{
                ComputerName          = $server
                ExSetupVersion        = "15.00.1497.038"
                IsClientAccessServer  = $false
                ApplicationHostConfig = $E15_Configured_Mbx_ApplicationHost
            }
            TestSupportedConfiguredExtendedProtection -TestingExtendedProtectionResults (Get-ExtendedProtectionConfiguration @mockParams) -ExtendedProtectionNoneCount 12 -ExpectedExtendedProtectionNoneCount 12 -SkipAllow $true -SkipAutoDiscover $true
        }

        It "Exchange 2016" {
            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = "15.1.2375.30"
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

    Context "Extended Protection Is Configured On Supported Exchange Version And IP Filter Is Configured" {
        It "Exchange 2016 - IPs filtered: Exchange Back End/EWS" {
            $epMockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = "15.2.1118.29"
                ApplicationHostConfig = $E16_Configured_IPFilter_ApplicationHost
            }
            $e16ExtendedProtectionResults = Get-ExtendedProtectionConfiguration @epMockParams

            $mockParams = @{
                TestingExtendedProtectionResults = $e16ExtendedProtectionResults
                ExtendedProtectionNoneCount      = 20
                SkipAutoDiscover                 = $true
                IPFilterEnabled                  = $true
                IPFilteredvDir                   = "Exchange Back End/EWS"
                AllowedIpAddresses               = "192.168.100.5", "fe80::de2:4f45:21dc:6c5a%14", "::1", "127.0.0.1"
            }
            TestSupportedConfiguredExtendedProtection @mockParams
        }

        It "Exchange 2019 - IPs filtered: Exchange Back End/EWS" {
            $epMockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = "15.2.1118.29"
                ApplicationHostConfig = $E19_Configured_IPFilter_ApplicationHost
            }
            $e19ExtendedProtectionResults = Get-ExtendedProtectionConfiguration @epMockParams

            $mockParams = @{
                TestingExtendedProtectionResults = $e19ExtendedProtectionResults
                ExtendedProtectionNoneCount      = 20
                SkipAutoDiscover                 = $true
                IPFilterEnabled                  = $true
                IPFilteredvDir                   = "Exchange Back End/EWS"
                AllowedIpAddresses               = "192.168.100.5", "fe80::de2:4f45:21dc:6c5a%14", "::1", "127.0.0.1"
            }
            TestSupportedConfiguredExtendedProtection @mockParams
        }
    }

    Context "Supported/Unsupported Versions Tests" {
        BeforeAll {
            function TestVersionSupportedOnly {
                param(
                    [string]$Version,
                    [bool]$Supported
                )

                $mockParams = @{
                    ComputerName          = $Server
                    ExSetupVersion        = $Version
                    ApplicationHostConfig = $E19_Configured_ApplicationHost
                }

                (Get-ExtendedProtectionConfiguration @mockParams).SupportedVersionForExtendedProtection | Should -Be $Supported
            }
        }

        It "15.02.1119.011 - Supported" {
            TestVersionSupportedOnly "15.02.1119.011" $true
        }

        It "15.02.1118.011 - Supported" {
            TestVersionSupportedOnly "15.02.1118.011" $true
        }

        It "15.02.1118.010 - Unsupported" {
            TestVersionSupportedOnly "15.02.1118.010" $false
        }

        It "15.02.0986.029 - Supported" {
            TestVersionSupportedOnly "15.02.0986.029" $true
        }

        It "15.02.0986.028 - Supported" {
            TestVersionSupportedOnly "15.02.0986.028" $true
        }

        It "15.02.0986.027 - Unsupported" {
            TestVersionSupportedOnly "15.02.0986.027" $false
        }

        It "15.01.2508.011 - Supported" {
            TestVersionSupportedOnly "15.01.2508.011" $true
        }

        It "15.01.2507.011 - Supported" {
            TestVersionSupportedOnly "15.01.2507.011" $true
        }

        It "15.01.2507.010 - Unsupported" {
            TestVersionSupportedOnly "15.01.2507.010" $false
        }

        It "15.01.2375.031 - Supported" {
            TestVersionSupportedOnly "15.01.2375.031" $true
        }

        It "15.01.2375.030 - Supported" {
            TestVersionSupportedOnly "15.01.2375.030" $true
        }

        It "15.01.2375.029 - Unsupported" {
            TestVersionSupportedOnly "15.01.2375.029" $false
        }

        It "15.00.1498.038 - Supported" {
            TestVersionSupportedOnly "15.00.1498.038" $true
        }

        It "15.00.1497.038 - Supported" {
            TestVersionSupportedOnly "15.00.1497.038" $true
        }

        It "15.00.1497.037 - Unsupported" {
            TestVersionSupportedOnly "15.00.1497.037" $false
        }
    }
}
