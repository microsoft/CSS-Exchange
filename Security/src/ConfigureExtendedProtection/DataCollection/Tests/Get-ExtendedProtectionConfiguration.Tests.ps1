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

    function ConvertXmlToConfig {
        [CmdletBinding()]
        [OutputType("System.Xml.XmlNode")]
        param(
            [string]$Path
        )

        $applicationHostConfigPath = "$env:TEMP\applicationHost.config"

        $xml = New-Object -TypeName xml
        $config = Import-Clixml -Path $Path
        $config | Out-File -Path $applicationHostConfigPath
        $xml.Load($applicationHostConfigPath)

        return $xml
    }

    $Script:buildNumbers = @{
        epUnsupportedExBuildNumber   = "15.0.1497.16"
        epSupportedExBuildNumber2013 = "15.0.1497.37"
        epSupportedExBuildNumber2016 = "15.1.2375.29"
        epSupportedExBuildNumber2019 = "15.2.1118.29"
    }
}

Describe "Testing Get-ExtendedProtectionConfiguration.ps1" {
    BeforeAll {
        $Script:applicationHostEPUnsupportedAndNotConfigured = ConvertXmlToConfig -Path $Script:parentPath\Tests\applicationHostEPUnsupportedAndNotConfigured.xml
        Mock Get-Command { return Import-Clixml -Path $Script:parentPath\Tests\GetCommand.xml }
    }

    Context "No ExSetupVersion Passed To The Function" {
        BeforeAll {
            $mockParams = @{
                ComputerName          = $Server
                ApplicationHostConfig = $applicationHostEPUnsupportedAndNotConfigured
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

        It "Build Unsupported To Run Extended Protection" {
            $extendedProtectionResults.SupportedVersionForExtendedProtection | Should -Be $false
        }
    }

    Context "Extended Protection Is Not Configured On Unsupported Exchange 2013 Build" {
        BeforeAll {
            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = $buildNumbers.epUnsupportedExBuildNumber
                ApplicationHostConfig = $applicationHostEPUnsupportedAndNotConfigured
            }

            $Script:extendedProtectionResults = Get-ExtendedProtectionConfiguration @mockParams
        }

        It "Build Unsupported To Run Extended Protection" {
            $extendedProtectionResults.SupportedVersionForExtendedProtection | Should -Be $false
        }

        It "Extended Protection Is Not Configured" {
            foreach ($e in $extendedProtectionResults.ExtendedProtectionConfiguration) {
                $e.ExtendedProtection | Should -Be "None"
                $e.SupportedExtendedProtection | Should -Be $true
                $e.ExpectedExtendedConfiguration | Should -Be "None"
            }
        }

        It "SSL Settings Are Returned For Default Web Site/PowerShell" {
            foreach ($e in $extendedProtectionResults.ExtendedProtectionConfiguration.Configuration) {
                if ($e.NodePath -eq "Default Web Site/PowerShell") {
                    $e.SslSettings.RequireSsl | Should -Be $false
                    $e.SslSettings.Ssl128Bit | Should -Be $false
                    $e.SslSettings.ClientCertificate | Should -Be "Accept"
                    $e.SslSettings.Value | Should -Be "SslNegotiateCert"
                }
            }
        }

        It "SSL Settings Are Returned For Exchange Back End/PowerShell" {
            foreach ($e in $extendedProtectionResults.ExtendedProtectionConfiguration.Configuration) {
                if ($e.NodePath -eq "Exchange Back End/PowerShell") {
                    $e.SslSettings.RequireSsl | Should -Be $true
                    $e.SslSettings.Ssl128Bit | Should -Be $true
                    $e.SslSettings.ClientCertificate | Should -Be "Accept"
                    $e.SslSettings.Value | Should -Be "Ssl, SslNegotiateCert, Ssl128"
                }
            }
        }
    }

    Context "Extended Protection Is Configured On Supported Exchange 2016 Build" {
        BeforeAll {
            $Script:applicationHostEPSupportedAndConfigured = ConvertXmlToConfig -Path $Script:parentPath\Tests\applicationHostEPSupportedAndConfigured.xml

            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = $buildNumbers.epSupportedExBuildNumber2016
                ApplicationHostConfig = $applicationHostEPSupportedAndConfigured
            }

            $Script:extendedProtectionResults = Get-ExtendedProtectionConfiguration @mockParams
        }

        It "Build Supported To Run Support Extended Protection" {
            $extendedProtectionResults.SupportedVersionForExtendedProtection | Should -Be $true
        }

        It "Extended Protection Is Configured" {
            # Validated on EWS and PowerShell (Front- and Back End)
            # Test must be adjusted once the values are finally confirmed
            foreach ($e in $extendedProtectionResults.ExtendedProtectionConfiguration) {
                $configuration = $e.configuration
                if ($configuation.NodePath -eq "Default Web Site/EWS") {
                    $e.ExtendedProtection | Should -Be "Allow"
                    $e.SupportedExtendedProtection | Should -Be $true
                    $e.ExpectedExtendedConfiguration | Should -Be "Allow"
                    $configuration.SslSettings.RequireSsl | Should -Be $true
                    $configuration.SslSettings.Ssl128Bit | Should -Be $true
                    $configuration.SslSettings.ClientCertificate | Should -Be "Accept"
                    $configuration.SslSettings.Value | Should -Be "Ssl, SslNegotiateCert, Ssl128"
                } elseif ($configuration.NodePath -eq "Exchange Back End/EWS") {
                    $e.ExtendedProtection | Should -Be "Require"
                    $e.SupportedExtendedProtection | Should -Be $true
                    $e.ExpectedExtendedConfiguration | Should -Be "Require"
                    $configuration.SslSettings.RequireSsl | Should -Be $true
                    $configuration.SslSettings.Ssl128Bit | Should -Be $true
                    $configuration.SslSettings.ClientCertificate | Should -Be "Ignore"
                    $configuration.SslSettings.Value | Should -Be "Ssl, Ssl128"
                } elseif ($configuration.NodePath -eq "Default Web Site/PowerShell ") {
                    $e.ExtendedProtection | Should -Be "Require"
                    $e.SupportedExtendedProtection | Should -Be $true
                    $e.ExpectedExtendedConfiguration | Should -Be "Require"
                    $configuration.SslSettings.RequireSsl | Should -Be $false
                    $configuration.SslSettings.Ssl128Bit | Should -Be $false
                    $configuration.SslSettings.ClientCertificate | Should -Be "Accept"
                    $configuration.SslSettings.Value | Should -Be "SslNegotiateCert"
                } elseif ($configuration.NodePath -eq "Exchange Back End/PowerShell") {
                    $e.ExtendedProtection | Should -Be "Require"
                    $e.SupportedExtendedProtection | Should -Be $true
                    $e.ExpectedExtendedConfiguration | Should -Be "Require"
                    $configuration.SslSettings.RequireSsl | Should -Be $true
                    $configuration.SslSettings.Ssl128Bit | Should -Be $true
                    $configuration.SslSettings.ClientCertificate | Should -Be "Accept"
                    $configuration.SslSettings.Value | Should -Be "Ssl, SslNegotiateCert, Ssl128"
                }
            }
        }
    }

    Context "Insecure Extended Protection Configuration On Supported Exchange 2019 Build" {
        BeforeAll {
            $Script:applicationHostEPSupportedButMisconfigured = ConvertXmlToConfig -Path $Script:parentPath\Tests\applicationHostEPSupportedButMisconfigured.xml

            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = $buildNumbers.epSupportedExBuildNumber2019
                ApplicationHostConfig = $applicationHostEPSupportedButMisconfigured
            }

            $Script:extendedProtectionResults = Get-ExtendedProtectionConfiguration @mockParams
        }

        It "Build Supported To Run Support Extended Protection" {
            $extendedProtectionResults.SupportedVersionForExtendedProtection | Should -Be $true
        }

        It "Extended Protection Is Not Configured On Powershell Back-End" {
            foreach ($e in $extendedProtectionResults.ExtendedProtectionConfiguration) {
                $configuration = $e.configuration
                if ($configuration.NodePath -eq "Exchange Back End/Powershell") {
                    $e.ExtendedProtection | Should -Be "None"
                    $e.SupportedExtendedProtection | Should -Be $false
                    $e.ExpectedExtendedConfiguration | Should -Be "Require"
                    $configuration.SslSettings.RequireSsl | Should -Be $true
                    $configuration.SslSettings.Ssl128Bit | Should -Be $true
                    $configuration.SslSettings.ClientCertificate | Should -Be "Accept"
                    $configuration.SslSettings.Value | Should -Be "Ssl, SslNegotiateCert, Ssl128"
                }
            }
        }
    }

    Context "Secure Extended Protection Configuration On Unsupported Exchange 2013 Build" {
        BeforeAll {
            $Script:applicationHostEPUnsupportedAndConfigured = ConvertXmlToConfig -Path $Script:parentPath\Tests\applicationHostEPUnsupportedAndConfigured.xml

            $mockParams = @{
                ComputerName          = $Server
                ExSetupVersion        = $buildNumbers.epUnsupportedExBuildNumber
                ApplicationHostConfig = $applicationHostEPUnsupportedAndConfigured
            }

            $Script:extendedProtectionResults = Get-ExtendedProtectionConfiguration @mockParams
        }

        It "Build Unsupported To Run Extended Protection" {
            $extendedProtectionResults.SupportedVersionForExtendedProtection | Should -Be $false
        }

        It "Extended Protection Is Configured On Multiple vDirs But Unsupported" {
            foreach ($e in $extendedProtectionResults.ExtendedProtectionConfiguration) {
                $configuration = $e.configuration
                if (($configuration.NodePath -notlike "*/Autodiscover") -and
                    ($configuration.NodePath -notlike "*/EWS")) {
                    $e.ExtendedProtection | Should -Be "Require"
                    $e.SupportedExtendedProtection | Should -Be $false
                    $e.ExpectedExtendedConfiguration | Should -Be "None"
                }
            }
        }
    }
}
