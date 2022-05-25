# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\..\..\Helpers\Class.ps1
    . $Script:parentPath\Get-ExtendedProtectionConfiguration.ps1

    function Invoke-CatchActions {
        param()
    }

    function LoadXml {
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

    $Script:buildObject = ([HealthChecker.ExchangeBuildInformation]@{
            MajorVersion  = [HealthChecker.ExchangeMajorVersion]::Exchange2013
            ExchangeSetup = [PSCustomObject]@{
                FileVersion = "15.0.1497.16"
            }
        })
}

Describe "Testing Get-ExtendedProtectionConfiguration.ps1" {
    BeforeAll {
        Mock LoadXml -MockWith { return ConvertXmlToConfig -Path $Script:parentPath\Tests\applicationHostEPUnsupportedAndNotConfigured.xml }
    }

    Context "Insecure Extended Protection Configuration On Unsupported Build" {
        BeforeAll {
            $Script:extendedProtectionResults = Get-ExtendedProtectionConfiguration -ComputerName $Script:Server -BuildInformationObject $buildObject
        }

        It "Build Unsupported To Run Support Extended Protection" {
            $buildObject.IsEPSupportedBuild | Should -Be $false
        }

        It "Extended Protection Is Not Configured" {
            foreach ($e in $extendedProtectionResults.ExtendedProtectionConfig) {
                $e.MaxSupportedValue | Should -Be "None"
                $e.ExtendedProtection | Should -Be "None"
                $e.ConfigSupported | Should -Be $true
                $e.CheckPass | Should -Be $true
            }
        }
    }

    Context "Secure Extended Protection Configuration On Supported Build" {
        BeforeAll {
            $buildObject.ExchangeSetup.FileVersion  = "15.0.1497.36"
            Mock LoadXml -MockWith { return ConvertXmlToConfig -Path $Script:parentPath\Tests\applicationHostEPSupportedAndConfigured.xml }
            $Script:extendedProtectionResults = Get-ExtendedProtectionConfiguration -ComputerName $Script:Server -BuildInformationObject $buildObject
        }

        It "Build Supported To Run Support Extended Protection" {
            $buildObject.IsEPSupportedBuild | Should -Be $true
        }

        It "Extended Protection Is Configured" {
            foreach ($e in $extendedProtectionResults.ExtendedProtectionConfig) {
                if ($e.vDir -eq "Autodiscover") {
                    $e.MaxSupportedValue | Should -Be "None"
                    $e.ExtendedProtection | Should -Be "None"
                    $e.ConfigSupported | Should -Be $true
                    $e.CheckPass | Should -Be $true
                } elseif ($e.vDir -eq "EWS") {
                    if ($e.Type -eq "Default Web Site") {
                        $e.MaxSupportedValue | Should -Be "Allow"
                        $e.ExtendedProtection | Should -Be "Allow"
                        $e.ConfigSupported | Should -Be $true
                        $e.CheckPass | Should -Be $true
                    } else {
                        $e.MaxSupportedValue | Should -Be "Require"
                        $e.ExtendedProtection | Should -Be "Require"
                        $e.ConfigSupported | Should -Be $true
                        $e.CheckPass | Should -Be $true
                    }
                } else {
                    $e.MaxSupportedValue | Should -Be "Require"
                    $e.ExtendedProtection | Should -Be "Require"
                    $e.ConfigSupported | Should -Be $true
                    $e.CheckPass | Should -Be $true
                }
            }
        }

        It "Validating Different SSL Configurations On vDirs" {
            foreach ($e in $extendedProtectionResults.ExtendedProtectionConfig) {
                if ($e.vDir -eq "Powershell") {
                    if ($e.Type -eq "Default Web Site") {
                        $e.SSLConfiguration.RequireSSL | Should -Be $false
                        $e.SSLConfiguration.SSL128Bit | Should -Be $false
                        $e.SSLConfiguration.ClientCertificates | Should -Be "Accept"
                    } else {
                        $e.SSLConfiguration.RequireSSL | Should -Be $true
                        $e.SSLConfiguration.SSL128Bit | Should -Be $true
                        $e.SSLConfiguration.ClientCertificates | Should -Be "Accept"
                    }
                } elseif ($e.vDir -eq "Autodiscover") {
                    $e.SSLConfiguration.RequireSSL | Should -Be $true
                    $e.SSLConfiguration.SSL128Bit | Should -Be $true
                    $e.SSLConfiguration.ClientCertificates | Should -Be "Ignore"
                }
            }
        }
    }

    Context "Insecure Extended Protection Configuration On Supported Build" {
        BeforeAll {
            Mock LoadXml -MockWith { return ConvertXmlToConfig -Path $Script:parentPath\Tests\applicationHostEPSupportedButMisconfigured.xml }
            $Script:extendedProtectionResults = Get-ExtendedProtectionConfiguration -ComputerName $Script:Server -BuildInformationObject $buildObject
        }

        It "Build Supported To Run Support Extended Protection" {
            $buildObject.IsEPSupportedBuild | Should -Be $true
        }

        It "Extended Protection Is Not Configured On PowerShell vDir" {
            foreach ($e in $extendedProtectionResults.ExtendedProtectionConfig) {
                if ($e.vDir -eq "Powershell") {
                    $e.MaxSupportedValue | Should -Be "Require"
                    $e.ExtendedProtection | Should -Be "None"
                    $e.ConfigSupported | Should -Be $true
                    $e.CheckPass | Should -Be $false
                }
            }
        }
    }

    Context "Secure Extended Protection Configuration On Unsupported Build" {
        BeforeAll {
            $buildObject.ExchangeSetup.FileVersion  = "15.1.2507.8"
            $buildObject.MajorVersion = [HealthChecker.ExchangeMajorVersion]::Exchange2016
            Mock LoadXml -MockWith { return ConvertXmlToConfig -Path $Script:parentPath\Tests\applicationHostEPUnsupportedAndConfigured.xml }
            $Script:extendedProtectionResults = Get-ExtendedProtectionConfiguration -ComputerName $Script:Server -BuildInformationObject $buildObject
        }

        It "Build Unsupported To Run Support Extended Protection" {
            $buildObject.IsEPSupportedBuild | Should -Be $false
        }

        It "Extended Protection Is Configured But Unsupported" {
            foreach ($e in $extendedProtectionResults.ExtendedProtectionConfig) {
                if (($e.vDir -ne "Autodiscover") -and
                (($e.vDir -ne "EWS") -and ($e.Type -ne "Default Web Site"))) {
                    $e.MaxSupportedValue | Should -Be "None"
                    $e.ExtendedProtection | Should -Be "Require"
                    $e.ConfigSupported | Should -Be $false
                    $e.CheckPass | Should -Be $false
                }
            }
        }
    }
}
