# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Test-ExtendedProtectionTlsPrerequisites.ps1

    function Invoke-CatchActions {
        param()
    }

    function Get-ExchangeServer {
        param()
    }

    function Get-AllTlsSettings {
        param(
            [string]$MachineName
        )
    }

    function GetExchangeServer {
        param(
            [int]$NumberOfServers
        )

        $exchangeServerList = New-Object 'System.Collections.Generic.List[object]'
        $i = 0
        do {
            $i++
            $exchangeServerObj = [PSCustomObject]@{
                Name                = "E2k19-$i"
                Fqdn                = "E2k19-$i.contoso.lab"
                AdminDisplayVersion = [System.Version]("15.2.1118.9")
            }

            $exchangeServerList.Add($exchangeServerObj)
        } while ($i -lt $NumberOfServers)

        return $exchangeServerList
    }
}

Describe "Testing Test-ExtendedProtectionTlsPrerequisites.ps1" {

    Context "Executed With An Even Number Of Servers Returning The Same Tls Configuration" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 10 }
            Mock Get-AllTlsSettings -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-AllTlsSettingsDefault.xml }
            $Script:evenNumberOfExchangeServers = Get-ExchangeServer
            $Script:tlsPrerequisites = Test-ExtendedProtectionTlsPrerequisites -ExchangeServers $evenNumberOfExchangeServers
        }

        It "Should Return A PSCustomObject" {
            $tlsPrerequisites.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Find A Tls Configuration Majority" {
            $tlsPrerequisites.TlsComparedInfo.MajorityFound | Should -Be $true
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig | Should -Not -Be $null
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Return Settings For All Servers" {
            $tlsPrerequisites.TlsConfiguration.NumberOfServersPassed | Should -Be 10
            $tlsPrerequisites.TlsConfiguration.NumberOfTlsSettingsReturned | Should -Be 10
            $tlsPrerequisites.TlsConfiguration.UnreachableServers.Count | Should -Be 0
            $tlsPrerequisites.TlsConfiguration.TlsSettingsReturned.Count | Should -Be 10
        }

        It "Should Return A Tls Configuration For Each Tls Version" {
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig.Registry.TLS.GetEnumerator() | ForEach-Object {
                $_.value.ServerEnabled | Should -Be $true
                $_.value.ServerDisabledByDefault | Should -Be $false
                $_.value.ClientEnabled | Should -Be $true
                $_.value.ClientDisabledByDefault | Should -Be $false
                $_.value.TlsConfiguration | Should -Be "Enabled"
            }
        }
    }

    Context "Executed With An Odd Number Of Servers Returning The Same Tls Configuration" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 7 }
            Mock Get-AllTlsSettings -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-AllTlsSettingsDefault.xml }
            $Script:oddNumberOfExchangeServers = Get-ExchangeServer
            $Script:tlsPrerequisites = Test-ExtendedProtectionTlsPrerequisites -ExchangeServers $oddNumberOfExchangeServers
        }

        It "Should Return A PSCustomObject" {
            $tlsPrerequisites.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Find A Tls Configuration Majority" {
            $tlsPrerequisites.TlsComparedInfo.MajorityFound | Should -Be $true
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig | Should -Not -Be $null
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Return Settings For All Servers" {
            $tlsPrerequisites.TlsConfiguration.NumberOfServersPassed | Should -Be 7
            $tlsPrerequisites.TlsConfiguration.NumberOfTlsSettingsReturned | Should -Be 7
            $tlsPrerequisites.TlsConfiguration.UnreachableServers.Count | Should -Be 0
            $tlsPrerequisites.TlsConfiguration.TlsSettingsReturned.Count | Should -Be 7
        }

        It "Should Return A Tls Configuration For Each Tls Version" {
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig.Registry.TLS.GetEnumerator() | ForEach-Object {
                $_.value.ServerEnabled | Should -Be $true
                $_.value.ServerDisabledByDefault | Should -Be $false
                $_.value.ClientEnabled | Should -Be $true
                $_.value.ClientDisabledByDefault | Should -Be $false
                $_.value.TlsConfiguration | Should -Be "Enabled"
            }
        }
    }

    Context "One Server Returns Misconfigured Tls Settings" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 7 }
            Mock Get-AllTlsSettings -ParameterFilter { $MachineName -eq "E2k19-1.contoso.lab" } -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-TlsSettingsMisconfigured.xml }
            Mock Get-AllTlsSettings -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-AllTlsSettingsDefault.xml }

            $Script:oddNumberOfExchangeServers = Get-ExchangeServer
            $Script:tlsPrerequisites = Test-ExtendedProtectionTlsPrerequisites -ExchangeServers $oddNumberOfExchangeServers
        }

        It "Should Return A PSCustomObject" {
            $tlsPrerequisites.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Find A Tls Configuration Majority" {
            $tlsPrerequisites.TlsComparedInfo.MajorityFound | Should -Be $true
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig | Should -Not -Be $null
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Not Return E2k19-1.contoso.lab As Majority Configuration Server" {
            $tlsPrerequisites.TlsComparedInfo.MajorityServer | Should -Not -Be "E2k19-1.contoso.lab"
        }

        It "Should Return E2k19-2.contoso.lab As Majority Configuration Server" {
            $tlsPrerequisites.TlsComparedInfo.MajorityServer | Should -Be "E2k19-2.contoso.lab"
        }

        It "Should Return E2k19-1.contoso.lab As Misconfigured Server" {
            $tlsPrerequisites.TlsComparedInfo.MisconfiguredList.Count | Should -Be 1
            $tlsPrerequisites.TlsComparedInfo.MisconfiguredList.ComputerName | Should -Be "E2k19-1.contoso.lab"
            $tlsPrerequisites.TlsComparedInfo.MisconfiguredList.TlsSettings | Should -Not -Be $null
        }
    }

    Context "Two Servers Are Unreachable" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 7 }
            Mock Get-AllTlsSettings -ParameterFilter { ($MachineName -eq "E2k19-1.contoso.lab") -or ($MachineName -eq "E2k19-5.contoso.lab") } -MockWith { return $null }
            Mock Get-AllTlsSettings -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-AllTlsSettingsDefault.xml }

            $Script:oddNumberOfExchangeServers = Get-ExchangeServer
            $Script:tlsPrerequisites = Test-ExtendedProtectionTlsPrerequisites -ExchangeServers $oddNumberOfExchangeServers
        }

        It "Should Return A PSCustomObject" {
            $tlsPrerequisites.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Find A Tls Configuration Majority" {
            $tlsPrerequisites.TlsComparedInfo.MajorityFound | Should -Be $true
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig | Should -Not -Be $null
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Not Return E2k19-1.contoso.lab or E2k19-5.contoso.lab As Majority Configuration Server" {
            $tlsPrerequisites.TlsComparedInfo.MajorityServer | Should -Not -Be "E2k19-1.contoso.lab"
            $tlsPrerequisites.TlsComparedInfo.MajorityServer | Should -Not -Be "E2k19-5.contoso.lab"
        }

        It "Should Return E2k19-2.contoso.lab As Majority Configuration Server" {
            $tlsPrerequisites.TlsComparedInfo.MajorityServer | Should -Be "E2k19-2.contoso.lab"
        }

        It "Should Return E2k19-1.contoso.lab And E2k19-5.contoso.lab As Unreachable" {
            $tlsPrerequisites.TlsConfiguration.NumberOfServersPassed | Should -Be 7
            $tlsPrerequisites.TlsConfiguration.NumberOfTlsSettingsReturned | Should -Be 5
            $tlsPrerequisites.TlsConfiguration.UnreachableServers.Count | Should -Be 2
            $tlsPrerequisites.TlsConfiguration.TlsSettingsReturned.Count | Should -Be 5
            $tlsPrerequisites.TlsConfiguration.UnreachableServers | Should -Contain "E2k19-1.contoso.lab"
            $tlsPrerequisites.TlsConfiguration.UnreachableServers | Should -Contain "E2k19-5.contoso.lab"
            $tlsPrerequisites.TlsComparedInfo.MisconfiguredList.Count | Should -Be 0
        }
    }

    Context "All Servers Return Misconfigured Tls Settings" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 7 }
            Mock Get-AllTlsSettings -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-TlsSettingsMisconfigured.xml }
            $Script:oddNumberOfExchangeServers = Get-ExchangeServer
            $Script:tlsPrerequisites = Test-ExtendedProtectionTlsPrerequisites -ExchangeServers $oddNumberOfExchangeServers
        }

        It "Should Return A PSCustomObject" {
            $tlsPrerequisites.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Not Find A Tls Configuration Majority" {
            $tlsPrerequisites.TlsComparedInfo.MajorityFound | Should -Be $false
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig | Should -Be $null
            $tlsPrerequisites.TlsComparedInfo.MajorityServer | Should -Be $null
            $tlsPrerequisites.TlsComparedInfo.MisconfiguredList.Count | Should -Be 0
        }
    }

    Context "All Servers Return Recommended Tls Settings" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 7 }
            Mock Get-AllTlsSettings -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-SchUseStrongCryptoConfigured.xml }
            $Script:oddNumberOfExchangeServers = Get-ExchangeServer
            $Script:tlsPrerequisites = Test-ExtendedProtectionTlsPrerequisites -ExchangeServers $oddNumberOfExchangeServers
        }

        It "Should Return A PSCustomObject" {
            $tlsPrerequisites.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Find A Tls Configuration Majority" {
            $tlsPrerequisites.TlsComparedInfo.MajorityFound | Should -Be $true
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig | Should -Not -Be $null
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Return Settings For All Servers" {
            $tlsPrerequisites.TlsConfiguration.NumberOfServersPassed | Should -Be 7
            $tlsPrerequisites.TlsConfiguration.NumberOfTlsSettingsReturned | Should -Be 7
            $tlsPrerequisites.TlsConfiguration.UnreachableServers.Count | Should -Be 0
            $tlsPrerequisites.TlsConfiguration.TlsSettingsReturned.Count | Should -Be 7
        }

        It "Should Return Recommended Tls Settings For .NET 4" {
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig.Registry.NET.GetEnumerator() | ForEach-Object {
                if ($_.key -ne "NETv2") {
                    $_.value.SchUseStrongCrypto | Should -Be $true
                    $_.value.WowSchUseStrongCrypto | Should -Be $true
                    $_.value.SystemDefaultTlsVersions | Should -Be $true
                    $_.value.WowSystemDefaultTlsVersions | Should -Be $true
                }
            }
        }

        It "Should Return Enabled State For Tls 1.0 - 1.2" {
            $tlsPrerequisites.TlsComparedInfo.MajorityConfig.Registry.Tls.GetEnumerator() | ForEach-Object {
                $_.value.ServerEnabled | Should -Be $true
                $_.value.ServerDisabledByDefault | Should -Be $false
                $_.value.ClientEnabled | Should -Be $true
                $_.value.ClientDisabledByDefault | Should -Be $false
                $_.value.TLSConfiguration | Should -Be "Enabled"
            }
        }
    }
}
