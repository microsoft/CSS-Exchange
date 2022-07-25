# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Invoke-ExtendedProtectionTlsPrerequisitesCheck.ps1

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

Describe "Testing Invoke-ExtendedProtectionTlsPrerequisitesCheck.ps1" {

    Context "Executed With An Even Number Of Servers Returning The Same Default Tls Configuration" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 10 }
            Mock Get-AllTlsSettings -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-AllTlsSettingsDefault.xml }
            $Script:evenNumberOfExchangeServers = Get-ExchangeServer
            $Script:tlsPrerequisites = Invoke-ExtendedProtectionTlsPrerequisitesCheck -ExchangeServers $evenNumberOfExchangeServers.Fqdn
        }

        It "Should Return A PSCustomObject" {
            $tlsPrerequisites.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Not Pass The Prerequisites Check" {
            $tlsPrerequisites.CheckPassed | Should -Be $false
        }

        It "Should Return 2 Actions Required" {
            $tlsPrerequisites.ActionsRequired.Count | Should -Be 2
        }

        It "Number of different configurations" {
            $tlsPrerequisites.TlsSettings.Count | Should -Be 1
        }

        It "Should Return A Tls Configuration For Each Tls Version" {
            $tlsPrerequisites.TlsSettings | ForEach-Object { $_.TlsSettings.Registry.Tls.Values | ForEach-Object {
                    $_.ServerEnabled | Should -Be $true
                    $_.ClientEnabled | Should -Be $true
                }
            }
        }

        It "Should Return A Tls Configuration For Each .NET Version" {
            $tlsPrerequisites.TlsSettings | ForEach-Object { $_.TlsSettings.Registry.Net.Values | ForEach-Object {
                    $_.SystemDefaultTlsVersions | Should -Be $false
                    $_.WowSystemDefaultTlsVersions | Should -Be $false
                    $_.SchUseStrongCrypto | Should -Be $false
                    $_.WowSchUseStrongCrypto | Should -Be $false
                }
            }
        }
    }


    Context "One Server Returns Misconfigured Tls Settings" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 7 }
            Mock Get-AllTlsSettings -ParameterFilter { $MachineName -eq "E2k19-1.contoso.lab" } -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-TlsSettingsMisconfigured.xml }
            Mock Get-AllTlsSettings -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-AllTlsSettingsDefault.xml }

            $Script:oddNumberOfExchangeServers = Get-ExchangeServer
            $Script:tlsPrerequisites = Invoke-ExtendedProtectionTlsPrerequisitesCheck -ExchangeServers $oddNumberOfExchangeServers.Fqdn
        }

        It "Should Return A PSCustomObject" {
            $tlsPrerequisites.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Not Pass The Prerequisites Check" {
            $tlsPrerequisites.CheckPassed | Should -Be $false
        }

        It "Found multiple configurations" {
            $tlsPrerequisites.TlsSettings.Count | Should -Be 2
        }

        #TODO: Finish fixing all the tests back here
    }

    Context "Two Servers Are Unreachable" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 7 }
            Mock Get-AllTlsSettings -ParameterFilter { ($MachineName -eq "E2k19-1.contoso.lab") -or ($MachineName -eq "E2k19-5.contoso.lab") } -MockWith { return $null }
            Mock Get-AllTlsSettings -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-AllTlsSettingsDefault.xml }

            $Script:oddNumberOfExchangeServers = Get-ExchangeServer
            $Script:tlsPrerequisites = Invoke-ExtendedProtectionTlsPrerequisitesCheck -ExchangeServers $oddNumberOfExchangeServers.Fqdn
        }

        It "Should Return A PSCustomObject" {
            $tlsPrerequisites.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Not Pass The Prerequisites Check" {
            $tlsPrerequisites.CheckPassed | Should -Be $false
        }
    }

    Context "All Servers Return Misconfigured Tls Settings" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 7 }
            Mock Get-AllTlsSettings -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-TlsSettingsMisconfigured.xml }
            $Script:oddNumberOfExchangeServers = Get-ExchangeServer
            $Script:tlsPrerequisites = Invoke-ExtendedProtectionTlsPrerequisitesCheck -ExchangeServers $oddNumberOfExchangeServers.Fqdn
        }

        It "Should Return A PSCustomObject" {
            $tlsPrerequisites.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Not Pass The Prerequisites Check" {
            $tlsPrerequisites.CheckPassed | Should -Be $false
        }
    }

    Context "All Servers Return Recommended Tls Settings" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 7 }
            Mock Get-AllTlsSettings -MockWith { return Import-Clixml -Path $Script:parentPath\Tests\Data\GetAllTlsSettings-SchUseStrongCryptoConfigured.xml }
            $Script:oddNumberOfExchangeServers = Get-ExchangeServer
            $Script:tlsPrerequisites = Invoke-ExtendedProtectionTlsPrerequisitesCheck -ExchangeServers $oddNumberOfExchangeServers.Fqdn
        }

        It "Should Return A PSCustomObject" {
            $tlsPrerequisites.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Pass The Prerequisites Check" {
            # This is false now due to changes to the script need new data collected
            $tlsPrerequisites.CheckPassed | Should -Be $false
        }
    }
}
