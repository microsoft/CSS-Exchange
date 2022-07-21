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

        It "Should Find A Tls Configuration Majority" {
            $tlsPrerequisites.ReferenceServer | Should -Be "E2k19-1.contoso.lab"
            $tlsPrerequisites.TlsVersions.Count | Should -Be 3
            $tlsPrerequisites.NetVersions.Count | Should -Be 2
        }

        It "Should Successfully Query Tls Settings For All Servers" {
            $tlsPrerequisites.ServerPassed.Count | Should -Be 10
            $tlsPrerequisites.ServerFailed.Count | Should -Be 0
            $tlsPrerequisites.ServerFailedToReach.Count | Should -Be 0
        }

        It "Should Return 2 Actions Required" {
            $tlsPrerequisites.ActionsRequired.Count | Should -Be 2
        }

        It "Should Return A Tls Configuration For Each Tls Version" {
            $tlsPrerequisites.TlsVersions.GetEnumerator() | ForEach-Object {
                $_.ServerEnabled | Should -Be $true
                $_.ClientEnabled | Should -Be $true
            }
        }

        It "Should Return A Tls Configuration For Each .NET Version" {
            $tlsPrerequisites.NetVersions.GetEnumerator() | ForEach-Object {
                $_.SystemDefaultTlsVersions | Should -Be $false
                $_.WowSystemDefaultTlsVersions | Should -Be $false
                $_.SchUseStrongCrypto | Should -Be $false
                $_.WowSchUseStrongCrypto | Should -Be $false
            }
        }
    }

    Context "Executed With An Odd Number Of Servers Returning The Same Tls Configuration" {
        BeforeAll {
            Mock Get-ExchangeServer -MockWith { GetExchangeServer -NumberOfServers 7 }
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

        It "Should Find A Tls Configuration Majority" {
            $tlsPrerequisites.ReferenceServer | Should -Be "E2k19-1.contoso.lab"
            $tlsPrerequisites.TlsVersions.Count | Should -Be 3
            $tlsPrerequisites.NetVersions.Count | Should -Be 2
        }

        It "Should Successfully Query Tls Settings For All Servers" {
            $tlsPrerequisites.ServerPassed.Count | Should -Be 7
            $tlsPrerequisites.ServerFailed.Count | Should -Be 0
            $tlsPrerequisites.ServerFailedToReach.Count | Should -Be 0
        }

        It "Should Return 2 Actions Required" {
            $tlsPrerequisites.ActionsRequired.Count | Should -Be 2
        }

        It "Should Return A Tls Configuration For Each Tls Version" {
            $tlsPrerequisites.TlsVersions.GetEnumerator() | ForEach-Object {
                $_.ServerEnabled | Should -Be $true
                $_.ClientEnabled | Should -Be $true
            }
        }

        It "Should Return A Tls Configuration For Each .NET Version" {
            $tlsPrerequisites.NetVersions.GetEnumerator() | ForEach-Object {
                $_.SystemDefaultTlsVersions | Should -Be $false
                $_.WowSystemDefaultTlsVersions | Should -Be $false
                $_.SchUseStrongCrypto | Should -Be $false
                $_.WowSchUseStrongCrypto | Should -Be $false
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

        It "Should Find A Tls Configuration Majority" {
            $tlsPrerequisites.ReferenceServer | Should -Be "E2k19-2.contoso.lab"
            $tlsPrerequisites.TlsVersions.Count | Should -Be 3
            $tlsPrerequisites.NetVersions.Count | Should -Be 2
        }

        It "Should Successfully Query Tls Settings For Any Other Server" {
            $tlsPrerequisites.ServerPassed.Count | Should -Be 6
            $tlsPrerequisites.ServerFailed.Count | Should -Be 1
            $tlsPrerequisites.ServerFailedToReach.Count | Should -Be 0
        }

        It "Should Return E2k19-1.contoso.lab As Misconfigured Server" {
            $tlsPrerequisites.ServerFailed.Count | Should -Be 1
            $tlsPrerequisites.ServerFailed.ComputerName | Should -Be "E2k19-1.contoso.lab"
            $tlsPrerequisites.ServerFailed.TlsSettings.Count | Should -Be 1
            $tlsPrerequisites.ServerFailed.TlsSettings.GetType() | Should -Be "PSCustomObject"
        }

        It "Should Return A Tls Configuration For Each Tls Version" {
            $tlsPrerequisites.TlsVersions.GetEnumerator() | ForEach-Object {
                $_.ServerEnabled | Should -Be $true
                $_.ClientEnabled | Should -Be $true
            }
        }

        It "Should Return A Tls Configuration For Each .NET Version" {
            $tlsPrerequisites.NetVersions.GetEnumerator() | ForEach-Object {
                $_.SystemDefaultTlsVersions | Should -Be $false
                $_.WowSystemDefaultTlsVersions | Should -Be $false
                $_.SchUseStrongCrypto | Should -Be $false
                $_.WowSchUseStrongCrypto | Should -Be $false
            }
        }
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

        It "Should Find A Tls Configuration Majority" {
            $tlsPrerequisites.ReferenceServer | Should -Be "E2k19-2.contoso.lab"
            $tlsPrerequisites.TlsVersions.Count | Should -Be 3
            $tlsPrerequisites.NetVersions.Count | Should -Be 2
        }

        It "Should Return E2k19-1.contoso.lab And E2k19-5.contoso.lab As Unreachable" {
            $tlsPrerequisites.ServerPassed.Count | Should -Be 5
            $tlsPrerequisites.ServerFailed.Count | Should -Be 0
            $tlsPrerequisites.ServerFailedToReach.Count | Should -Be 2
            $tlsPrerequisites.ServerFailedToReach | Should -Contain "E2k19-1.contoso.lab"
            $tlsPrerequisites.ServerFailedToReach | Should -Contain "E2k19-5.contoso.lab"
        }

        It "Should Return A Tls Configuration For Each Tls Version" {
            $tlsPrerequisites.TlsVersions.GetEnumerator() | ForEach-Object {
                $_.ServerEnabled | Should -Be $true
                $_.ClientEnabled | Should -Be $true
            }
        }

        It "Should Return A Tls Configuration For Each .NET Version" {
            $tlsPrerequisites.NetVersions.GetEnumerator() | ForEach-Object {
                $_.SystemDefaultTlsVersions | Should -Be $false
                $_.WowSystemDefaultTlsVersions | Should -Be $false
                $_.SchUseStrongCrypto | Should -Be $false
                $_.WowSchUseStrongCrypto | Should -Be $false
            }
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

        It "Should Not Find A Tls Configuration Majority" {
            $tlsPrerequisites.ServerPassed.Count | Should -Be 0
            $tlsPrerequisites.ServerFailed.Count | Should -Be 7
            $tlsPrerequisites.ServerFailedToReach.Count | Should -Be 0
            $tlsPrerequisites.ReferenceServer | Should -Be $null
            $tlsPrerequisites.TlsVersions.Count | Should -Be 0
            $tlsPrerequisites.NetVersions.Count | Should -Be 0
        }

        It "Action should be 'No Majority TLS Configuration Found'" {
            $tlsPrerequisites.ActionsRequired.Count | Should -Be 1
            $tlsPrerequisites.ActionsRequired.Name | Should -Be "No majority TLS configuration found"
            $tlsPrerequisites.ActionsRequired.Action | Should -Be "Please ensure that all of your servers are running the same TLS configuration"
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
            $tlsPrerequisites.CheckPassed | Should -Be $true
        }

        It "Should Find A Tls Configuration Majority" {
            $tlsPrerequisites.ReferenceServer | Should -Be "E2k19-1.contoso.lab"
            $tlsPrerequisites.TlsVersions.Count | Should -Be 3
            $tlsPrerequisites.NetVersions.Count | Should -Be 2
        }

        It "Should Successfully Query Tls Settings For All Servers" {
            $tlsPrerequisites.ServerPassed.Count | Should -Be 7
            $tlsPrerequisites.ServerFailed.Count | Should -Be 0
            $tlsPrerequisites.ServerFailedToReach.Count | Should -Be 0
        }

        It "Should Return 0 Actions Required" {
            $tlsPrerequisites.ActionsRequired.Count | Should -Be 0
        }

        It "Should Return A Tls Configuration For Each Tls Version" {
            $tlsPrerequisites.TlsVersions.GetEnumerator() | ForEach-Object {
                $_.ServerEnabled | Should -Be $true
                $_.ClientEnabled | Should -Be $true
            }
        }

        It "Should Return A Tls Configuration For Each .NET Version" {
            $tlsPrerequisites.NetVersions.GetEnumerator() | ForEach-Object {
                if ($_.NetVersion -eq "Netv4") {
                    $_.SystemDefaultTlsVersions | Should -Be $true
                    $_.WowSystemDefaultTlsVersions | Should -Be $true
                    $_.SchUseStrongCrypto | Should -Be $true
                    $_.WowSchUseStrongCrypto | Should -Be $true
                }
            }
        }
    }
}
