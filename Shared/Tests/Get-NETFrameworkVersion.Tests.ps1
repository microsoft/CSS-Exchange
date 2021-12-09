# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    $parent = Split-Path -Parent $PSScriptRoot
    $scriptName = "Get-NETFrameworkVersion.ps1"

    . "$parent\$scriptName"
}

Describe "Testing $scriptName" {

    Context "Passing Values" {

        It "Unknown Result" {
            $result = Get-NETFrameworkVersion -NetVersionKey 3783
            $result.FriendlyName | Should -Be "Unknown"
            $result.MinimumValue | Should -Be -1
            $result.RegistryValue | Should -Be 3783
        }

        It ".NET 4.5" {
            $value = 378389
            $result = Get-NETFrameworkVersion -NetVersionKey ($value + 1)
            $result.FriendlyName | Should -Be "4.5"
            $result.MinimumValue | Should -Be $value
            $result.RegistryValue | Should -Be ($value + 1)
        }

        It ".NET 4.5.1" {
            $value = 378675
            $result = Get-NETFrameworkVersion -NetVersionKey ($value + 1)
            $result.FriendlyName | Should -Be "4.5.1"
            $result.MinimumValue | Should -Be $value
            $result.RegistryValue | Should -Be ($value + 1)
        }

        It ".NET 4.5.2" {
            $value = 379893
            $result = Get-NETFrameworkVersion -NetVersionKey ($value + 1)
            $result.FriendlyName | Should -Be "4.5.2"
            $result.MinimumValue | Should -Be $value
            $result.RegistryValue | Should -Be ($value + 1)
        }

        It ".NET 4.6" {
            $value = 393295
            $result = Get-NETFrameworkVersion -NetVersionKey ($value + 1)
            $result.FriendlyName | Should -Be "4.6"
            $result.MinimumValue | Should -Be $value
            $result.RegistryValue | Should -Be ($value + 1)
        }

        It ".NET 4.6.1" {
            $value = 394254
            $result = Get-NETFrameworkVersion -NetVersionKey ($value + 1)
            $result.FriendlyName | Should -Be "4.6.1"
            $result.MinimumValue | Should -Be $value
            $result.RegistryValue | Should -Be ($value + 1)
        }

        It ".NET 4.6.2" {
            $value = 394802
            $result = Get-NETFrameworkVersion -NetVersionKey ($value + 1)
            $result.FriendlyName | Should -Be "4.6.2"
            $result.MinimumValue | Should -Be $value
            $result.RegistryValue | Should -Be ($value + 1)
        }

        It ".NET 4.7" {
            $value = 460798
            $result = Get-NETFrameworkVersion -NetVersionKey ($value + 1)
            $result.FriendlyName | Should -Be "4.7"
            $result.MinimumValue | Should -Be $value
            $result.RegistryValue | Should -Be ($value + 1)
        }

        It ".NET 4.7.1" {
            $value = 461308
            $result = Get-NETFrameworkVersion -NetVersionKey ($value + 1)
            $result.FriendlyName | Should -Be "4.7.1"
            $result.MinimumValue | Should -Be $value
            $result.RegistryValue | Should -Be ($value + 1)
        }

        It ".NET 4.7.2" {
            $value = 461808
            $result = Get-NETFrameworkVersion -NetVersionKey ($value + 1)
            $result.FriendlyName | Should -Be "4.7.2"
            $result.MinimumValue | Should -Be $value
            $result.RegistryValue | Should -Be ($value + 1)
        }

        It ".NET 4.8" {
            $value = 528040
            $result = Get-NETFrameworkVersion -NetVersionKey ($value + 1)
            $result.FriendlyName | Should -Be "4.8"
            $result.MinimumValue | Should -Be $value
            $result.RegistryValue | Should -Be ($value + 1)
        }
    }

    Context "Get Local .NET Version and debug" {

        It "Testing local get and verbose" {
            Mock Write-Verbose {}

            $result = Get-NETFrameworkVersion
            $result.FriendlyName | Should -Not -Be "Unknown"
            $result.MinimumValue | Should -Not -Be -1
            $result.RegistryValue | Should -Not -Be -1

            Assert-MockCalled -CommandName Write-Verbose -Exactly 10
            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -eq "Calling: Get-NETFrameworkVersion" }
            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -like "FriendlyName: * | RegistryValue: * | MinimumValue: *" }
        }

        It "Testing a catch script block" {

            Function Write-CustomScriptBlock {
                Write-Host "Write-CustomScriptBlock"
            }

            Mock Get-RemoteRegistrySubKey { throw "pester testing failure" }
            Mock Write-Host {}

            $result = Get-NETFrameworkVersion -CatchActionFunction ${Function:Write-CustomScriptBlock}
            $result.FriendlyName | Should -Be "Unknown"
            $result.MinimumValue | Should -Be -1
            $result.RegistryValue | Should -Be 0

            Assert-MockCalled -CommandName Write-Host -Exactly 1 -ParameterFilter { $Object -eq "Write-CustomScriptBlock" }
        }
    }
}
