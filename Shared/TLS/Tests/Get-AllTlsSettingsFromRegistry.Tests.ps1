# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

Describe "Testing Get-AllTlsSettingsFromRegistry.ps1" {

    BeforeAll {
        . $PSScriptRoot\..\Get-AllTlsSettingsFromRegistry.ps1
        $Script:tlsServer10 = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
        $Script:tlsServer11 = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
        $Script:tlsServer12 = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
        $Script:tlsServer13 = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"
        $Script:tlsClient10 = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
        $Script:tlsClient11 = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
        $Script:tlsClient12 = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
        $Script:tlsClient13 = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
        $Script:net4 = "SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
        $Script:net4Wow = "SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        $Script:net2 = "SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
        $Script:net2Wow = "SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"
        $Script:enabledKey = "Enabled"

        function SetVariables {
            $Script:result = Get-AllTlsSettingsFromRegistry
            $Script:tls10 = $result.TLS["1.0"]
            $Script:tls11 = $result.TLS["1.1"]
            $Script:tls12 = $result.TLS["1.2"]
            $Script:tls13 = $result.TLS["1.3"]
            $Script:netV4 = $result.NET["NETv4"]
            $Script:netV2 = $result.NET["NETv2"]
        }

        function TestObjectCompare {
            param(
                [object]$CompareObject,
                [object]$TestObject
            )
            $properties = ($CompareObject | Get-Member | Where-Object { $_.MemberType -eq "NoteProperty" }).Name
            foreach ($property in $properties) {
                if ($TestObject.$property -ne $CompareObject.$property) {
                    Write-Host "Failed Property: $property"
                }
                $TestObject.$property | Should -Be $CompareObject.$property
            }
        }
    }

    Context "Testing Normal TLS Settings" {

        BeforeAll {
            Mock Get-RemoteRegistryValue {
                param (
                    [string]$MachineName,
                    [string]$SubKey,
                    [string]$GetValue,
                    [string]$ValueType,
                    [ScriptBlock]$CatchActionFunction
                )

                if ($SubKey -eq $Script:tlsServer10) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:tlsServer11) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:tlsServer12) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:tlsServer13) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:tlsClient10) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:tlsClient11) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:tlsClient12) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:tlsClient13) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:net4) {
                    return 0
                } elseif ($SubKey -eq $Script:net4Wow) {
                    return 0
                } elseif ($SubKey -eq $Script:net2) {
                    return 0
                } elseif ($SubKey -eq $Script:net2Wow) {
                    return 0
                } else {
                    throw "FAILED to find SubKey"
                }
            }

            SetVariables

            $Script:tlsCompareObject = [PSCustomObject]@{
                ServerEnabled           = $true
                ClientEnabled           = $true
                ServerDisabledByDefault = $false
                ClientDisabledByDefault = $false
                TLSConfiguration        = "Enabled"
            }

            $Script:netCompareObject = [PSCustomObject]@{
                SystemDefaultTlsVersions    = $false
                SchUseStrongCrypto          = $false
                WowSystemDefaultTlsVersions = $false
                WowSchUseStrongCrypto       = $false
                SDtvConfiguredCorrectly     = $true
                SDtvEnabled                 = $false
            }
        }

        It "TLS 1.0 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls10
        }

        It "TLS 1.1 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls11
        }

        It "TLS 1.2 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls12
        }

        It "TLS 1.3 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls13
        }

        It "NET v4 Testing Values" {
            TestObjectCompare $Script:netCompareObject $netV4
        }

        It "NET v2 Testing Values" {
            TestObjectCompare $Script:netCompareObject $netV2
        }
    }

    Context "Testing TLS Disabled Fully" {

        BeforeAll {
            $Script:tlsCompareObject = [PSCustomObject]@{
                ServerEnabled           = $false
                ClientEnabled           = $false
                ServerDisabledByDefault = $true
                ClientDisabledByDefault = $true
                TLSConfiguration        = "Disabled"
            }

            $Script:netCompareObject = [PSCustomObject]@{
                SystemDefaultTlsVersions    = $true
                SchUseStrongCrypto          = $true
                WowSystemDefaultTlsVersions = $true
                WowSchUseStrongCrypto       = $true
                SDtvConfiguredCorrectly     = $true
                SDtvEnabled                 = $true
            }

            Mock Get-RemoteRegistryValue {
                param (
                    [string]$MachineName,
                    [string]$SubKey,
                    [string]$GetValue,
                    [string]$ValueType,
                    [ScriptBlock]$CatchActionFunction
                )
                if ($SubKey -eq $Script:tlsServer10) {
                    if ($GetValue -eq $Script:enabledKey) { return 0 }
                    return 1
                } elseif ($SubKey -eq $Script:tlsServer11) {
                    if ($GetValue -eq $Script:enabledKey) { return 0 }
                    return 1
                } elseif ($SubKey -eq $Script:tlsServer12) {
                    if ($GetValue -eq $Script:enabledKey) { return 0 }
                    return 1
                } elseif ($SubKey -eq $Script:tlsServer13) {
                    if ($GetValue -eq $Script:enabledKey) { return 0 }
                    return 1
                } elseif ($SubKey -eq $Script:tlsClient10) {
                    if ($GetValue -eq $Script:enabledKey) { return 0 }
                    return 1
                } elseif ($SubKey -eq $Script:tlsClient11) {
                    if ($GetValue -eq $Script:enabledKey) { return 0 }
                    return 1
                } elseif ($SubKey -eq $Script:tlsClient12) {
                    if ($GetValue -eq $Script:enabledKey) { return 0 }
                    return 1
                } elseif ($SubKey -eq $Script:tlsClient13) {
                    if ($GetValue -eq $Script:enabledKey) { return 0 }
                    return 1
                } elseif ($SubKey -eq $Script:net4) {
                    return 1
                } elseif ($SubKey -eq $Script:net4Wow) {
                    return 1
                } elseif ($SubKey -eq $Script:net2) {
                    return 1
                } elseif ($SubKey -eq $Script:net2Wow) {
                    return 1
                } else {
                    throw "FAILED to find SubKey"
                }
            }

            SetVariables
        }

        It "TLS 1.0 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls10
        }

        It "TLS 1.1 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls11
        }

        It "TLS 1.2 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls12
        }

        It "TLS 1.3 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls13
        }

        It "NET v4 Testing Values" {
            TestObjectCompare $Script:netCompareObject $netV4
        }

        It "NET v2 Testing Values" {
            TestObjectCompare $Script:netCompareObject $netV2
        }
    }

    Context "Testing TLS Half Disabled - Part 1" {
        BeforeAll {
            $Script:tlsCompareObject = [PSCustomObject]@{
                ServerEnabled           = $true
                ClientEnabled           = $true
                ServerDisabledByDefault = $true
                ClientDisabledByDefault = $true
                TLSConfiguration        = "Half Disabled"
            }

            Mock Get-RemoteRegistryValue {
                param (
                    [string]$MachineName,
                    [string]$SubKey,
                    [string]$GetValue,
                    [string]$ValueType,
                    [ScriptBlock]$CatchActionFunction
                )
                return 1
            }

            SetVariables
        }

        It "TLS 1.0 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls10
        }

        It "TLS 1.1 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls11
        }

        It "TLS 1.2 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls12
        }

        It "TLS 1.3 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls13
        }
    }

    Context "Testing TLS Half Disabled - Part 2" {
        BeforeAll {
            $Script:tlsCompareObject = [PSCustomObject]@{
                ServerEnabled           = $false
                ClientEnabled           = $false
                ServerDisabledByDefault = $false
                ClientDisabledByDefault = $false
                TLSConfiguration        = "Half Disabled"
            }

            Mock Get-RemoteRegistryValue {
                param (
                    [string]$MachineName,
                    [string]$SubKey,
                    [string]$GetValue,
                    [string]$ValueType,
                    [ScriptBlock]$CatchActionFunction
                )
                return 0
            }

            SetVariables
        }

        It "TLS 1.0 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls10
        }

        It "TLS 1.1 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls11
        }

        It "TLS 1.2 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls12
        }

        It "TLS 1.3 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls13
        }
    }

    Context "Testing TLS Misconfigured - Part 1" {
        BeforeAll {
            $Script:tlsCompareObject = [PSCustomObject]@{
                ServerEnabled           = $true
                ClientEnabled           = $false
                ServerDisabledByDefault = $true
                ClientDisabledByDefault = $false
                TLSConfiguration        = "Misconfigured"
            }

            Mock Get-RemoteRegistryValue {
                param (
                    [string]$MachineName,
                    [string]$SubKey,
                    [string]$GetValue,
                    [string]$ValueType,
                    [ScriptBlock]$CatchActionFunction
                )
                if ($SubKey -eq $Script:tlsServer10) {
                    return 1
                } elseif ($SubKey -eq $Script:tlsServer11) {
                    return 1
                } elseif ($SubKey -eq $Script:tlsServer12) {
                    return 1
                } elseif ($SubKey -eq $Script:tlsServer13) {
                    return 1
                } elseif ($SubKey -eq $Script:tlsClient10) {
                    return 0
                } elseif ($SubKey -eq $Script:tlsClient11) {
                    return 0
                } elseif ($SubKey -eq $Script:tlsClient12) {
                    return 0
                } elseif ($SubKey -eq $Script:tlsClient13) {
                    return 0
                } elseif ($SubKey -eq $Script:net4) {
                    return 1
                } elseif ($SubKey -eq $Script:net4Wow) {
                    return 1
                } elseif ($SubKey -eq $Script:net2) {
                    return 1
                } elseif ($SubKey -eq $Script:net2Wow) {
                    return 1
                } else {
                    throw "FAILED to find SubKey"
                }
            }

            SetVariables
        }

        It "TLS 1.0 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls10
        }

        It "TLS 1.1 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls11
        }

        It "TLS 1.2 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls12
        }

        It "TLS 1.3 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls13
        }
    }

    Context "Testing TLS Misconfigured - Part 2" {
        BeforeAll {
            $Script:tlsCompareObject = [PSCustomObject]@{
                ServerEnabled           = $false
                ClientEnabled           = $true
                ServerDisabledByDefault = $false
                ClientDisabledByDefault = $true
                TLSConfiguration        = "Misconfigured"
            }

            Mock Get-RemoteRegistryValue {
                param (
                    [string]$MachineName,
                    [string]$SubKey,
                    [string]$GetValue,
                    [string]$ValueType,
                    [ScriptBlock]$CatchActionFunction
                )
                if ($SubKey -eq $Script:tlsServer10) {
                    return 0
                } elseif ($SubKey -eq $Script:tlsServer11) {
                    return 0
                } elseif ($SubKey -eq $Script:tlsServer12) {
                    return 0
                } elseif ($SubKey -eq $Script:tlsServer13) {
                    return 0
                } elseif ($SubKey -eq $Script:tlsClient10) {
                    return 1
                } elseif ($SubKey -eq $Script:tlsClient11) {
                    return 1
                } elseif ($SubKey -eq $Script:tlsClient12) {
                    return 1
                } elseif ($SubKey -eq $Script:tlsClient13) {
                    return 1
                } elseif ($SubKey -eq $Script:net4) {
                    return 1
                } elseif ($SubKey -eq $Script:net4Wow) {
                    return 1
                } elseif ($SubKey -eq $Script:net2) {
                    return 1
                } elseif ($SubKey -eq $Script:net2Wow) {
                    return 1
                } else {
                    throw "FAILED to find SubKey"
                }
            }

            SetVariables
        }

        It "TLS 1.0 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls10
        }

        It "TLS 1.1 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls11
        }

        It "TLS 1.2 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls12
        }

        It "TLS 1.3 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls13
        }
    }

    Context "Testing TLS Misconfigured - Part 3" {
        BeforeAll {
            $Script:tlsCompareObject = [PSCustomObject]@{
                ServerEnabled           = $true
                ClientEnabled           = $true
                ServerDisabledByDefault = $true
                ClientDisabledByDefault = $false
                TLSConfiguration        = "Misconfigured"
            }

            Mock Get-RemoteRegistryValue {
                param (
                    [string]$MachineName,
                    [string]$SubKey,
                    [string]$GetValue,
                    [string]$ValueType,
                    [ScriptBlock]$CatchActionFunction
                )
                if ($SubKey -eq $Script:tlsServer10) {
                    return 1
                } elseif ($SubKey -eq $Script:tlsServer11) {
                    return 1
                } elseif ($SubKey -eq $Script:tlsServer12) {
                    return 1
                } elseif ($SubKey -eq $Script:tlsServer13) {
                    return 1
                } elseif ($SubKey -eq $Script:tlsClient10) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:tlsClient11) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:tlsClient12) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:tlsClient13) {
                    if ($GetValue -eq $Script:enabledKey) { return 1 }
                    return 0
                } elseif ($SubKey -eq $Script:net4) {
                    return 1
                } elseif ($SubKey -eq $Script:net4Wow) {
                    return 1
                } elseif ($SubKey -eq $Script:net2) {
                    return 1
                } elseif ($SubKey -eq $Script:net2Wow) {
                    return 1
                } else {
                    throw "FAILED to find SubKey"
                }
            }

            SetVariables
        }

        It "TLS 1.0 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls10
        }

        It "TLS 1.1 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls11
        }

        It "TLS 1.2 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls12
        }

        It "TLS 1.3 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls13
        }
    }

    Context "Testing TLS 1.3 Differences with NULL Check" {

        BeforeAll {
            $Script:tlsCompareObject = [PSCustomObject]@{
                ServerEnabled                = $true
                ServerEnabledValue           = $null
                ClientEnabled                = $true
                ClientEnabledValue           = $null
                ServerDisabledByDefault      = $false
                ServerDisabledByDefaultValue = $null
                ClientDisabledByDefault      = $false
                ClientDisabledByDefaultValue = $null
                TLSConfiguration             = "Enabled"
            }

            $Script:tls13CompareObject = [PSCustomObject]@{
                ServerEnabled                = $false
                ServerEnabledValue           = $null
                ClientEnabled                = $false
                ClientEnabledValue           = $null
                ServerDisabledByDefault      = $false
                ServerDisabledByDefaultValue = $null
                ClientDisabledByDefault      = $false
                ClientDisabledByDefaultValue = $null
                TLSConfiguration             = "Disabled"
            }

            $Script:netCompareObject = [PSCustomObject]@{
                SystemDefaultTlsVersions    = $false
                SchUseStrongCrypto          = $false
                WowSystemDefaultTlsVersions = $false
                WowSchUseStrongCrypto       = $false
                SDtvConfiguredCorrectly     = $true
                SDtvEnabled                 = $false
            }

            Mock Get-RemoteRegistryValue {
                param (
                    [string]$MachineName,
                    [string]$SubKey,
                    [string]$GetValue,
                    [string]$ValueType,
                    [ScriptBlock]$CatchActionFunction
                )
                return $null
            }

            SetVariables
        }

        It "TLS 1.0 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls10
        }

        It "TLS 1.1 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls11
        }

        It "TLS 1.2 Testing Values" {
            TestObjectCompare $Script:tlsCompareObject $tls12
        }

        It "TLS 1.3 Testing Values" {
            TestObjectCompare $Script:tls13CompareObject $tls13
        }

        It "NET v4 Testing Values" {
            TestObjectCompare $Script:netCompareObject $netV4
        }

        It "NET v2 Testing Values" {
            TestObjectCompare $Script:netCompareObject $netV2
        }
    }

    Context "Testing NET Settings Enabled" {
        BeforeAll {
            $Script:netCompareObject = [PSCustomObject]@{
                SystemDefaultTlsVersions    = $true
                SchUseStrongCrypto          = $true
                WowSystemDefaultTlsVersions = $true
                WowSchUseStrongCrypto       = $true
                SDtvConfiguredCorrectly     = $true
                SDtvEnabled                 = $true
            }

            Mock Get-RemoteRegistryValue {
                param (
                    [string]$MachineName,
                    [string]$SubKey,
                    [string]$GetValue,
                    [string]$ValueType,
                    [ScriptBlock]$CatchActionFunction
                )
                return 1
            }

            SetVariables
        }

        It "NET v4 Testing Values" {
            TestObjectCompare $Script:netCompareObject $netV4
        }

        It "NET v2 Testing Values" {
            TestObjectCompare $Script:netCompareObject $netV2
        }
    }

    Context "Testing NET Setting Incorrectly Configured" {
        BeforeAll {
            $Script:netCompareObject = [PSCustomObject]@{
                SystemDefaultTlsVersions    = $true
                SchUseStrongCrypto          = $true
                WowSystemDefaultTlsVersions = $false
                WowSchUseStrongCrypto       = $false
                SDtvConfiguredCorrectly     = $false
                SDtvEnabled                 = $false
            }

            Mock Get-RemoteRegistryValue {
                param (
                    [string]$MachineName,
                    [string]$SubKey,
                    [string]$GetValue,
                    [string]$ValueType,
                    [ScriptBlock]$CatchActionFunction
                )
                if ($SubKey -eq $Script:net4) {
                    return 1
                } elseif ($SubKey -eq $Script:net4Wow) {
                    return 0
                } elseif ($SubKey -eq $Script:net2) {
                    return 1
                } elseif ($SubKey -eq $Script:net2Wow) {
                    return 0
                } else {
                    return 1
                }
            }

            SetVariables
        }

        It "NET v4 Testing Values" {
            TestObjectCompare $Script:netCompareObject $netV4
        }

        It "NET v2 Testing Values" {
            TestObjectCompare $Script:netCompareObject $netV2
        }
    }
}
