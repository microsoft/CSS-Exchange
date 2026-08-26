# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Get-ParameterString.ps1
}

Describe "Testing Get-ParameterString" {

    Context "Empty hashtable" {
        It "Should return an empty string" {
            $result = Get-ParameterString -InputObject @{}
            $result | Should -Be ([string]::Empty)
        }
    }

    Context "Single key-value pair" {
        It "Should return a single -Key Value parameter string" {
            $result = Get-ParameterString -InputObject @{ Name = "TestValue" }
            $result | Should -Be '-Name "TestValue"'
        }
    }

    Context "Multiple key-value pairs" {
        BeforeAll {
            $Script:result = Get-ParameterString -InputObject @{
                Filter = "system.webServer/security"
                Name   = "enabled"
            }
        }

        It "Should contain each key-value pair in -Key Value format" {
            $result | Should -Match '-Filter "system.webServer/security"'
            $result | Should -Match '-Name "enabled"'
        }

        It "Should separate pairs with spaces" {
            # Each pair should be present and the total should be two pairs
            ($result -split '(?<=")\s+(?=-)').Count | Should -Be 2
        }
    }

    Context "Output format validation" {
        It "Should wrap values in double quotes" {
            $result = Get-ParameterString -InputObject @{ PSPath = "IIS:\" }
            $result | Should -BeLike '*"IIS:\"*'
        }

        It "Should prefix keys with a dash" {
            $result = Get-ParameterString -InputObject @{ Value = "true" }
            $result | Should -BeLike '-Value*'
        }

        It "Should trim trailing whitespace" {
            $result = Get-ParameterString -InputObject @{ Key = "Val" }
            $result | Should -Not -Match '\s$'
        }
    }
}
