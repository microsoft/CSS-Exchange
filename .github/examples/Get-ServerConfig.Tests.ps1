# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Example test pattern for a getter function with parameter validation.

.DESCRIPTION
    This demonstrates:
    - Testing parameter validation (null, empty, range)
    - Happy path and output validation
    - Error handling patterns
    - Edge cases

#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    # Dot-source the script being tested (colocated in same directory)
    . $PSScriptRoot\Get-ServerConfig.ps1
}

Describe "Testing Get-ServerConfig.ps1" {

    Context "Happy Path: Valid Server Name" {
        BeforeAll {
            $Script:result = Get-ServerConfig -ServerName "SERVER01"
        }

        It "Should return a PSCustomObject" {
            $Script:result | Should -Not -BeNullOrEmpty
            $Script:result | Should -BeOfType [PSCustomObject]
        }

        It "Should have expected properties" {
            $Script:result.PSObject.Properties.Name | Should -Contain "ServerName"
            $Script:result.PSObject.Properties.Name | Should -Contain "IsOnline"
            $Script:result.PSObject.Properties.Name | Should -Contain "ProcessorCount"
        }

        It "Should set ServerName correctly" {
            $Script:result.ServerName | Should -Be "SERVER01"
        }

        It "Should have correct data types" {
            $Script:result.IsOnline | Should -BeOfType [bool]
            $Script:result.ProcessorCount | Should -BeOfType [int]
        }
    }

    Context "Parameter Validation" {
        It "Should throw when ServerName is null" {
            { Get-ServerConfig -ServerName $null } | Should -Throw
        }

        It "Should throw when ServerName is empty" {
            { Get-ServerConfig -ServerName "" } | Should -Throw
        }

        It "Should throw when Timeout is out of range" {
            { Get-ServerConfig -ServerName "SERVER01" -Timeout 0 } | Should -Throw
            { Get-ServerConfig -ServerName "SERVER01" -Timeout 301 } | Should -Throw
        }

        It "Should accept valid Timeout values" {
            { Get-ServerConfig -ServerName "SERVER01" -Timeout 1 } | Should -Not -Throw
            { Get-ServerConfig -ServerName "SERVER01" -Timeout 300 } | Should -Not -Throw
        }
    }

    Context "Error Handling" {
        It "Should throw when server not found" {
            { Get-ServerConfig -ServerName "INVALID" } | Should -Throw "*Server not found*"
        }

        It "Should catch and re-throw errors" {
            Mock Get-Date { throw "Access denied" }
            # Function should propagate the error
            { Get-ServerConfig -ServerName "SERVER01" -ErrorAction Stop } | Should -Throw
        }
    }

    Context "Edge Cases" {
        It "Should handle server names with special characters" {
            $result = Get-ServerConfig -ServerName "SERVER-01.contoso.com"
            $result.ServerName | Should -Be "SERVER-01.contoso.com"
        }

        It "Should handle mixed case server names" {
            $result = Get-ServerConfig -ServerName "SeRvEr01"
            $result.ServerName | Should -Be "SeRvEr01"
        }

        It "Should use default timeout when not specified" {
            # Test that timeout parameter defaults work
            $result = Get-ServerConfig -ServerName "SERVER01"
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context "Output Validation" {
        BeforeAll {
            Mock Get-Date { return [DateTime]::Parse('2024-06-15T12:00:00') }
            $Script:result = Get-ServerConfig -ServerName "SERVER01"
        }

        It "Should always set IsOnline to true for valid servers" {
            $Script:result.IsOnline | Should -Be $true
        }

        It "Should set LastUpdated to mocked time" {
            $Script:result.LastUpdated | Should -Be ([DateTime]::Parse('2024-06-15T12:00:00'))
        }

        It "Should have ConfigVersion set" {
            $Script:result.ConfigVersion | Should -Not -BeNullOrEmpty
        }
    }
}
