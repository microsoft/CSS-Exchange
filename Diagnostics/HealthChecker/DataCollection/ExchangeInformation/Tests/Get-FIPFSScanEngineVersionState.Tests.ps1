# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Get-FIPFSScanEngineVersionState.ps1

    Function Invoke-CatchActions {
        param()
    }

    Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetChildItemInvalidPattern.xml }
}

Describe "Testing Get-FIPFSScanEngineVersionState.ps1" {

    Context "Invalid Pattern Detected" {
        BeforeAll {
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server
        }

        It "System Affected By Transport Queue Issue" {
            $results | Should -Be $true
        }
    }

    Context "Valid Pattern Detected" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetChildItemValidPattern.xml }
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server
        }

        It "System NOT Affected By Transport Queue Issue" {
            $results | Should -Be $false
        }
    }

    Context "No Pattern Detected" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return $null }
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server
        }

        It "System NOT Affected By Transport Queue / Pattern Download Issue" {
            $results | Should -Be $false
        }
    }
}
