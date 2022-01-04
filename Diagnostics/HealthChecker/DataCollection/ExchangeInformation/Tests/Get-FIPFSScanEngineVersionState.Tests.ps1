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
}

Describe "Testing Get-FIPFSScanEngineVersionState.ps1" {

    Context "Invalid Pattern Detected" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetChildItemInvalidPattern.xml }
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

    Context "No FIP-FS scan engines - return null back from GetFolderFromExchangeInstallPath" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return $null }
            Mock Write-Verbose {}
        }

        It "Result return null" {
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server
            $results | Should -Be $null
            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -eq "No FIP-FS scan engine version(s) detected" }
        }
    }

    Context "No FIP-FS scan engine directory - return failed object from GetFolderFromExchangeInstallPath" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetChildItemFailed.xml }
            Mock Write-Verbose {}
        }

        It "Results return null back" {
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server
            $results | Should -Be $null
            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -eq "Failed to find the scan engine directory" }
        }
    }
}
