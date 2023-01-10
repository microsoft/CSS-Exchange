# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Copy-ScriptToExchangeDirectory.ps1
}

Describe "Testing Copy-ScriptToExchangeDirectory.ps1" {

    Context "Executed On Exchange Server" {
        BeforeAll {
            $env:ExchangeInstallPath = $env:TEMP
            $Script:results = Copy-ScriptToExchangeDirectory -FullPathToScript $Script:parentPath\Copy-ScriptToExchangeDirectory.ps1
        }

        It "Should Copy The Script To ExchangeScripts Folder" {
            $results.WorkingDirectory | Should -Be ('{0}\Scripts' -f $env:TEMP)
            $results.ScriptName | Should -Be 'Copy-ScriptToExchangeDirectory.ps1'
        }
    }

    Context "Executed On Non-Exchange Server" {
        BeforeAll {
            $env:ExchangeInstallPath = $null
            $Script:results = Copy-ScriptToExchangeDirectory
        }

        It "Should Not Do Anything And Return Null" {
            $results | Should -Be $null
        }
    }
}
