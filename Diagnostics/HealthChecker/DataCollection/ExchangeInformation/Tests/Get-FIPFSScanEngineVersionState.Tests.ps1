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

    Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetItemPipeline2Dll.xml } `
        -ParameterFilter { $ArgumentList -eq "FIP-FS\Bin\pipeline2.dll" }

    Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetChildItemInvalidPattern.xml }
}

Describe "Testing Get-FIPFSScanEngineVersionState.ps1" {

    Context "Invalid Pattern Detected On E16/E19" {
        BeforeAll {
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server `
                -CatchActionFunction ${Function:Invoke-CatchActions}
        }

        It "System Affected By Transport Queue Issue" {
            $results | Should -Be $true
        }
    }

    Context "Valid Pattern Detected On E16/E19" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetChildItemValidPattern.xml }
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server `
                -CatchActionFunction ${Function:Invoke-CatchActions}
        }

        It "System NOT Affected By Transport Queue Issue" {
            $results | Should -Be $false
        }
    }

    Context "Invalid Pattern Detected On E15" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\E15GetItemPipeline2Dll.xml } `
                -ParameterFilter { $ArgumentList -eq "FIP-FS\Bin\pipeline2.dll" }
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server `
                -CatchActionFunction ${Function:Invoke-CatchActions}
        }

        It "System Affected By Pattern Download Issue" {
            $results | Should -Be $true
        }
    }
}
