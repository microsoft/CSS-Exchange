# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\..\..\Helpers\Class.ps1
    . $Script:parentPath\Get-FIPFSScanEngineVersionState.ps1

    function Invoke-CatchActions {
        param()
    }

    $Script:serverRoles = New-Object HealthChecker.ExchangeServerRole
    [System.Version]$Script:fixed = "15.1.2308.27"
    [System.Version]$Script:notFixed = "15.1.2300.20"
}

Describe "Testing Get-FIPFSScanEngineVersionState.ps1" {

    Context "Invalid Pattern Detected On Affected Exchange Build" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetChildItemInvalidPattern.xml }
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server -ExSetupVersion $Script:notFixed -ServerRole $Script:serverRoles
        }

        It "System Affected By Transport Queue Issue" {
            $results.FIPFSFixedBuild | Should -Be $false
            $results.ServerRoleAffected | Should -Be $true
            $results.HighesVersionNumberDetected | Should -Be 2201010000
            $results.BadVersionNumberDirDetected | Should -Be $true
        }
    }

    Context "Valid Pattern Detected On Affected Exchange Build" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetChildItemValidPattern.xml }
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server -ExSetupVersion $Script:notFixed -ServerRole $Script:serverRoles
        }

        It "System NOT Affected By Transport Queue Issue" {
            $results.FIPFSFixedBuild | Should -Be $false
            $results.ServerRoleAffected | Should -Be $true
            $results.HighesVersionNumberDetected | Should -Be 2110070014
            $results.BadVersionNumberDirDetected | Should -Be $false
        }
    }

    Context "Invalid Pattern Detected On Fixed Exchange Build" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetChildItemInvalidPattern.xml }
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server -ExSetupVersion $Script:Fixed -ServerRole $Script:serverRoles
        }

        It "System NOT Affected By Transport Queue Issue Due To Fixed Exchange Build" {
            $results.FIPFSFixedBuild | Should -Be $true
            $results.ServerRoleAffected | Should -Be $true
            $results.HighesVersionNumberDetected | Should -Be 2201010000
            $results.BadVersionNumberDirDetected | Should -Be $true
        }
    }

    Context "Exchange Server Role Not Affected" {
        BeforeAll {
            $edgeRole = $Script:serverRoles
            $edgeRole = [HealthChecker.ExchangeServerRole]::Edge
            Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetChildItemInvalidPattern.xml }
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server -ExSetupVersion $Script:Fixed -ServerRole $edgeRole
        }

        It "Edge Transport Server Role Isn't Affected" {
            $results.FIPFSFixedBuild | Should -Be $null
            $results.ServerRoleAffected | Should -Be $false
            $results.HighesVersionNumberDetected | Should -Be $null
            $results.BadVersionNumberDirDetected | Should -Be $false
        }
    }

    Context "No FIP-FS scan engines - return null back from GetFolderFromExchangeInstallPath" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return $null }
            Mock Write-Verbose {}
        }

        It "HighesVersionNumberDetected return null" {
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server -ExSetupVersion $Script:notFixed -ServerRole $Script:serverRoles
            $results.HighesVersionNumberDetected | Should -Be $null
            $results.BadVersionNumberDirDetected | Should -Be $false
            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -eq "No FIP-FS scan engine version(s) detected - GetFolderFromExchangeInstallPath returned null" }
        }
    }

    Context "No FIP-FS scan engine directory - return failed object from GetFolderFromExchangeInstallPath" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -MockWith { return Import-Clixml $Script:parentPath\Tests\GetChildItemFailed.xml }
            Mock Write-Verbose {}
        }

        It "HighesVersionNumberDetected return null" {
            $Script:results = Get-FIPFSScanEngineVersionState -ComputerName $Script:Server -ExSetupVersion $Script:notFixed -ServerRole $Script:serverRoles
            $results.HighesVersionNumberDetected | Should -Be $null
            $results.BadVersionNumberDirDetected | Should -Be $false
            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -eq "Failed to find the scan engine directory" }
        }
    }
}
