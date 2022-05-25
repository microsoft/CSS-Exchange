# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Get-PrintSpoolerConfiguration.ps1

    function Invoke-CatchActions {
        param()
    }

    # We need to overwrite the existing 'Get-Service' function because it doesn't support
    # the '-ComputerName' parameter on PowerShell 7.0
    function Get-Service {
        param(
            [Parameter(Mandatory = $false)]
            [string]
            $ComputerName,
            [Parameter(Mandatory = $false)]
            [string]
            $Name
        )
    }
}

Describe "Testing Get-PrintSpoolerConfiguration.ps1" {
    BeforeAll {
        Mock Get-Service -MockWith { return Import-Clixml $Script:parentPath\Tests\PrintSpoolerSetToAutomaticAndRunning.xml } `
            -ParameterFilter { $ComputerName -eq $Script:Server }
    }

    Context "Insecure Print Spooler Configuration" {
        BeforeAll {
            $Script:printSpoolerConfig = Get-PrintSpoolerConfiguration -ComputerName $Script:Server
        }

        It "Print Spooler Is Set To 'Automatic' And 'Running'" {
            $printSpoolerConfig.SpoolerStatus | Should -Be "Running"
            $printSpoolerConfig.SpoolerStartType | Should -Be "Automatic"
            $printSpoolerConfig.SpoolerConfigSecure | Should -Be $false
        }
    }

    Context "Secure Print Spooler Configuration" {
        BeforeAll {
            Mock Get-Service -MockWith { return Import-Clixml $Script:parentPath\Tests\PrintSpoolerSetToDisabledAndStopped.xml } `
                -ParameterFilter { $ComputerName -eq $Script:Server }
            $Script:printSpoolerConfig = Get-PrintSpoolerConfiguration -ComputerName $Script:Server
        }

        It "Print Spooler Is Set To 'Disabled' And 'Stopped'" {
            $printSpoolerConfig.SpoolerStatus | Should -Be "Stopped"
            $printSpoolerConfig.SpoolerStartType | Should -Be "Disabled"
            $printSpoolerConfig.SpoolerConfigSecure | Should -Be $true
        }
    }

    Context "Mixed Print Spooler Configuration" {
        BeforeAll {
            Mock Get-Service -MockWith { return Import-Clixml $Script:parentPath\Tests\PrintSpoolerSetToAutomaticAndStopped.xml } `
                -ParameterFilter { $ComputerName -eq $Script:Server }
            $Script:printSpoolerConfig = Get-PrintSpoolerConfiguration -ComputerName $Script:Server
        }

        It "Print Spooler Is Set To 'Automatic' And 'Stopped'" {
            $printSpoolerConfig.SpoolerStatus | Should -Be "Stopped"
            $printSpoolerConfig.SpoolerStartType | Should -Be "Automatic"
            $printSpoolerConfig.SpoolerConfigSecure | Should -Be $false
        }
    }
}
