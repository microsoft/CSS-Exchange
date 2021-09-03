# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Incorrect rule result')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'Pester testing, no issues')]
[CmdletBinding()]
param()
BeforeAll {
    $parent = Split-Path -Parent $PSScriptRoot
    $scriptName = "Invoke-ScriptBlockHandler.ps1"

    . "$parent\$scriptName"

    Function Get-WinHttpSettings {
        param(
            [Parameter(Mandatory = $true)][string]$RegistryLocation
        )
        $connections = Get-ItemProperty -Path $RegistryLocation
        $Proxy = [string]::Empty
        if (($null -ne $connections) -and
            ($Connections | Get-Member).Name -contains "WinHttpSettings") {
            foreach ($Byte in $Connections.WinHttpSettings) {
                if ($Byte -ge 48) {
                    $Proxy += [CHAR]$Byte
                }
            }
        }
        return $(if ($Proxy -eq [string]::Empty) { "<None>" } else { $Proxy })
    }

    Function Get-PendingSCCMReboot {

        begin {
            $returnValue = $false
        }

        process {
            try {
                $sccmReboot = Invoke-CimMethod -Namespace 'Root\ccm\clientSDK' -ClassName 'CCM_ClientUtilities' -Name 'DetermineIfRebootPending' -ErrorAction Stop

                if ($sccmReboot) {
                    if ($sccmReboot.RebootPending -or
                        $sccmReboot.IsHardRebootPending) {
                        $returnValue = $true
                        return
                    }
                }
                return
            } catch {
                throw
            }
        }

        end {
            return $returnValue
        }
    }

    Function Test-VerboseOutput {
        param(
            [bool]$Without = $true,
            [bool]$Local = $true
        )

        $withoutValue = "without"

        if (-not ($Without)) {
            $withoutValue = "with"
        }

        Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -eq "Calling: Invoke-ScriptBlockHandler" }
        Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -eq "Exiting: Invoke-ScriptBlockHandler" }

        if ($Local) {
            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -eq "Running Script Block Locally $withoutValue argument list" }
        } else {
            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -eq "Running Invoke-Command $withoutValue argument list" }
        }
    }

    $myFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
}

Describe "Testing $scriptName" {

    BeforeEach {
        Mock Write-Verbose {}
    }

    Context "Local Test Results" {

        It "Processor Count" {
            $myValue = [System.Environment]::ProcessorCount
            $result = Invoke-ScriptBlockHandler -ComputerName $env:COMPUTERNAME `
                -ScriptBlock { [System.Environment]::ProcessorCount } `
                -ScriptBlockDescription "Getting Processor Count"
            $result | Should -Be $myValue

            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -like "*Getting Processor Count" }
            Test-VerboseOutput
        }

        It "Bad Server Name" {
            $result = Invoke-ScriptBlockHandler -ComputerName "BadComputerName" `
                -ScriptBlock { [System.Environment]::ProcessorCount } `
                -ScriptBlockDescription "Getting Processor Count"
            $result | Should -Be $null

            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -like "*Getting Processor Count" }
            Test-VerboseOutput -Local $false
        }

        It "Passing Argument List" {
            $httpProxyPath32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
            $testResults = Get-WinHttpSettings $httpProxyPath32
            $results = Invoke-ScriptBlockHandler -ComputerName $env:COMPUTERNAME `
                -ScriptBlock ${Function:Get-WinHttpSettings} `
                -ScriptBlockDescription "Getting Http Proxy Settings 32 bit" `
                -ArgumentList $httpProxyPath32
            $results | Should -Be $testResults

            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -like "*Getting Http Proxy Settings 32 bit" }
            Test-VerboseOutput -Without $false
        }

        <# TODO ADD This back
        It "Pending SCCM Reboot" {
            $results = Invoke-ScriptBlockHandler -ComputerName $env:COMPUTERNAME `
                -ScriptBlock ${Function:Get-PendingSCCMReboot} `
                -ScriptBlockDescription "Getting Pending SCCM Reboot Result"
            $results | Should -Be $false

            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -like "*Getting Pending SCCM Reboot Result" }
            Test-VerboseOutput
        }
    #>
    }

    Context "Remote Execution Test Results" {
        BeforeEach {
            $trueComputerName = $env:COMPUTERNAME
            $env:COMPUTERNAME = "Testing"

            Mock Write-Verbose {}
            Mock Invoke-Command {}
        }
        AfterEach {
            $env:COMPUTERNAME = $trueComputerName
        }

        It "Processor Count" {
            $results = Invoke-ScriptBlockHandler -ComputerName $myFQDN `
                -ScriptBlock { [System.Environment]::ProcessorCount } `
                -ScriptBlockDescription "Getting Processor Count"

            #not able to properly test because of Admin
            $results | Should -Be $null

            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -like "*Getting Processor Count" }
            Assert-MockCalled -CommandName Invoke-Command -Exactly 1
            Test-VerboseOutput -Local $false
        }
        It "Passing Argument List" {
            $httpProxyPath32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
            $results = Invoke-ScriptBlockHandler -ComputerName $myFQDN `
                -ScriptBlock ${Function:Get-WinHttpSettings} `
                -ScriptBlockDescription "Getting Http Proxy Settings 32 bit" `
                -ArgumentList $httpProxyPath32

            #not able to properly test because of Admin
            $results | Should -Be $null

            Assert-MockCalled -CommandName Write-Verbose -Exactly 1 -ParameterFilter { $Message -like "*Getting Http Proxy Settings 32 bit" }
            Assert-MockCalled -CommandName Invoke-Command -Exactly 1
            Test-VerboseOutput -Local $false -Without $false
        }
    }

    Context "Testing catch action script block" {

        It "Testing throw" {
            Function Test-PesterCatchAction {
                Write-Host "Test-PesterCatchAction"
            }
            Mock Invoke-Command { throw "Failed Pester Testing" }
            Mock Write-Host {}

            try {
                $trueComputerName = $env:COMPUTERNAME
                $env:COMPUTERNAME = "Testing"
                $result = Invoke-ScriptBlockHandler -ComputerName $myFQDN `
                    -ScriptBlock { $env:COMPUTERNAME } `
                    -CatchActionFunction ${Function:Test-PesterCatchAction} -Verbose
            } finally {
                $env:COMPUTERNAME = $trueComputerName
            }

            Assert-MockCalled -CommandName Write-Host -Exactly 1 -ParameterFilter { $Object -eq "Test-PesterCatchAction" }
        }
    }
}
