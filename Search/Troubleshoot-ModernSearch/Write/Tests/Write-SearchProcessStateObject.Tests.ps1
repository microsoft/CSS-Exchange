# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Write-SearchProcessStateObject.ps1

    function NewTestState {
        param(
            [object[]]$ThirdPartyModules = @(),
            [object[]]$AmsiModules = @(),
            [string]$ModulesReadError,
            [string[]]$AmsiProviderErrors = @()
        )

        # A [string] parameter converts $null to an empty string, the real object uses $null when there is no error
        $processModulesReadError = $null

        if (-not [string]::IsNullOrEmpty($ModulesReadError)) {
            $processModulesReadError = $ModulesReadError
        }

        return [PSCustomObject]@{
            ServerName              = "EXCH1"
            ServicesConfigCorrectly = $true
            AllProcessesRunning     = $true
            RunForAnHour            = $true
            ThirdPartyModuleFound   = $ThirdPartyModules.Count -gt 0
            ModulesReadFailed       = $null -ne $processModulesReadError
            LatestProcessStartTime  = [DateTime]::Now.AddDays(-1)
            ProcessInformation      = [PSCustomObject]@{
                Services                = @()
                AmsiProviderModuleNames = @("MpOav.dll")
                AmsiProviderErrors      = $AmsiProviderErrors
                Processes               = @([PSCustomObject]@{
                        Name              = "hostcontrollerservice"
                        PID               = 1001
                        StartTime         = [DateTime]::Now.AddDays(-1)
                        ThirdPartyModules = $ThirdPartyModules
                        AmsiModules       = $AmsiModules
                        ModulesReadError  = $processModulesReadError
                    })
            }
        }
    }

    $Script:mpOavModule = [PSCustomObject]@{
        ModuleName  = "MpOav.dll"
        Company     = "Microsoft Corporation"
        FileVersion = "4.18.26100.4"
        FileName    = "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MpOav.dll"
    }

    $Script:vendorModule = [PSCustomObject]@{
        ModuleName  = "VendorHook.dll"
        Company     = "Contoso Security"
        FileVersion = "1.0.0.0"
        FileName    = "C:\Program Files\Contoso\VendorHook.dll"
    }
}

Describe "Testing Write-SearchProcessStateObject" {
    BeforeAll {
        Mock Write-Host {}
        Mock Write-Verbose {}
    }

    Context "Only the AMSI provider module is loaded" {
        BeforeAll {
            Write-SearchProcessStateObject -SearchProcessState (NewTestState -AmsiModules @($Script:mpOavModule))
        }

        It "Should report success" {
            Should -Invoke Write-Host -Times 1 -Exactly -Scope Context -ParameterFilter { $Object -eq "Search Process Status - EXCH1: Success" }
        }

        It "Should log the AMSI provider module to the debug log only" {
            Should -Invoke Write-Verbose -Times 1 -Exactly -Scope Context -ParameterFilter { $Message -like "AMSI provider module in hostcontrollerservice PID 1001: MpOav.dll*" }
            Should -Invoke Write-Host -Times 0 -Exactly -Scope Context -ParameterFilter { "$Object" -like "*MpOav.dll*" }
        }
    }

    Context "A 3rd party module is loaded" {
        BeforeAll {
            Write-SearchProcessStateObject -SearchProcessState (NewTestState -ThirdPartyModules @($Script:vendorModule))
        }

        It "Should report the warning" {
            Should -Invoke Write-Host -Times 1 -Exactly -Scope Context -ParameterFilter { $Object -eq "Search Process Status - EXCH1: Warning - Third Party Modules Detected" }
        }

        It "Should display the module details" {
            Should -Invoke Write-Host -Times 1 -Exactly -Scope Context -ParameterFilter { $Object -eq "    Module: VendorHook.dll Company: Contoso Security FileVersion: 1.0.0.0 Path: C:\Program Files\Contoso\VendorHook.dll" }
        }
    }

    Context "The process modules can't be read" {
        BeforeAll {
            Write-SearchProcessStateObject -SearchProcessState (NewTestState -ModulesReadError "Access is denied.")
        }

        It "Should report the warning" {
            Should -Invoke Write-Host -Times 1 -Exactly -Scope Context -ParameterFilter { $Object -eq "Search Process Status - EXCH1: Warning - Unable To Read Process Modules" }
        }

        It "Should display that the modules are unknown" {
            Should -Invoke Write-Host -Times 1 -Exactly -Scope Context -ParameterFilter { $Object -eq "Contains 3rd Party Modules: Unknown - Unable to read the loaded modules. Access is denied." }
        }
    }

    Context "The AMSI provider registration can't be read" {
        BeforeAll {
            Write-SearchProcessStateObject -SearchProcessState (NewTestState -ThirdPartyModules @($Script:mpOavModule) -AmsiProviderErrors @("Failed to read the provider."))
        }

        It "Should display the registration issue" {
            Should -Invoke Write-Host -Times 1 -Exactly -Scope Context -ParameterFilter { $Object -eq "AMSI provider registration issue: Failed to read the provider." }
        }
    }
}
