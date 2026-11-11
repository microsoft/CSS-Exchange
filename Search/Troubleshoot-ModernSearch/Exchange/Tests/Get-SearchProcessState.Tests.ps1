# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Get-SearchProcessState.ps1

    # cSpell:ignore MPCLIENT CLSID
    $Script:amsiProvidersPath = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
    $Script:providerGuid = "{2781761E-28E0-4109-99FE-B9D127C57AFE}"
    $Script:defenderPath = "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0"
    # cSpell:disable-next-line
    $Script:localizedMicrosoftCompany = "Корпорация Майкрософт"

    function NewTestModule {
        param(
            [string]$ModuleName,
            [string]$Company,
            [string]$FileName
        )
        return [PSCustomObject]@{
            ModuleName  = $ModuleName
            Company     = $Company
            FileVersion = "1.0.0.0"
            FileName    = $FileName
        }
    }

    $Script:amsiDll = NewTestModule -ModuleName "amsi.dll" -Company "Microsoft Corporation" -FileName "C:\Windows\System32\amsi.dll"
    $Script:mpOavDll = NewTestModule -ModuleName "MpOav.dll" -Company "Microsoft Corporation" -FileName "$Script:defenderPath\MpOav.dll"
    $Script:mpClientDll = NewTestModule -ModuleName "MPCLIENT.DLL" -Company "Microsoft Corporation" -FileName "$Script:defenderPath\MPCLIENT.DLL"

    function InvokeTestSearchProcessState {
        param(
            [object]$HostControllerModules,
            [bool]$AmsiProvidersKeyExists = $true,
            [string]$ProviderDll = "`"$Script:defenderPath\MpOav.dll`"",
            [bool]$ProviderReadFails = $false,
            [bool]$ProvidersPathCheckFails = $false
        )
        $Script:hostControllerModules = $HostControllerModules
        $Script:providersPathCheckFails = $ProvidersPathCheckFails
        $Script:amsiProvidersKeyExists = $AmsiProvidersKeyExists
        $Script:providerDll = $ProviderDll
        $Script:providerReadFails = $ProviderReadFails
        $Script:result = Get-SearchProcessState
        $Script:hostController = $Script:result.ProcessInformation.Processes | Where-Object { $_.Name -eq "hostcontrollerservice" }
    }
}

Describe "Testing Get-SearchProcessState" {
    BeforeAll {
        Mock Get-Service {
            foreach ($name in @("HostControllerService", "MSExchangeFastSearch")) {
                [PSCustomObject]@{
                    Name      = $name
                    Status    = [PSCustomObject]@{ value__ = 4 }
                    StartType = [PSCustomObject]@{ value__ = 2 }
                }
            }
        }

        Mock Get-CimInstance {
            $nodeNames = @("AdminNode1", "ContentEngineNode1", "IndexNode1", "InteractionEngineNode1")
            for ($i = 0; $i -lt $nodeNames.Count; $i++) {
                [PSCustomObject]@{
                    ProcessId   = 1003 + $i
                    CommandLine = "noderunner.exe $($nodeNames[$i])"
                }
            }
        }

        Mock Get-Process {
            $startTime = [DateTime]::Now.AddDays(-1)
            [PSCustomObject]@{ Name = "hostcontrollerservice"; Id = 1001; StartTime = $startTime; Modules = $Script:hostControllerModules }
            [PSCustomObject]@{ Name = "Microsoft.Exchange.Search.Service"; Id = 1002; StartTime = $startTime; Modules = @($Script:amsiDll) }

            for ($i = 0; $i -lt 4; $i++) {
                [PSCustomObject]@{ Name = "noderunner"; Id = 1003 + $i; StartTime = $startTime; Modules = @($Script:amsiDll) }
            }
        }

        Mock Test-Path {
            if ($Script:providersPathCheckFails) {
                Write-Error "Requested registry access is not allowed."
                return $false
            }
            return $Script:amsiProvidersKeyExists
        } -ParameterFilter { $Path -eq $Script:amsiProvidersPath }

        Mock Get-ChildItem { return [PSCustomObject]@{ PSChildName = $Script:providerGuid } } -ParameterFilter { $Path -eq $Script:amsiProvidersPath }

        Mock Get-ItemProperty {
            if ($Script:providerReadFails) {
                Write-Error "Requested registry access is not allowed."
                return
            }
            return [PSCustomObject]@{ "(default)" = $Script:providerDll }
        } -ParameterFilter { $Path -like "HKLM:\SOFTWARE\Classes\CLSID\*\InprocServer32" }
    }

    Context "Mocked search processes are collected" {
        BeforeAll {
            InvokeTestSearchProcessState -HostControllerModules @($Script:amsiDll)
        }

        It "Should find all search processes and services" {
            $Script:result.AllProcessesRunning | Should -Be $true
            $Script:result.ServicesConfigCorrectly | Should -Be $true
            $Script:result.RunForAnHour | Should -Be $true
        }

        It "Should not report module issues" {
            $Script:result.ThirdPartyModuleFound | Should -Be $false
            $Script:result.ModulesReadFailed | Should -Be $false
        }

        It "Should return the registered AMSI provider module name" {
            $Script:result.ProcessInformation.AmsiProviderModuleNames | Should -Be "MpOav.dll"
            $Script:result.ProcessInformation.AmsiProviderErrors.Count | Should -Be 0
        }
    }

    Context "Modules shipped with Exchange or Windows aren't reported" {
        BeforeAll {
            InvokeTestSearchProcessState -HostControllerModules @(
                (NewTestModule -ModuleName "Google.Protobuf.ni.dll" -Company "Google Inc." -FileName "C:\Windows\assembly\NativeImages_v4.0.30319_64\Google.Protobuf\Google.Protobuf.ni.dll"),
                (NewTestModule -ModuleName "ManagedBlingSigned.dll" -Company $null -FileName "C:\Exchange\Bin\ManagedBlingSigned.dll"),
                (NewTestModule -ModuleName "user32.dll" -Company $Script:localizedMicrosoftCompany -FileName "C:\Windows\System32\user32.dll"))
        }

        It "Should not report the allowed modules" {
            $Script:result.ThirdPartyModuleFound | Should -Be $false
            $Script:hostController.ThirdPartyModules.Count | Should -Be 0
        }
    }

    Context "A 3rd party module is loaded" {
        BeforeAll {
            InvokeTestSearchProcessState -HostControllerModules @(
                $Script:amsiDll,
                (NewTestModule -ModuleName "VendorHook.dll" -Company "Contoso Security" -FileName "C:\Program Files\Contoso\VendorHook.dll"))
        }

        It "Should report the module with its details" {
            $Script:result.ThirdPartyModuleFound | Should -Be $true
            $Script:hostController.ThirdPartyModules.Count | Should -Be 1
            $Script:hostController.ThirdPartyModules[0].ModuleName | Should -Be "VendorHook.dll"
            $Script:hostController.ThirdPartyModules[0].Company | Should -Be "Contoso Security"
            $Script:hostController.ThirdPartyModules[0].FileName | Should -Be "C:\Program Files\Contoso\VendorHook.dll"
        }
    }

    Context "The registered AMSI provider is loaded with amsi.dll" {
        BeforeAll {
            InvokeTestSearchProcessState -HostControllerModules @($Script:amsiDll, $Script:mpOavDll)
        }

        It "Should report the provider as AMSI module only" {
            $Script:result.ThirdPartyModuleFound | Should -Be $false
            $Script:hostController.AmsiModules.ModuleName | Should -Be "MpOav.dll"
        }
    }

    Context "The registered AMSI provider is loaded without amsi.dll" {
        BeforeAll {
            InvokeTestSearchProcessState -HostControllerModules @($Script:mpOavDll)
        }

        It "Should report the provider as 3rd party module" {
            $Script:result.ThirdPartyModuleFound | Should -Be $true
            $Script:hostController.ThirdPartyModules.ModuleName | Should -Be "MpOav.dll"
            $Script:hostController.AmsiModules.Count | Should -Be 0
        }
    }

    Context "A not registered Windows Defender module is loaded with amsi.dll" {
        BeforeAll {
            InvokeTestSearchProcessState -HostControllerModules @($Script:amsiDll, $Script:mpOavDll, $Script:mpClientDll)
        }

        It "Should report only the not registered module as 3rd party module" {
            $Script:result.ThirdPartyModuleFound | Should -Be $true
            $Script:hostController.ThirdPartyModules.ModuleName | Should -Be "MPCLIENT.DLL"
            $Script:hostController.AmsiModules.ModuleName | Should -Be "MpOav.dll"
        }
    }

    Context "A Windows Defender module is loaded outside of the Windows Defender folder" {
        BeforeAll {
            InvokeTestSearchProcessState -HostControllerModules @(
                $Script:amsiDll,
                (NewTestModule -ModuleName "MPCLIENT.DLL" -Company "Microsoft Corporation" -FileName "C:\Other\MPCLIENT.DLL"))
        }

        It "Should report the module as 3rd party module" {
            $Script:result.ThirdPartyModuleFound | Should -Be $true
            $Script:hostController.ThirdPartyModules.FileName | Should -Be "C:\Other\MPCLIENT.DLL"
        }
    }

    Context "A registered AMSI provider with a Microsoft company name outside of the Windows Defender folder" {
        BeforeAll {
            InvokeTestSearchProcessState -ProviderDll "C:\Other\OtherAmsi.dll" -HostControllerModules @(
                $Script:amsiDll,
                (NewTestModule -ModuleName "OtherAmsi.dll" -Company "Microsoft Corporation" -FileName "C:\Other\OtherAmsi.dll"))
        }

        It "Should report the provider as AMSI module" {
            $Script:result.ThirdPartyModuleFound | Should -Be $false
            $Script:hostController.AmsiModules.ModuleName | Should -Be "OtherAmsi.dll"
        }
    }

    Context "The registered AMSI provider path contains an environment variable" {
        BeforeAll {
            InvokeTestSearchProcessState -ProviderDll "`"%ProgramFiles%\Contoso\ContosoAmsi.dll`"" -HostControllerModules @(
                $Script:amsiDll,
                (NewTestModule -ModuleName "ContosoAmsi.dll" -Company "Contoso Security" -FileName "C:\Program Files\Contoso\ContosoAmsi.dll"))
        }

        It "Should report the provider as AMSI module" {
            $Script:result.ProcessInformation.AmsiProviderModuleNames | Should -Be "ContosoAmsi.dll"
            $Script:result.ThirdPartyModuleFound | Should -Be $false
            $Script:hostController.AmsiModules.ModuleName | Should -Be "ContosoAmsi.dll"
        }
    }

    Context "No AMSI provider is registered" {
        BeforeAll {
            InvokeTestSearchProcessState -AmsiProvidersKeyExists $false -HostControllerModules @($Script:amsiDll, $Script:mpOavDll)
        }

        It "Should report the Windows Defender module as 3rd party module without registration issues" {
            $Script:result.ThirdPartyModuleFound | Should -Be $true
            $Script:hostController.ThirdPartyModules.ModuleName | Should -Be "MpOav.dll"
            $Script:result.ProcessInformation.AmsiProviderErrors.Count | Should -Be 0
        }
    }

    Context "The AMSI provider registration can't be read" {
        BeforeAll {
            InvokeTestSearchProcessState -ProviderReadFails $true -HostControllerModules @($Script:amsiDll, $Script:mpOavDll)
        }

        It "Should return the registration issue" {
            $Script:result.ProcessInformation.AmsiProviderErrors.Count | Should -Be 1
            $Script:result.ProcessInformation.AmsiProviderErrors[0] | Should -BeLike "*$Script:providerGuid*Requested registry access is not allowed.*"
        }

        It "Should report the Windows Defender module as 3rd party module" {
            $Script:result.ThirdPartyModuleFound | Should -Be $true
            $Script:hostController.ThirdPartyModules.ModuleName | Should -Be "MpOav.dll"
        }
    }

    Context "The AMSI providers registry key can't be checked" {
        BeforeAll {
            InvokeTestSearchProcessState -ProvidersPathCheckFails $true -HostControllerModules @($Script:amsiDll, $Script:mpOavDll)
        }

        It "Should return the registration issue" {
            $Script:result.ProcessInformation.AmsiProviderErrors.Count | Should -Be 1
            $Script:result.ProcessInformation.AmsiProviderErrors[0] | Should -BeLike "Failed to check $Script:amsiProvidersPath*Requested registry access is not allowed.*"
        }

        It "Should still collect all search processes" {
            $Script:result.AllProcessesRunning | Should -Be $true
            $Script:hostController.ThirdPartyModules.ModuleName | Should -Be "MpOav.dll"
        }
    }

    Context "The process modules can't be read" {
        BeforeAll {
            InvokeTestSearchProcessState -HostControllerModules $null
        }

        It "Should report that the modules can't be read" {
            $Script:result.ModulesReadFailed | Should -Be $true
            $Script:hostController.ModulesReadError | Should -Not -BeNullOrEmpty
        }

        It "Should not report an empty 3rd party module" {
            $Script:result.ThirdPartyModuleFound | Should -Be $false
            $Script:hostController.ThirdPartyModules.Count | Should -Be 0
        }
    }
}
