# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\IISFunctions\Get-IISModules.ps1
    . $Script:parentPath\Invoke-ScriptBlockHandler.ps1

    function LoadApplicationHostConfig {
        [CmdletBinding()]
        [OutputType("System.Xml.XmlNode")]
        param(
            [string]$Path
        )

        $appHostConfig = New-Object -TypeName Xml
        try {
            $appHostConfig.Load($Path)
        } catch {
            throw "Failed to loaded application host config file. $_"
            $appHostConfig = $null
        }
        return $appHostConfig
    }

    Mock Invoke-CatchActionError {
        param()
    }

    Mock Get-AuthenticodeSignature {
        param(
            [string[]]$FilePath
        )

        $modulesList = New-Object 'System.Collections.Generic.List[System.Object]'
        foreach ($path in $FilePath) {
            $pathArray = $path.Split("\")
            try {
                $mockedData = $pathArray[-1].replace(".dll", ".xml")
                $modulesList.Add((Import-Clixml -Path $Script:parentPath\Tests\Data\acs_$mockedData -ErrorAction Stop))
            } catch {
                Write-Verbose "Unable to mock module signature for $path"
            }
        }

        return $modulesList
    }

    $Script:E19_ApplicationHost_Default = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E19_applicationHost_Default.config
    $Script:E16_ApplicationHost_Default = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E16_applicationHost_Default.config
    $Script:E16_ApplicationHost_Mixed = LoadApplicationHostConfig -Path $Script:parentPath\Tests\Data\E16_applicationHost_Mixed.config
}

Describe "Testing Get-IISModules.ps1" {
    Context "Exchange 2019 Default applicationHost.config" {
        BeforeAll {
            $Script:iisModules = Get-IISModules -ApplicationHostConfig $E19_ApplicationHost_Default
        }

        It "Should Return The IISModules Object" {
            $iisModules.GetType() | Should -Be PSCustomObject
            $iisModules.ModuleList.GetType() | Should -Be System.Object[]
            $iisModules.Count | Should -Be 1
            $iisModules.ModuleList.Count | Should -Be 31
        }

        It "All Signed Modules Should Be Signed By Microsoft" {
            $iisModules.AllSignedModulesSignedByMSFT | Should -Be $true
            $iisModules.ModuleList.Signed.Contains($false) | Should -Be $false
        }

        It "All Signatures Should Be Valid" {
            $iisModules.AllSignaturesValid | Should -Be $true
        }

        It "All Modules Should Be Signed" {
            $iisModules.AllModulesSigned | Should -Be $true
            foreach ($m in $iisModules.ModuleList) {
                $m.Signed | Should -Be $true
                $m.SignatureDetails.SignatureStatus | Should -Be 0
                $m.SignatureDetails.Signer | Should -BeLike "*Microsoft*"
                $m.SignatureDetails.IsMicrosoftSigned | Should -Be $true
            }
        }
    }

    Context "Exchange 2016 Default applicationHost.config" {
        BeforeAll {
            $Script:iisModules = Get-IISModules -ApplicationHostConfig $E16_ApplicationHost_Default
        }

        It "Should Return The IISModules Object" {
            $iisModules.GetType() | Should -Be PSCustomObject
            $iisModules.ModuleList.GetType() | Should -Be System.Object[]
            $iisModules.Count | Should -Be 1
            $iisModules.ModuleList.Count | Should -Be 31
        }

        It "All Signed Modules Should Be Signed By Microsoft" {
            $iisModules.AllSignedModulesSignedByMSFT | Should -Be $true
            $iisModules.ModuleList.Signed.Contains($false) | Should -Be $false
        }

        It "All Signatures Should Be Valid" {
            $iisModules.AllSignaturesValid | Should -Be $true
        }

        It "All Modules Should Be Signed" {
            $iisModules.AllModulesSigned | Should -Be $true
            foreach ($m in $iisModules.ModuleList) {
                $m.Signed | Should -Be $true
                $m.SignatureDetails.SignatureStatus | Should -Be 0
                $m.SignatureDetails.Signer | Should -BeLike "*Microsoft*"
                $m.SignatureDetails.IsMicrosoftSigned | Should -Be $true
            }
        }
    }

    Context "Exchange 2016 Mixed applicationHost.config" {
        BeforeAll {
            $Script:iisModules = Get-IISModules -ApplicationHostConfig $E16_ApplicationHost_Mixed
        }

        It "Should Return The IISModules Object" {
            $iisModules.GetType() | Should -Be PSCustomObject
            $iisModules.ModuleList.GetType() | Should -Be System.Object[]
            $iisModules.Count | Should -Be 1
            $iisModules.ModuleList.Count | Should -Be 34
        }

        It "Not All Signed Modules Are Signed By Microsoft" {
            $iisModules.AllSignedModulesSignedByMSFT | Should -Be $false
            $iisModules.ModuleList.Signed.Contains($false) | Should -Be $true
        }

        It "All Signatures Should Be Valid" {
            $iisModules.AllSignaturesValid | Should -Be $true
        }

        It "Not All Modules Are Signed" {
            $iisModules.AllModulesSigned | Should -Be $false
        }

        It "Module Signed By 3rd Party" {
            foreach ($m in $iisModules.ModuleList) {
                if ($m.Name -eq "Test-SignedBy3rdParty") {
                    $m.Signed | Should -Be $true
                    $m.SignatureDetails.SignatureStatus | Should -Be 0
                    $m.SignatureDetails.Signer | Should -Be "CN=ContosoTech"
                    $m.SignatureDetails.IsMicrosoftSigned | Should -Be $false
                }
            }
        }

        It "Module Is Not Signed" {
            foreach ($m in $iisModules.ModuleList) {
                if (($m.Name -eq "Test-UnsignedInvalid") -or
                    ($m.Name -eq "Test-Unsigned")) {
                    $m.Signed | Should -Be $false
                    $m.SignatureDetails.SignatureStatus | Should -Be -1
                }
            }
        }
    }

    Context "Exchange 2016 Default applicationHost.config On Pre-Windows 2016 Server" {
        BeforeAll {
            $Script:iisModules = Get-IISModules -ApplicationHostConfig $E16_ApplicationHost_Default -SkipLegacyOSModulesCheck $true
        }

        It "Should Return The IISModules Object" {
            $iisModules.GetType() | Should -Be PSCustomObject
            $iisModules.ModuleList.GetType() | Should -Be System.Object[]
            $iisModules.Count | Should -Be 1
            $iisModules.ModuleList.Count | Should -Be 31
        }

        It "Should Contain Default Modules Which Are Excluded" {
            $iisModules.ModuleList.Path -contains "C:\Windows\system32\inetSrv\protSup.dll" | Should -Be $true
            $iisModules.ModuleList.Path -contains "C:\Windows\system32\inetSrv\iisFreb.dll" | Should -Be $true
            $iisModules.ModuleList.Path -contains "C:\Windows\system32\inetSrv\isApi.dll" | Should -Be $true
            $iisModules.ModuleList.Path -contains "C:\Windows\system32\rpcProxy\rpcProxy.dll" | Should -Be $true
            $iisModules.ModuleList.Path -contains "C:\Windows\system32\inetSrv\cachtokn.dll" | Should -Be $true
        }

        It "Should Contain Default Signature Information For Modules That Are Skipped" {
            foreach ($m in $iisModules.ModuleList) {
                if (($m.Name -eq "TokenCacheModule") -or
                    ($m.Name -eq "ProtocolSupportModule")) {
                    $m.Signed | Should -Be $null
                    $m.SignatureDetails.SignatureStatus | Should -Be -1
                    $m.SignatureDetails.Signer | Should -Be $null
                    $m.SignatureDetails.IsMicrosoftSigned | Should -Be $null
                }
            }
        }
    }
}
