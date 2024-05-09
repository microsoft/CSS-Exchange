# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

Describe "Exchange 2019 Scenarios testing 2" {

    BeforeAll {
        . $PSScriptRoot\HealthCheckerTests.ImportCode.NotPublished.ps1
        $Script:MockDataCollectionRoot = "$Script:parentPath\Tests\DataCollection\E19"
        . $PSScriptRoot\HealthCheckerTest.CommonMocks.NotPublished.ps1
    }

    Context "Scenario 1" {

        BeforeAll {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PageFileWellConfigured.xml" }
            Mock Invoke-ScriptBlockHandler -ParameterFilter { $ScriptBlockDescription -eq "Getting applicationHost.config" } -MockWith { return Get-Content "$Script:MockDataCollectionRoot\Exchange\IIS\BadApplicationHost.config" -Raw -Encoding UTF8 }
            Mock Get-WebApplication -MockWith { throw "Error - Pester" }
            Mock Get-WebSite -ParameterFilter { $null -eq $Name } -MockWith { throw "Error - Pester" }
            Mock Get-WebSite -ParameterFilter { $Name -eq "Default Web Site" } -MockWith { throw "Error - Pester" }
            Mock Get-WebSite -ParameterFilter { $Name -eq "Exchange Back End" } -MockWith { throw "Error - Pester" }

            SetDefaultRunOfHealthChecker "Debug_PageFile_Well_Scenario_Results.xml"
        }

        It "PageFile Configured As Expected" {

            SetActiveDisplayGrouping "Operating System Information"
            $pageFile = GetObject "PageFile Size 0"
            $pageFile.Name | Should -Be "c:\pagefile.sys"
            $pageFile.TotalPhysicalMemory | Should -Be 6144
            $pageFile.MaxPageSize | Should -Be 1536
            $pageFile.MultiPageFile | Should -Be $false
            $pageFile.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be $null
        }

        It "Bad application host config file" {
            SetActiveDisplayGrouping "Exchange IIS Information"
            TestObjectMatch "Invalid Configuration File - Application Host Config File" $true -WriteType "Red"
            $m = GetObject "Missing Web Application Configuration File"
            $m | Should -Be $null
        }
    }

    Context "Scenario 2" {

        BeforeAll {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PageFileOverSized.xml" }

            # Unable to test the error logic for Get-WebConfigFile at this time.
            # Instead just going to point the path to the bad file to continue to test out the rest of the logic.
            Mock Get-WebConfigFile -ParameterFilter { $PSPath -like "IIS:\Sites\Default Web Site*" } -MockWith { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite_web1.config" } }
            Mock Get-WebConfigFile -ParameterFilter { $PSPath -eq "IIS:\Sites\Exchange Back End/mapi/emsmdb" } -MockWith { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\applicationHost.config" } }
            SetDefaultRunOfHealthChecker "Debug_PageFile_OverSized_Scenario_Results.xml"
        }

        It "PageFile Oversized" {

            SetActiveDisplayGrouping "Operating System Information"
            $pageFile = GetObject "PageFile Size 0"
            $pageFile.Name | Should -Be "c:\pagefile.sys"
            $pageFile.TotalPhysicalMemory | Should -Be 6144
            $pageFile.MaxPageSize | Should -Be 2025
            $pageFile.MultiPageFile | Should -Be $false
            $pageFile.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be "Warning: On Exchange 2019, the recommended PageFile size is 25% (1536MB) of the total system memory (6144MB)."
        }

        It "Bad Default Web Site web.config file" {
            SetActiveDisplayGrouping "Exchange IIS Information"
            TestObjectMatch "Invalid Configuration File" $true -WriteType "Red"
            TestObjectMatch "Invalid: $Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite_web1.config" $true -WriteType "Red"
            TestObjectMatch "Missing Web Application Configuration File" $true -WriteType "Red"
            TestObjectMatch "Web Application: 'Exchange Back End/mapi/emsmdb'" "$Script:MockDataCollectionRoot\Exchange\IIS\applicationHost.config" -WriteType "Red"
        }
    }

    Context "Scenario 3" {

        BeforeAll {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PageFileSystemManaged.xml" }

            SetDefaultRunOfHealthChecker "Debug_PageFile_SystemManaged_Scenario_Results.xml"
        }

        It "PageFile System-managed" {

            SetActiveDisplayGrouping "Operating System Information"
            $pageFile = GetObject "PageFile Size 0"
            $pageFile.Name | Should -Be ""
            $pageFile.TotalPhysicalMemory | Should -Be 6144
            $pageFile.MaxPageSize | Should -Be 0
            $pageFile.MultiPageFile | Should -Be $false
            $pageFile.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be "Error: On Exchange 2019, the recommended PageFile size is 25% (1536MB) of the total system memory (6144MB)."
        }
    }

    Context "Scenario 4" {

        BeforeAll {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_MultiplePageFilesOneSystemManaged.xml" }

            SetDefaultRunOfHealthChecker "Debug_PageFile_Multiple_PageFiles_Scenario1_Results.xml"
        }

        It "PageFiles One System Managed, One Static" {

            SetActiveDisplayGrouping "Operating System Information"
            $pageFile1 = GetObject "PageFile Size 0"
            $pageFile1.Name | Should -Be "c:\pagefile.sys"
            $pageFile1.TotalPhysicalMemory | Should -Be 6144
            $pageFile1.MaxPageSize | Should -Be 1536
            $pageFile1.MultiPageFile | Should -Be $true
            $pageFile1.RecommendedPageFile | Should -Be 1536

            $pageFile2 = GetObject "PageFile Size 1"
            $pageFile2.Name | Should -Be "d:\pagefile.sys"
            $pageFile2.TotalPhysicalMemory | Should -Be 6144
            $pageFile2.MaxPageSize | Should -Be 0
            $pageFile2.MultiPageFile | Should -Be $true
            $pageFile2.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be "Error: On Exchange 2019, the recommended PageFile size is 25% (1536MB) of the total system memory (6144MB)."

            $multiPageFileWarning = GetObject "Multiple PageFile Detected"
            $multiPageFileWarning | Should -Be $true
        }
    }

    Context "Scenario 5" {

        BeforeAll {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_MultiplePageFilesOneOverSized.xml" }

            SetDefaultRunOfHealthChecker "Debug_PageFile_Multiple_PageFiles_Scenario1_Results.xml"
        }

        It "PageFiles One Correct, One OverSized" {

            SetActiveDisplayGrouping "Operating System Information"
            $pageFile1 = GetObject "PageFile Size 0"
            $pageFile1.Name | Should -Be "c:\pagefile.sys"
            $pageFile1.TotalPhysicalMemory | Should -Be 6144
            $pageFile1.MaxPageSize | Should -Be 1536
            $pageFile1.MultiPageFile | Should -Be $true
            $pageFile1.RecommendedPageFile | Should -Be 1536

            $pageFile2 = GetObject "PageFile Size 1"
            $pageFile2.Name | Should -Be "d:\pagefile.sys"
            $pageFile2.TotalPhysicalMemory | Should -Be 6144
            $pageFile2.MaxPageSize | Should -Be 2024
            $pageFile2.MultiPageFile | Should -Be $true
            $pageFile2.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be "Warning: On Exchange 2019, the recommended PageFile size is 25% (1536MB) of the total system memory (6144MB)."

            $multiPageFileWarning = GetObject "Multiple PageFile Detected"
            $multiPageFileWarning | Should -Be $true
        }
    }
}
