# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

Describe "Checking PageFile Scenarios" {

    BeforeAll {
        . $PSScriptRoot\HealthCheckerTests.ImportCode.NotPublished.ps1
        $Script:MockDataCollectionRoot = "$Script:parentPath\Tests\DataCollection\E19"
        . $PSScriptRoot\HealthCheckerTest.CommonMocks.NotPublished.ps1
    }

    Context "Scenario 1 - Configure As Expected" {

        BeforeAll {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PageFileWellConfigured.xml" }

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
    }

    Context "Scenario 2 - Oversized" {

        BeforeAll {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PageFileOverSized.xml" }

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
    }

    Context "Scenario 3 - System-managed" {

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

    Context "Scenario 4 - System Managed and Static" {

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

    Context "Scenario 5 - One Correct and One Oversized" {

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
