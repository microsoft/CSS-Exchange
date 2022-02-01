# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Get-ExchangeBuildVersionInformation.ps1
}

Describe "Testing Get-ExchangeBuildVersionInformation.ps1" {

    Context "Parse AdminDisplayVersion CU Build ServerVersion Object" {
        BeforeAll {
            [object]$e19CU11ServerVersion = Import-Clixml $Script:parentPath\Tests\E19CU11AdminDisplayVersion.xml
            $Script:results = Get-ExchangeBuildVersionInformation -AdminDisplayVersion $e19CU11ServerVersion
            [System.Version]$Script:fullAdminDisplayVersionBuildNumber = "{0}.{1}.{2}.{3}" -f $results.Major, $results.Minor, $results.Build, $results.Revision
        }

        It "Return the final E19CU11 version object" {
            $results.MajorVersion | Should -Be "Exchange2019"
            $results.Major | Should -Be 15
            $results.Minor | Should -Be 2
            $results.Build | Should -Be 986
            $results.Revision | Should -Be 5
            $results.Product | Should -Be 15.2
            $results.BuildVersion | Should -Be 986.5
        }

        It "Perform version comparison E19CU11" {
            $fullAdminDisplayVersionBuildNumber -lt "15.2.986.5" | Should -Be $false
            $fullAdminDisplayVersionBuildNumber -ge "15.2.986.5" | Should -Be $true
        }
    }

    Context "Parse AdminDisplayVersion CU Build String Object" {
        BeforeAll {
            [string]$e19CU11 = "Version 15.2 (Build 986.5)"
            $Script:results = Get-ExchangeBuildVersionInformation -AdminDisplayVersion $e19CU11
            [System.Version]$Script:fullAdminDisplayVersionBuildNumber = "{0}.{1}.{2}.{3}" -f $results.Major, $results.Minor, $results.Build, $results.Revision
        }

        It "Return the final E19CU11 version object" {
            $results.MajorVersion | Should -Be "Exchange2019"
            $results.Major | Should -Be 15
            $results.Minor | Should -Be 2
            $results.Build | Should -Be 986
            $results.Revision | Should -Be 5
            $results.Product | Should -Be 15.2
            $results.BuildVersion | Should -Be 986.5
        }

        It "Perform version comparison E19CU11" {
            $fullAdminDisplayVersionBuildNumber -lt "15.2.986.5" | Should -Be $false
            $fullAdminDisplayVersionBuildNumber -ge "15.2.986.5" | Should -Be $true
        }
    }

    Context "Parse AdminDisplayVersion CU + SU Build String Object" {
        BeforeAll {
            [string]$e19CU10Jan22SU = "Version 15.2 (Build 922.20)"
            $Script:results = Get-ExchangeBuildVersionInformation -AdminDisplayVersion $e19CU10Jan22SU
            [System.Version]$Script:fullAdminDisplayVersionBuildNumber = "{0}.{1}.{2}.{3}" -f $results.Major, $results.Minor, $results.Build, $results.Revision
        }

        It "Return the final E19CU10Jan22SU version object" {
            $results.MajorVersion | Should -Be "Exchange2019"
            $results.Major | Should -Be 15
            $results.Minor | Should -Be 2
            $results.Build | Should -Be 922
            $results.Revision | Should -Be 20
            $results.Product | Should -Be 15.2
            $results.BuildVersion | Should -Be 922.20
        }

        It "Perform version comparison E19CU10Jan22SU" {
            $fullAdminDisplayVersionBuildNumber -lt "15.2.922.7" | Should -Be $false
            $fullAdminDisplayVersionBuildNumber -lt "15.2.986.5" | Should -Be $true
            $fullAdminDisplayVersionBuildNumber -ge "15.2.986.5" | Should -Be $false
        }
    }
}