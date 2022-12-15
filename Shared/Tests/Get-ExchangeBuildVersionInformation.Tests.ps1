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
        }

        It "Return the final E19CU11 version object" {
            $results.MajorVersion | Should -Be "Exchange2019"
            $results.FriendlyName = "Exchange 2019 CU11"
            $results.BuildVersion.ToString() | Should -Be "15.2.986.5"
            $results.CU | Should -Be "CU11"
            $results.ReleaseDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"9/28/2021", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.ExtendedSupportDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"10/14/2025", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.Supported | Should -Be $true
            $results.LatestSU | Should -Be $false
            $results.ADLevel.SchemaValue | Should -Be 17003
            $results.ADLevel.MESOValue | Should -Be 13242
            $results.ADLevel.OrgValue | Should -Be 16759
        }
    }

    Context "Parse AdminDisplayVersion CU Build String Object" {
        BeforeAll {
            [string]$e19CU11 = "Version 15.2 (Build 986.5)"
            $Script:results = Get-ExchangeBuildVersionInformation -AdminDisplayVersion $e19CU11
        }

        It "Return the final E19CU11 version object" {
            $results.MajorVersion | Should -Be "Exchange2019"
            $results.FriendlyName = "Exchange 2019 CU11"
            $results.BuildVersion.ToString() | Should -Be "15.2.986.5"
            $results.CU | Should -Be "CU11"
            $results.ReleaseDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"9/28/2021", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.ExtendedSupportDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"10/14/2025", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.Supported | Should -Be $true
            $results.LatestSU | Should -Be $false
            $results.ADLevel.SchemaValue | Should -Be 17003
            $results.ADLevel.MESOValue | Should -Be 13242
            $results.ADLevel.OrgValue | Should -Be 16759
        }
    }

    Context "Parse FileVersion String Object" {
        BeforeAll {
            [string]$fileVersion = "15.2.1118.15"
            $Script:results = Get-ExchangeBuildVersionInformation -FileVersion $fileVersion
        }

        It "Return the final E19CU12 Oct22SU version object" {
            $results.MajorVersion | Should -Be "Exchange2019"
            $results.FriendlyName = "Exchange 2019 CU12 Oct22SU"
            $results.BuildVersion.ToString() | Should -Be "15.2.1118.15"
            $results.CU | Should -Be "CU12"
            $results.ReleaseDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"04/20/2022", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.ExtendedSupportDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"10/14/2025", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.Supported | Should -Be $true
            $results.LatestSU | Should -Be $false
            $results.ADLevel.SchemaValue | Should -Be 17003
            $results.ADLevel.MESOValue | Should -Be 13243
            $results.ADLevel.OrgValue | Should -Be 16760
        }
    }

    Context "Testing Unsupported CU Exchange 2019 CU 10 Jul21SU" {
        BeforeAll {
            [string]$fileVersion = "15.02.0922.013"
            $Script:results = Get-ExchangeBuildVersionInformation -FileVersion $fileVersion
        }

        It "Return the final E19CU12 Oct22SU version object" {
            $results.MajorVersion | Should -Be "Exchange2019"
            $results.FriendlyName = "Exchange 2019 CU10 Jul21SU"
            $results.BuildVersion.ToString() | Should -Be "15.2.922.13"
            $results.CU | Should -Be "CU10"
            $results.ReleaseDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"06/29/2021", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.ExtendedSupportDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"10/14/2025", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.Supported | Should -Be $false
            $results.LatestSU | Should -Be $false
            $results.ADLevel.SchemaValue | Should -Be 17003
            $results.ADLevel.MESOValue | Should -Be 13241
            $results.ADLevel.OrgValue | Should -Be 16758
        }
    }
}
