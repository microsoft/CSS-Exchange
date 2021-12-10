# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\..\..\Helpers\Class.ps1
    . $Script:parentPath\Get-ExchangeKnownIssuesBuildState.ps1
}

Describe "Testing Get-ExchangeKnownIssuesBuildState.ps1" {
    BeforeAll {
        [double]$Script:buildWithIssues = 985.2
        [double]$Script:buildWithoutIssues = 986.5

        [HealthChecker.ExchangeInformation]$Script:exchangeInformation = New-Object -TypeName HealthChecker.ExchangeInformation
        $Script:exchangeInformation.BuildInformation.MajorVersion = [HealthChecker.ExchangeMajorVersion]::Exchange2019
    }

    Context "Pass A Build Number Which Has Known Issues" {
        BeforeAll {
            $Script:results = Get-ExchangeKnownIssuesBuildState `
                -MajorVersion $exchangeInformation.BuildInformation.MajorVersion `
                -BuildAndRevision $buildWithIssues
        }

        It "Build Has Known Issues" {
            $results.BuildWithIssues | Should -Be $true
        }

        It "KB Url Is Returned" {
            $results.IssueKb | Should -Be "https://support.microsoft.com/help/xxxxxxx"
        }
    }

    Context "Pass A Build Number Without Known Issues" {
        BeforeAll {
            $Script:results = Get-ExchangeKnownIssuesBuildState `
                -MajorVersion $exchangeInformation.BuildInformation.MajorVersion `
                -BuildAndRevision $buildWithoutIssues
        }

        It "Build Is Reported As Good" {
            $results.BuildWithIssues | Should -Be $false
        }

        It "KB Url Is null" {
            $results.IssueKb | Should -Be $null
        }
    }
}
