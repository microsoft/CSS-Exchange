# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    . $PSScriptRoot\..\..\..\..\Shared\PesterLoadFunctions.NotPublished.ps1
    $scriptContent = Get-PesterScriptContent -FilePath "$PSScriptRoot\..\Invoke-AnalyzerKnownBuildIssues.ps1"
    Invoke-Expression $scriptContent
    Function Invoke-CatchActions { throw "Called Invoke-CatchActions" }

    Function TestPesterResults {
        param(
            [hashtable]$TestGroup,
            [object]$KnownIssue
        )

        foreach ($key in $TestGroup.Keys) {
            $currentBuild = GetVersionFromString $key
            TestOnKnownBuildIssue $KnownIssue $currentBuild -Verbose | Should -Be $TestGroup[$key]
        }
    }
}

Describe "Testing Known Build Issue Main Logic" {

    Context "Basic Test Initial Tests" {

        It "Initial Testing CU Bound" {

            TestPesterResults -TestGroup @{
                "15.1.2375.17" = $true
                "15.1.2375.16" = $false
                "15.1.2376.17" = $false
                "15.1.2375.18" = $true
            } `
                -KnownIssue (GetKnownIssueBuildInformation -BuildNumber "15.1.2375.17" -FixBuildNumber $null)
        }

        It "Initial Testing CU Not Bound" {

            TestPesterResults -TestGroup @{
                "15.1.2375.17" = $true
                "15.1.2375.16" = $false
                "15.1.2376.17" = $true
                "15.1.2375.18" = $true
            } `
                -KnownIssue (GetKnownIssueBuildInformation -BuildNumber "15.1.2375.17" -FixBuildNumber $null -BuildBound $false)
        }

        It "On Fix Build" {

            TestPesterResults -TestGroup @{
                "15.1.2375.17" = $true
                "15.1.2375.16" = $false
                "15.1.2376.17" = $false
                "15.1.2375.18" = $false
            } `
                -KnownIssue (GetKnownIssueBuildInformation -BuildNumber "15.1.2375.17" -FixBuildNumber "15.1.2375.18")
        }

        It "Testing Major Diff" {

            TestPesterResults -TestGroup @{
                "15.1.2375.17" = $false
                "15.1.2375.16" = $false
                "15.1.2376.17" = $false
                "15.1.2375.18" = $false
            } `
                -KnownIssue (GetKnownIssueBuildInformation -BuildNumber "15.2.2375.17" -FixBuildNumber $null)
        }
    }
}
