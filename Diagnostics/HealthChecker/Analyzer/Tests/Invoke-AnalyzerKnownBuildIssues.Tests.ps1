# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    . $PSScriptRoot\..\..\..\..\Shared\PesterLoadFunctions.NotPublished.ps1
    $scriptContent = Get-PesterScriptContent -FilePath "$PSScriptRoot\..\Invoke-AnalyzerKnownBuildIssues.ps1"
    Invoke-Expression $scriptContent
    function Invoke-CatchActions { throw "Called Invoke-CatchActions" }

    function TestPesterResults {
        param(
            [Hashtable]$TestGroup,
            [object]$KnownIssue
        )

        foreach ($key in $TestGroup.Keys) {
            $currentBuild = GetVersionFromString $key
            TestOnKnownBuildIssue $KnownIssue $currentBuild | Should -Be $TestGroup[$key]
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

        It "Testing Issue always been there" {
            TestPesterResults -TestGroup @{
                "15.2.1544.14" = $false
                "15.2.1544.13" = $false # This is false, but the next test it should be true
                "15.2.1258.39" = $false
                "15.2.1258.38" = $true
                "15.2.1118.40" = $true
            } `
                -KnownIssue (GetKnownIssueBuildInformation -BuildNumber "15.2.0.0" -FixBuildNumber "15.2.1258.39" -BuildBound $false)

            TestPesterResults -TestGroup @{
                "15.2.1544.14" = $false
                "15.2.1544.13" = $true
                "15.2.1258.39" = $false
                "15.2.1258.38" = $false
                "15.2.1118.40" = $false
            } `
                -KnownIssue (GetKnownIssueBuildInformation -BuildNumber "15.2.1544.0" -FixBuildNumber "15.2.1544.14" -BuildBound $true)
        }
    }
}
