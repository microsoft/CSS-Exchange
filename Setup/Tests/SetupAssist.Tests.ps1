# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    . $PSScriptRoot\..\..\.build\BuildFunctions\Get-ExpandedScriptContent.ps1
    $Script:parentPath = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), "SetupAssist")
    $Script:PesterExtract = "# Extract for Pester Testing - Start"
}

Describe "Testing SetupAssist" {

    BeforeAll {

        #Load the functions
        $internalFunctions = New-Object 'System.Collections.Generic.List[string]'
        $scriptContent = Get-ExpandedScriptContent -File "$Script:parentPath\Checks\Domain\Test-ExchangeADSetupLevel.ps1"
        $startIndex = $scriptContent.Trim().IndexOf($Script:PesterExtract)
        for ($i = $startIndex + 1; $i -lt $scriptContent.Count; $i++) {
            if ($scriptContent[$i].Trim().Contains($Script:PesterExtract.Replace("Start", "End"))) {
                $endIndex = $i
                break
            }
            $internalFunctions.Add($scriptContent[$i])
        }

        $scriptContent.RemoveRange($startIndex, $endIndex - $startIndex)
        $scriptContentString = [string]::Empty
        $internalFunctionsString = [string]::Empty
        $scriptContent | ForEach-Object { $scriptContentString += "$($_)`n" }
        $internalFunctions | ForEach-Object { $internalFunctionsString += "$($_)`n" }
        Invoke-Expression $scriptContentString
        Invoke-Expression $internalFunctionsString
    }

    Context "Test-ExchangeADSetupLevel Function Test" {

        BeforeEach {

            Mock GetExchangeADSetupLevel { return $Script:GetExchangeADSetupLevel }
            Mock TestMismatchLevel {}
            Mock TestPrepareAD {}
            Mock Test-UserGroupMemberOf {}

            Function SetGetExchangeADSetupLevel {
                param(
                    [int]$OrgValue,
                    [int]$SchemaValue,
                    [int]$MESOValue
                )

                $Script:GetExchangeADSetupLevel = [PSCustomObject]@{
                    Org    = [PSCustomObject]@{
                        DN    = "CN=ContosoOrg,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=Contoso,DC=local"
                        Value = $OrgValue
                    }
                    Schema = [PSCustomObject]@{
                        DN    = "CN=ms-Exch-Schema-Version-Pt,CN=Schema,CN=Configuration,DC=Contoso,DC=local"
                        Value = $SchemaValue
                    }
                    MESO   = [PSCustomObject]@{
                        DN    = "CN=Microsoft Exchange System Objects,DC=Contoso,DC=local"
                        Value = $MESOValue
                    }
                }
            }
        }

        It "Unknown Exchange 2013 Schema Value" {
            SetGetExchangeADSetupLevel -OrgValue 15130 -SchemaValue 15130 -MESOValue 15130
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "Unknown Exchange Schema Version"
        }

        It "Exchange 2013 CU23 Not Ready" {
            SetGetExchangeADSetupLevel -OrgValue 16133 -SchemaValue 15312 -MESOValue 13236
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "Exchange 2013 CU23 Not Ready"
        }

        It "Exchange 2013 CU23 Ready" {
            SetGetExchangeADSetupLevel -OrgValue 16133 -SchemaValue 15312 -MESOValue 13237
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Passed"
            $results.Details | Should -Be "Exchange 2013 CU23 Ready"
        }

        It "Exchange 2016 Mismatch MESO 13236 Schema 15332" {
            SetGetExchangeADSetupLevel -OrgValue 16133 -SchemaValue 15332 -MESOValue 13236
            Test-ExchangeADSetupLevel
            Assert-MockCalled -Exactly 1 -CommandName "TestMismatchLevel"
        }

        It "Exchange 2016 Mismatch MESO 13235 Schema 15332" {
            SetGetExchangeADSetupLevel -OrgValue 16133 -SchemaValue 15332 -MESOValue 13235
            Test-ExchangeADSetupLevel
            Assert-MockCalled -Exactly 1 -CommandName "TestMismatchLevel"
        }

        It "Exchange 2016 CU10" {
            SetGetExchangeADSetupLevel -OrgValue 16213 -SchemaValue 15332 -MESOValue 13236
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2016 CU10"
        }

        It "Exchange 2016 CU11" {
            SetGetExchangeADSetupLevel -OrgValue 16214 -SchemaValue 15332 -MESOValue 13236
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2016 CU11"
        }

        It "Exchange 2016 CU12" {
            SetGetExchangeADSetupLevel -OrgValue 16215 -SchemaValue 15332 -MESOValue 13236
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2016 CU12"
        }

        It "Exchange 2016 CU17" {
            SetGetExchangeADSetupLevel -OrgValue 16217 -SchemaValue 15332 -MESOValue 13237
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2016 CU17"
        }

        It "Exchange 2016 CU18" {
            SetGetExchangeADSetupLevel -OrgValue 16218 -SchemaValue 15332 -MESOValue 13238
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2016 CU18"
        }

        It "Exchange 2016 CU19" {
            SetGetExchangeADSetupLevel -OrgValue 16219 -SchemaValue 15333 -MESOValue 13239
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2016 CU19"
        }

        It "Exchange 2016 CU20" {
            SetGetExchangeADSetupLevel -OrgValue 16220 -SchemaValue 15333 -MESOValue 13240
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2016 CU20"
        }

        It "Exchange 2016 Mismatch Schema 15333" {
            SetGetExchangeADSetupLevel -OrgValue 16221 -SchemaValue 15333 -MESOValue 13240
            Test-ExchangeADSetupLevel
            Assert-MockCalled -Exactly 1 -CommandName "TestMismatchLevel"
        }

        It "Exchange 2016 CU21" {
            SetGetExchangeADSetupLevel -OrgValue 16221 -SchemaValue 15334 -MESOValue 13241
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2016 CU21"
        }

        It "Exchange 2016 CU22" {
            SetGetExchangeADSetupLevel -OrgValue 16222 -SchemaValue 15334 -MESOValue 13242
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Passed"
            $results.Details | Should -Be "At Exchange 2016 CU22"
        }

        It "Exchange 2016 Mismatch Schema 15334" {
            SetGetExchangeADSetupLevel -OrgValue 16221 -SchemaValue 15334 -MESOValue 13240
            Test-ExchangeADSetupLevel
            Assert-MockCalled -Exactly 1 -CommandName "TestMismatchLevel"
        }

        It "Exchange 2019 CU8" {
            SetGetExchangeADSetupLevel -OrgValue 16756 -SchemaValue 17002 -MESOValue 13239
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2019 CU8"
        }

        It "Exchange 2019 CU9" {
            SetGetExchangeADSetupLevel -OrgValue 16757 -SchemaValue 17002 -MESOValue 13240
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2019 CU9"
        }

        It "Exchange 2019 Mismatch Schema 17002" {
            SetGetExchangeADSetupLevel -OrgValue 16221 -SchemaValue 17002 -MESOValue 13240
            Test-ExchangeADSetupLevel
            Assert-MockCalled -Exactly 1 -CommandName "TestMismatchLevel"
        }

        It "Exchange 2019 CU10" {
            SetGetExchangeADSetupLevel -OrgValue 16758 -SchemaValue 17003 -MESOValue 13241
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2019 CU10"
        }

        It "Exchange 2019 CU11" {
            SetGetExchangeADSetupLevel -OrgValue 16759 -SchemaValue 17003 -MESOValue 13242
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Passed"
            $results.Details | Should -Be "At Exchange 2019 CU11"
        }

        It "Exchange 2019 Mismatch Schema 17003" {
            SetGetExchangeADSetupLevel -OrgValue 16757 -SchemaValue 17003 -MESOValue 13241
            Test-ExchangeADSetupLevel
            Assert-MockCalled -Exactly 1 -CommandName "TestMismatchLevel"
        }
    }
}
