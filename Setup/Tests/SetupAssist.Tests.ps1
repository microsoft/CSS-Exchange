# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), "SetupAssist")
    . $PSScriptRoot\..\..\Shared\PesterLoadFunctions.NotPublished.ps1
}

Describe "Testing SetupAssist" {

    BeforeAll {

        #Load the functions
        $scriptContent = Get-PesterScriptContent -FilePath "$Script:parentPath\Checks\Domain\Test-ExchangeADSetupLevel.ps1"
        Invoke-Expression $scriptContent
    }

    Context "Test-ExchangeADSetupLevel Function Test" {

        BeforeEach {

            Mock GetExchangeADSetupLevel { return $Script:GetExchangeADSetupLevel }
            Mock Get-SetupLogReviewer { return $Script:GetSetupLogReviewer }
            Mock TestPrepareAD {}
            Mock Test-Path { return $true }
            Mock Test-UserGroupMemberOf { return $null }

            function SetGetExchangeADSetupLevel {
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

            function SetGetSetupLogReviewer {
                param(
                    [string]$BuildNumber,
                    [string]$User
                )

                $Script:GetSetupLogReviewer = [PSCustomObject]@{
                    SetupBuildNumber = $BuildNumber
                    User             = $User
                }
            }
        }

        It "Unknown Exchange 2013 Schema Value" {
            SetGetExchangeADSetupLevel -OrgValue 15130 -SchemaValue 15130 -MESOValue 13243
            SetGetSetupLogReviewer "15.00.1473.003" "contoso\user"
            $results = Test-ExchangeADSetupLevel
            Assert-MockCalled -CommandName Test-UserGroupMemberOf -ParameterFilter { $PrepareAdRequired -eq $true -and $PrepareSchemaRequired -eq $true } -Exactly 1
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "Exchange 2013 CU22 Feb19SU"
        }

        It "Exchange 2013 CU23 Ready" {
            SetGetExchangeADSetupLevel -OrgValue 16133 -SchemaValue 15312 -MESOValue 13237
            SetGetSetupLogReviewer "15.00.1497.002" "contoso\user"
            $results = Test-ExchangeADSetupLevel
            Assert-MockCalled -CommandName Test-UserGroupMemberOf -Exactly 0
            $results.Result | Should -Be "Passed"
            $results.Details | Should -Be "Exchange 2013 CU23"
        }

        It "Exchange 2016 CU10 - Last attempt CU10" {
            SetGetExchangeADSetupLevel -OrgValue 16213 -SchemaValue 15332 -MESOValue 13236
            SetGetSetupLogReviewer "15.01.1531.003" "contoso\user"
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Passed"
            $results.Details | Should -Be "Exchange 2016 CU10"
        }

        It "Exchange 2016 CU10 AD - Last attempt CU11" {
            SetGetExchangeADSetupLevel -OrgValue 16213 -SchemaValue 15332 -MESOValue 13236
            SetGetSetupLogReviewer "15.01.1591.010" "contoso\user"
            $results = Test-ExchangeADSetupLevel
            Assert-MockCalled -CommandName Test-UserGroupMemberOf -ParameterFilter { $PrepareAdRequired -eq $true } -Exactly 1
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "Exchange 2016 CU11"
        }

        It "Exchange 2016 CU23" {
            SetGetExchangeADSetupLevel -OrgValue 16223 -SchemaValue 15334 -MESOValue 13243
            SetGetSetupLogReviewer "15.1.2507.6" "contoso\user"
            $results = Test-ExchangeADSetupLevel
            Assert-MockCalled -CommandName Test-UserGroupMemberOf -Exactly 0
            $results.Result | Should -Be "Passed"
            $results.Details | Should -Be "Exchange 2016 CU23"
        }

        It "Exchange 2019 CU8" {
            SetGetExchangeADSetupLevel -OrgValue 16756 -SchemaValue 17002 -MESOValue 13239
            SetGetSetupLogReviewer "15.2.464.5" "contoso\user"
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Passed"
            $results.Details | Should -Be "Exchange 2019 CU3"
        }

        It "Exchange 2019 CU12" {
            SetGetExchangeADSetupLevel -OrgValue 16760 -SchemaValue 17003 -MESOValue 13243
            SetGetSetupLogReviewer "15.2.1118.7" "contoso\user"
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Passed"
            $results.Details | Should -Be "Exchange 2019 CU12"
        }
    }
}
