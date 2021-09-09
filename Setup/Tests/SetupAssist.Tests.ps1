# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
BeforeAll {
    . $PSScriptRoot\..\..\.build\BuildFunctions\Get-ExpandedScriptContent.ps1
    $Script:parentPath = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), "SetupAssist")
    $Script:PesterExtract = "# Extract for Pester Testing"
}

Describe "Testing SetupAssist" {

    BeforeAll {

        #Load the functions
        $internalFunctions = New-Object 'System.Collections.Generic.List[string]'
        $scriptContent = Get-ExpandedScriptContent -File "$Script:parentPath\Checks\Domain\Test-ExchangeADSetupLevel.ps1"
        $startIndex = $scriptContent.Trim().IndexOf($Script:PesterExtract)
        for ($i = $startIndex + 1; $i -lt $scriptContent.Count; $i++) {
            if ($scriptContent[$i].Trim().Contains($Script:PesterExtract)) {
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
            Mock TestPrepareAD {}

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

        It "Exchange 2019 CU9" {
            SetGetExchangeADSetupLevel -OrgValue 16757 -SchemaValue 17002 -MESOValue 13240
            $results = Test-ExchangeADSetupLevel
            $results.Result | Should -Be "Failed"
            $results.Details | Should -Be "At Exchange 2019 CU9"
        }
    }
}
