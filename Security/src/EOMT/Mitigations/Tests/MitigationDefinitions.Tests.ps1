# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\MitigationDefinitions.ps1
}

Describe "Testing MitigationDefinitions" {

    Context "All definitions in MitigationDefinitionMap are valid" {

        BeforeAll {
            $Script:allCVEs = @($script:MitigationDefinitionMap.Keys | Sort-Object)
        }

        It "Should have at least one CVE definition registered" {
            $script:MitigationDefinitionMap.Count | Should -BeGreaterThan 0
        }

        It "Should have unique CVE identifiers" {
            $allCVEs.Count | Should -Be @($allCVEs | Select-Object -Unique).Count
        }

        It "Should have unique Priority values across all definitions" {
            $priorities = $allCVEs | ForEach-Object {
                $def = & $script:MitigationDefinitionMap[$_]
                $def.Priority
            }
            $priorities.Count | Should -Be @($priorities | Select-Object -Unique).Count
        }
    }

    Context "Each CVE definition returns valid contract properties" {

        It "All definitions have a non-empty Id matching their map key" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $def.Id | Should -Not -BeNullOrEmpty -Because "$key must have an Id"
                $def.Id | Should -Be $key -Because "$key Id must match its map key"
            }
        }

        It "All definitions have a numeric Priority" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $def.Priority | Should -Not -BeNullOrEmpty -Because "$key must have a Priority"
                $def.Priority -is [int] | Should -Be $true -Because "$key Priority must be an integer"
            }
        }

        It "All definitions have a non-empty Description" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $def.Description | Should -Not -BeNullOrEmpty -Because "$key must have a Description"
            }
        }

        It "All definitions have a boolean RequiresUrlRewrite" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $def.RequiresUrlRewrite -is [bool] | Should -Be $true -Because "$key RequiresUrlRewrite must be a boolean"
            }
        }

        It "All definitions have a non-empty SiteName" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $def.SiteName | Should -Not -BeNullOrEmpty -Because "$key must have a SiteName"
            }
        }

        It "All definitions have a TestVulnerable ScriptBlock" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $def.TestVulnerable | Should -Not -BeNullOrEmpty -Because "$key must have TestVulnerable"
                $def.TestVulnerable -is [ScriptBlock] | Should -Be $true -Because "$key TestVulnerable must be a ScriptBlock"
            }
        }

        It "All definitions have a GetActions ScriptBlock" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $def.GetActions | Should -Not -BeNullOrEmpty -Because "$key must have GetActions"
                $def.GetActions -is [ScriptBlock] | Should -Be $true -Because "$key GetActions must be a ScriptBlock"
            }
        }
    }

    Context "Each CVE definition GetActions returns valid action objects" {

        It "All definitions return at least one action from GetActions" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $actions = @(& $def.GetActions)
                $actions.Count | Should -BeGreaterThan 0 -Because "$key GetActions must return at least one action"
            }
        }

        It "All actions have a non-empty Cmdlet property" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $actions = @(& $def.GetActions)
                foreach ($action in $actions) {
                    $action.Cmdlet | Should -Not -BeNullOrEmpty -Because "every action in $key must have a Cmdlet"
                }
            }
        }

        It "All actions have a Parameters hashtable" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $actions = @(& $def.GetActions)
                foreach ($action in $actions) {
                    $action.Parameters | Should -Not -BeNullOrEmpty -Because "every action in $key must have Parameters"
                    $action.Parameters -is [hashtable] | Should -Be $true -Because "Parameters in $key must be a hashtable"
                }
            }
        }

        It "All actions have a Filter in Parameters" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $actions = @(& $def.GetActions)
                foreach ($action in $actions) {
                    $action.Parameters["Filter"] | Should -Not -BeNullOrEmpty -Because "every action in $key must have a Filter parameter"
                }
            }
        }

        It "All actions use only supported Cmdlet types" {
            $supportedCmdlets = @(
                "Set-WebConfigurationProperty",
                "Add-WebConfigurationProperty",
                "Clear-WebConfiguration"
            )
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $actions = @(& $def.GetActions)
                foreach ($action in $actions) {
                    $action.Cmdlet | Should -BeIn $supportedCmdlets -Because "action Cmdlet in $key must be a supported IIS management cmdlet"
                }
            }
        }

        It "Add actions with RuleName have a non-empty RuleName value" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $actions = @(& $def.GetActions)
                foreach ($action in $actions) {
                    if ($action.Cmdlet -eq "Add-WebConfigurationProperty" -and $null -ne $action.RuleName) {
                        $action.RuleName | Should -Not -BeNullOrEmpty -Because "Add action with RuleName in $key must have a non-empty value"
                    }
                }
            }
        }

        It "Set-WebConfigurationProperty actions have required Name and PSPath parameters" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $actions = @(& $def.GetActions)
                foreach ($action in $actions) {
                    if ($action.Cmdlet -eq "Set-WebConfigurationProperty") {
                        $action.Parameters["Name"] | Should -Not -BeNullOrEmpty -Because "Set action in $key must have a Name parameter"
                        $action.Parameters["PSPath"] | Should -Not -BeNullOrEmpty -Because "Set action in $key must have a PSPath parameter"
                    }
                }
            }
        }

        It "Add-WebConfigurationProperty actions have required PSPath parameter" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $actions = @(& $def.GetActions)
                foreach ($action in $actions) {
                    if ($action.Cmdlet -eq "Add-WebConfigurationProperty") {
                        $action.Parameters["PSPath"] | Should -Not -BeNullOrEmpty -Because "Add action in $key must have a PSPath parameter"
                    }
                }
            }
        }
    }

    Context "Get-MitigationDefinition function" {

        It "Should return the correct definition for each registered CVE" {
            foreach ($cve in $script:MitigationDefinitionMap.Keys) {
                $result = Get-MitigationDefinition -CVE $cve
                $result.Id | Should -Be $cve
            }
        }

        It "Should throw for unknown CVE identifier" {
            { Get-MitigationDefinition -CVE "CVE-9999-99999" } | Should -Throw "*Unknown CVE identifier*"
        }

        It "Should include available CVEs in error message for unknown identifier" {
            try {
                Get-MitigationDefinition -CVE "CVE-9999-99999"
            } catch {
                $_.Exception.Message | Should -BeLike "*Available:*"
            }
        }
    }

    Context "TestVulnerable expected names consistency with GetActions" {

        It "Definitions with expectedRuleNames must match GetActions rule-type Add RuleNames" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $scriptText = $def.TestVulnerable.ToString()
                $match = [regex]::Match($scriptText, '\$expectedRuleNames\s*=\s*@\(([^)]+)\)')

                if (-not $match.Success) { continue }

                $parsed = $match.Groups[1].Value -split "," | ForEach-Object { $_.Trim().Trim("'").Trim('"') } | Where-Object { $_ }
                $parsedNames = @($parsed) | Sort-Object

                $actions = @(& $def.GetActions) | Where-Object { $_.Cmdlet -eq "Add-WebConfigurationProperty" -and $_.RuleName -and -not $_.ElementName }
                $getActionsRuleNames = @($actions | ForEach-Object { $_.RuleName }) | Sort-Object

                $parsedNames | Should -Be $getActionsRuleNames -Because "$key expectedRuleNames must match GetActions rule-type RuleNames"
            }
        }

        It "Definitions with expectedPreConditionNames must match GetActions preCondition-type Add RuleNames" {
            foreach ($key in $script:MitigationDefinitionMap.Keys) {
                $def = & $script:MitigationDefinitionMap[$key]
                $scriptText = $def.TestVulnerable.ToString()
                $match = [regex]::Match($scriptText, '\$expectedPreConditionNames\s*=\s*@\(([^)]+)\)')

                if (-not $match.Success) { continue }

                $parsed = $match.Groups[1].Value -split "," | ForEach-Object { $_.Trim().Trim("'").Trim('"') } | Where-Object { $_ }
                $parsedNames = @($parsed) | Sort-Object

                $actions = @(& $def.GetActions) | Where-Object { $_.Cmdlet -eq "Add-WebConfigurationProperty" -and $_.RuleName -and $_.ElementName -eq "preCondition" }
                $getActionsPreConditionNames = @($actions | ForEach-Object { $_.RuleName }) | Sort-Object

                $parsedNames | Should -Be $getActionsPreConditionNames -Because "$key expectedPreConditionNames must match GetActions preCondition-type RuleNames"
            }
        }
    }
}
