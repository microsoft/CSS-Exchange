# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\New-IISConfigurationAction.ps1
}

Describe "Testing New-IISConfigurationAction" {

    Context "Set-WebConfigurationProperty action creates correct Set/Get/Restore tuple" {
        BeforeAll {
            $action = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = @{
                    Filter = "system.webServer/security/requestFiltering"
                    Name   = "allowHighBitCharacters"
                    Value  = "false"
                    PSPath = "IIS:\"
                }
            }
            $Script:result = New-IISConfigurationAction -Action $action
        }

        It "Should return a Set action with the correct cmdlet" {
            $result.Set.Cmdlet | Should -Be "Set-WebConfigurationProperty"
        }

        It "Should return a Get action that uses Get-WebConfigurationProperty" {
            $result.Get.Cmdlet | Should -Be "Get-WebConfigurationProperty"
        }

        It "Should return a Restore action that uses Set-WebConfigurationProperty" {
            $result.Restore.Cmdlet | Should -Be "Set-WebConfigurationProperty"
        }

        It "Should carry Filter, Name, PSPath into the Get parameters" {
            $result.Get.Parameters["Filter"] | Should -Be "system.webServer/security/requestFiltering"
            $result.Get.Parameters["Name"] | Should -Be "allowHighBitCharacters"
            $result.Get.Parameters["PSPath"] | Should -Be "IIS:\"
        }

        It "Should set ErrorAction to Stop on the Get parameters" {
            $result.Get.Parameters["ErrorAction"] | Should -Be "Stop"
        }

        It "Should have a ParametersToString on the Set action" {
            $result.Set.ParametersToString | Should -Not -BeNullOrEmpty
        }
    }

    Context "Validation: missing Cmdlet throws" {
        It "Should throw when Cmdlet is null" {
            $action = [PSCustomObject]@{
                Cmdlet     = $null
                Parameters = @{ Filter = "f" }
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "Invalid Action parameter provided"
        }

        It "Should throw when Cmdlet is empty string" {
            $action = [PSCustomObject]@{
                Cmdlet     = ""
                Parameters = @{ Filter = "f" }
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "Invalid Action parameter provided"
        }
    }

    Context "Validation: missing Parameters throws" {
        It "Should throw when Parameters is null" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = $null
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "Invalid Action parameter provided"
        }
    }

    Context "Validation: Parameters not a hashtable throws" {
        It "Should throw when Parameters is a string" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = "not-a-hashtable"
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "Invalid Action parameter provided"
        }

        It "Should throw when Parameters is an array" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = @("a", "b")
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "Invalid Action parameter provided"
        }
    }

    Context "Validation: missing Filter/Name/Value/PSPath for Set-WebConfigurationProperty throws" {
        It "Should throw when Filter is missing" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = @{ Name = "n"; Value = "v"; PSPath = "IIS:\" }
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "*Invalid cmdlet parameters*"
        }

        It "Should throw when Name is missing" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = @{ Filter = "f"; Value = "v"; PSPath = "IIS:\" }
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "*Invalid cmdlet parameters*"
        }

        It "Should throw when Value is missing" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = @{ Filter = "f"; Name = "n"; PSPath = "IIS:\" }
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "*Invalid cmdlet parameters*"
        }

        It "Should throw when PSPath is missing" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = @{ Filter = "f"; Name = "n"; Value = "v" }
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "*Invalid cmdlet parameters*"
        }
    }

    Context "Location is optional and included when provided" {
        It "Should not include Location in Get params when not provided" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = @{ Filter = "f"; Name = "n"; Value = "v"; PSPath = "IIS:\" }
            }
            $result = New-IISConfigurationAction -Action $action
            $result.Get.Parameters.ContainsKey("Location") | Should -Be $false
        }

        It "Should include Location in Get params when provided" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = @{
                    Filter   = "f"
                    Name     = "n"
                    Value    = "v"
                    PSPath   = "IIS:\"
                    Location = "Default Web Site"
                }
            }
            $result = New-IISConfigurationAction -Action $action
            $result.Get.Parameters["Location"] | Should -Be "Default Web Site"
        }
    }

    Context "ErrorAction and WhatIf are added to parameters" {
        BeforeAll {
            $action = [PSCustomObject]@{
                Cmdlet     = "Set-WebConfigurationProperty"
                Parameters = @{ Filter = "f"; Name = "n"; Value = "v"; PSPath = "IIS:\" }
            }
            $Script:result = New-IISConfigurationAction -Action $action -OverrideErrorAction "SilentlyContinue" -OverrideWhatIf $true
        }

        It "Should set ErrorAction on Set parameters" {
            $result.Set.Parameters["ErrorAction"] | Should -Be "SilentlyContinue"
        }

        It "Should set WhatIf on Set parameters" {
            $result.Set.Parameters["WhatIf"] | Should -Be $true
        }
    }

    Context "Unknown cmdlet type produces null Get/Restore" {
        BeforeAll {
            $action = [PSCustomObject]@{
                Cmdlet     = "Remove-WebConfigurationProperty"
                Parameters = @{ Filter = "f"; Name = "n" }
            }
            $Script:result = New-IISConfigurationAction -Action $action
        }

        It "Should have Set action populated" {
            $result.Set | Should -Not -BeNullOrEmpty
            $result.Set.Cmdlet | Should -Be "Remove-WebConfigurationProperty"
        }

        It "Should have null Get action" {
            $result.Get | Should -BeNullOrEmpty
        }

        It "Should have null Restore action" {
            $result.Restore | Should -BeNullOrEmpty
        }
    }

    # ========================================================================
    # Add-WebConfigurationProperty tests
    # ========================================================================
    Context "Add-WebConfigurationProperty action creates correct Set/Get/Restore tuple" {
        BeforeAll {
            $action = [PSCustomObject]@{
                Cmdlet     = "Add-WebConfigurationProperty"
                RuleName   = "TestRule"
                Parameters = @{
                    Filter = "system.webServer/rewrite/rules"
                    PSPath = "IIS:\"
                    Name   = "."
                    Value  = @{ name = "TestRule"; patternSyntax = "Regular Expressions" }
                }
            }
            $Script:result = New-IISConfigurationAction -Action $action
        }

        It "Should return a Set action with Add-WebConfigurationProperty cmdlet" {
            $result.Set.Cmdlet | Should -Be "Add-WebConfigurationProperty"
        }

        It "Should return a Get action using Get-WebConfiguration" {
            $result.Get.Cmdlet | Should -Be "Get-WebConfiguration"
        }

        It "Should return a Restore action using Clear-WebConfiguration" {
            $result.Restore.Cmdlet | Should -Be "Clear-WebConfiguration"
        }

        It "Should build a targeted Clear filter with rule[@name] by default" {
            $result.Restore.Parameters["Filter"] | Should -Be "system.webServer/rewrite/rules/rule[@name='TestRule']"
        }

        It "Should use the targeted Clear filter in the Get action" {
            $result.Get.Parameters["Filter"] | Should -Be "system.webServer/rewrite/rules/rule[@name='TestRule']"
        }

        It "Should set ErrorAction to Stop on the Restore parameters" {
            $result.Restore.Parameters["ErrorAction"] | Should -Be "Stop"
        }

        It "Should set ErrorAction to SilentlyContinue on the Get parameters" {
            $result.Get.Parameters["ErrorAction"] | Should -Be "SilentlyContinue"
        }
    }

    Context "Add-WebConfigurationProperty with ElementName overrides default element type" {
        BeforeAll {
            $action = [PSCustomObject]@{
                Cmdlet      = "Add-WebConfigurationProperty"
                RuleName    = "MyPreCondition"
                ElementName = "preCondition"
                Parameters  = @{
                    Filter = "system.webServer/rewrite/outboundRules/preConditions"
                    PSPath = "IIS:\"
                    Name   = "."
                    Value  = @{ name = "MyPreCondition"; logicalGrouping = "MatchAll" }
                }
            }
            $Script:result = New-IISConfigurationAction -Action $action
        }

        It "Should build Clear filter using preCondition instead of rule" {
            $result.Restore.Parameters["Filter"] | Should -Be "system.webServer/rewrite/outboundRules/preConditions/preCondition[@name='MyPreCondition']"
        }

        It "Should use the same preCondition filter in Get action" {
            $result.Get.Parameters["Filter"] | Should -Be "system.webServer/rewrite/outboundRules/preConditions/preCondition[@name='MyPreCondition']"
        }
    }

    Context "Add-WebConfigurationProperty without RuleName produces null Get/Restore" {
        It "Should have null Get and Restore when RuleName is not provided" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Add-WebConfigurationProperty"
                Parameters = @{ Filter = "system.webServer/rewrite/rules"; PSPath = "IIS:\"; Name = "." }
            }
            $result = New-IISConfigurationAction -Action $action
            $result.Set.Cmdlet | Should -Be "Add-WebConfigurationProperty"
            $result.Get | Should -BeNullOrEmpty
            $result.Restore | Should -BeNullOrEmpty
        }

        It "Should have null Get and Restore when RuleName is empty string" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Add-WebConfigurationProperty"
                RuleName   = ""
                Parameters = @{ Filter = "system.webServer/rewrite/rules"; PSPath = "IIS:\"; Name = "." }
            }
            $result = New-IISConfigurationAction -Action $action
            $result.Set.Cmdlet | Should -Be "Add-WebConfigurationProperty"
            $result.Get | Should -BeNullOrEmpty
            $result.Restore | Should -BeNullOrEmpty
        }
    }

    Context "Validation: Add-WebConfigurationProperty missing Filter or PSPath throws" {
        It "Should throw when Filter is missing" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Add-WebConfigurationProperty"
                RuleName   = "TestRule"
                Parameters = @{ PSPath = "IIS:\" }
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "*Invalid cmdlet parameters*Add-WebConfigurationProperty*"
        }

        It "Should throw when PSPath is missing" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Add-WebConfigurationProperty"
                RuleName   = "TestRule"
                Parameters = @{ Filter = "system.webServer/rewrite/rules" }
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "*Invalid cmdlet parameters*Add-WebConfigurationProperty*"
        }
    }

    Context "Add-WebConfigurationProperty includes Location when provided" {
        It "Should include Location in Restore and Get parameters" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Add-WebConfigurationProperty"
                RuleName   = "TestRule"
                Parameters = @{
                    Filter   = "system.webServer/rewrite/rules"
                    PSPath   = "IIS:\"
                    Name     = "."
                    Location = "Default Web Site"
                }
            }
            $result = New-IISConfigurationAction -Action $action
            $result.Restore.Parameters["Location"] | Should -Be "Default Web Site"
            $result.Get.Parameters["Location"] | Should -Be "Default Web Site"
        }
    }

    # ========================================================================
    # Clear-WebConfiguration tests
    # ========================================================================
    Context "Clear-WebConfiguration action creates correct Set/Get/Restore tuple" {
        BeforeAll {
            $action = [PSCustomObject]@{
                Cmdlet     = "Clear-WebConfiguration"
                Parameters = @{
                    Filter = "system.webServer/rewrite/rules/rule[@name='OldRule']"
                    PSPath = "IIS:\"
                }
            }
            $Script:result = New-IISConfigurationAction -Action $action
        }

        It "Should return a Set action with Clear-WebConfiguration cmdlet" {
            $result.Set.Cmdlet | Should -Be "Clear-WebConfiguration"
        }

        It "Should return a Get action using Get-WebConfiguration" {
            $result.Get.Cmdlet | Should -Be "Get-WebConfiguration"
        }

        It "Should return a Restore action using Add-WebConfigurationProperty" {
            $result.Restore.Cmdlet | Should -Be "Add-WebConfigurationProperty"
        }

        It "Should pass Filter through to Get and Restore" {
            $result.Get.Parameters["Filter"] | Should -Be "system.webServer/rewrite/rules/rule[@name='OldRule']"
            $result.Restore.Parameters["Filter"] | Should -Be "system.webServer/rewrite/rules/rule[@name='OldRule']"
        }

        It "Should set ErrorAction to SilentlyContinue on Get parameters" {
            $result.Get.Parameters["ErrorAction"] | Should -Be "SilentlyContinue"
        }
    }

    Context "Validation: Clear-WebConfiguration missing Filter throws" {
        It "Should throw when Filter is missing" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Clear-WebConfiguration"
                Parameters = @{ PSPath = "IIS:\" }
            }
            { New-IISConfigurationAction -Action $action } | Should -Throw "*Invalid cmdlet parameters*Clear-WebConfiguration*"
        }
    }

    Context "Clear-WebConfiguration includes Location and PSPath when provided" {
        It "Should include both in Get and Restore parameters" {
            $action = [PSCustomObject]@{
                Cmdlet     = "Clear-WebConfiguration"
                Parameters = @{
                    Filter   = "system.webServer/rewrite/rules/rule[@name='R']"
                    PSPath   = "IIS:\"
                    Location = "Default Web Site"
                }
            }
            $result = New-IISConfigurationAction -Action $action
            $result.Get.Parameters["PSPath"] | Should -Be "IIS:\"
            $result.Get.Parameters["Location"] | Should -Be "Default Web Site"
            $result.Restore.Parameters["PSPath"] | Should -Be "IIS:\"
            $result.Restore.Parameters["Location"] | Should -Be "Default Web Site"
        }
    }
}
