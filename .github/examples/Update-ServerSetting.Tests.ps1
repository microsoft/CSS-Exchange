# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Example test pattern for state-changing functions.

.DESCRIPTION
    Demonstrates:
    - Testing parameter validation with multiple scenarios
    - Testing state changes and results
    - Error path testing
    - Mocking side effects
    - Testing business logic (validation rules)

#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    # Dot-source the script being tested (colocated in same directory)
    . $PSScriptRoot\Update-ServerSetting.ps1

    # Mock external functions if needed
    function Write-ConfigAuditLog {
        param([string]$Message)
        Write-Verbose "Audit: $Message"
    }
}

Describe "Testing Update-ServerSetting.ps1" {

    Context "Happy Path: Valid Configuration Update" {
        It "Should update MaxMemory setting" {
            $result = Update-ServerSetting -ConfigKey "MaxMemory" -ConfigValue "32GB"

            $result | Should -Not -BeNullOrEmpty
            $result.ConfigKey | Should -Be "MaxMemory"
            $result.NewValue | Should -Be "32GB"
            $result.Updated | Should -Be $true
        }

        It "Should update MaxCPU setting" {
            $result = Update-ServerSetting -ConfigKey "MaxCPU" -ConfigValue "8"
            $result.ConfigKey | Should -Be "MaxCPU"
        }

        It "Should update HealthCheckInterval setting" {
            $result = Update-ServerSetting -ConfigKey "HealthCheckInterval" -ConfigValue "300"
            $result.ConfigKey | Should -Be "HealthCheckInterval"
        }

        It "Should update LogRetention setting" {
            $result = Update-ServerSetting -ConfigKey "LogRetention" -ConfigValue "90"
            $result.ConfigKey | Should -Be "LogRetention"
        }
    }

    Context "Parameter Validation: ConfigKey" {
        It "Should throw when ConfigKey is null" {
            { Update-ServerSetting -ConfigKey $null -ConfigValue "value" } | Should -Throw
        }

        It "Should throw when ConfigKey is empty" {
            { Update-ServerSetting -ConfigKey "" -ConfigValue "value" } | Should -Throw
        }

        It "Should throw when ConfigKey is invalid" {
            { Update-ServerSetting -ConfigKey "InvalidKey" -ConfigValue "32GB" } | Should -Throw "*Invalid configuration key*"
        }

        It "Should accept valid configuration keys" {
            $validInputs = @{
                "MaxMemory"           = "32GB"
                "MaxCPU"              = "8"
                "HealthCheckInterval" = "300"
                "LogRetention"        = "90"
            }
            foreach ($key in $validInputs.Keys) {
                { Update-ServerSetting -ConfigKey $key -ConfigValue $validInputs[$key] } | Should -Not -Throw
            }
        }
    }

    Context "Parameter Validation: ConfigValue" {
        It "Should throw when ConfigValue is null" {
            { Update-ServerSetting -ConfigKey "MaxMemory" -ConfigValue $null } | Should -Throw
        }

        It "Should throw when ConfigValue is empty" {
            { Update-ServerSetting -ConfigKey "MaxMemory" -ConfigValue "" } | Should -Throw
        }
    }

    Context "Business Logic: Memory Format Validation" {
        It "Should accept valid memory format (e.g., 32GB)" {
            $result = Update-ServerSetting -ConfigKey "MaxMemory" -ConfigValue "32GB"
            $result.NewValue | Should -Be "32GB"
        }

        It "Should accept various valid memory values" {
            @("4GB", "8GB", "16GB", "64GB") | ForEach-Object {
                { Update-ServerSetting -ConfigKey "MaxMemory" -ConfigValue $_ } | Should -Not -Throw
            }
        }

        It "Should throw when memory format is invalid (missing GB)" {
            { Update-ServerSetting -ConfigKey "MaxMemory" -ConfigValue "32" } | Should -Throw "*Invalid memory format*"
        }

        It "Should throw when memory format is invalid (wrong unit)" {
            { Update-ServerSetting -ConfigKey "MaxMemory" -ConfigValue "32MB" } | Should -Throw "*Invalid memory format*"
        }

        It "Should throw when memory format has letters in number" {
            { Update-ServerSetting -ConfigKey "MaxMemory" -ConfigValue "32xGB" } | Should -Throw "*Invalid memory format*"
        }
    }

    Context "Output Validation" {
        BeforeAll {
            Mock Get-Date { return [DateTime]::Parse('2024-06-15T12:00:00') }
            $Script:result = Update-ServerSetting -ConfigKey "MaxMemory" -ConfigValue "32GB"
        }

        It "Should return PSCustomObject" {
            $Script:result | Should -BeOfType [PSCustomObject]
        }

        It "Should have required properties" {
            $Script:result.PSObject.Properties.Name | Should -Contain "ConfigKey"
            $Script:result.PSObject.Properties.Name | Should -Contain "NewValue"
            $Script:result.PSObject.Properties.Name | Should -Contain "Updated"
            $Script:result.PSObject.Properties.Name | Should -Contain "Timestamp"
        }

        It "Should have correct property types" {
            $Script:result.Updated | Should -BeOfType [bool]
            $Script:result.Timestamp | Should -BeOfType [DateTime]
        }

        It "Should set Timestamp to mocked time" {
            $Script:result.Timestamp | Should -Be ([DateTime]::Parse('2024-06-15T12:00:00'))
        }
    }

    Context "Edge Cases" {
        It "Should handle ConfigKey with mixed case" {
            $result = Update-ServerSetting -ConfigKey "mAxMeMoRy" -ConfigValue "32GB"
            $result | Should -Not -BeNullOrEmpty
            $result.Updated | Should -Be $true
        }

        It "Should handle ConfigValue with special characters if valid" {
            # If the function allows it
            { Update-ServerSetting -ConfigKey "LogRetention" -ConfigValue "90-days" } | Should -Not -Throw
        }
    }

    Context "Error Scenarios" {
        It "Should provide helpful error message for invalid key" {
            $errorAction = $null
            try {
                Update-ServerSetting -ConfigKey "BadKey" -ConfigValue "value" -ErrorAction Stop
            } catch {
                $errorAction = $_
            }

            $errorAction | Should -Not -BeNullOrEmpty
            $errorAction.Exception.Message | Should -BeLike "*Invalid configuration key*"
        }
    }
}
