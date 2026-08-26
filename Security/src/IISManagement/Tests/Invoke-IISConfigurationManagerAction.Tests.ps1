# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Invoke-IISConfigurationManagerAction.ps1

    # Stub external functions referenced by the script
    function Invoke-ScriptBlockHandler {
        [CmdletBinding()]
        param(
            [string]$ComputerName,
            [object]$ArgumentList,
            [ScriptBlock]$ScriptBlock
        )
    }

    function Write-VerboseErrorInformation {
        [CmdletBinding()]
        param([object]$CurrentError)
    }

    function Get-ParameterString {
        [CmdletBinding()]
        [OutputType([System.String])]
        param([hashtable]$InputObject)
        return ""
    }
}

Describe "Testing Invoke-IISConfigurationManagerAction" {

    BeforeEach {
        Mock Write-Progress { }
        Mock Write-Verbose { }
        Mock Write-Warning { }
        Mock Write-Host { }
    }

    Context "Iterates over all servers in input" {

        It "Should invoke the script block handler for each server" {
            Mock Invoke-ScriptBlockHandler {
                return [PSCustomObject]@{
                    SuccessfulExecution = $true
                    ErrorContext        = @()
                    RestoreActions      = @()
                }
            }

            $servers = @(
                [PSCustomObject]@{ ServerName = "Server1"; Actions = @(); BackupFileName = "test" },
                [PSCustomObject]@{ ServerName = "Server2"; Actions = @(); BackupFileName = "test" },
                [PSCustomObject]@{ ServerName = "Server3"; Actions = @(); BackupFileName = "test" }
            )

            $servers | Invoke-IISConfigurationManagerAction

            Should -Invoke Invoke-ScriptBlockHandler -Times 3
        }
    }

    Context "Failed server (null result) is added to failedServers" {

        It "Should log a warning about the failed server" {
            Mock Invoke-ScriptBlockHandler { return $null }
            Mock Write-VerboseErrorInformation { }

            $servers = @(
                [PSCustomObject]@{ ServerName = "FailServer"; Actions = @(); BackupFileName = "test" }
            )

            $servers | Invoke-IISConfigurationManagerAction

            Should -Invoke Write-Warning -Times 1 -ParameterFilter {
                $Message -like "*Failed to execute request*FailServer*NULL Result: True"
            }
        }

        It "Should not log the server as successful" {
            Mock Invoke-ScriptBlockHandler { return $null }
            Mock Write-VerboseErrorInformation { }

            $servers = @(
                [PSCustomObject]@{ ServerName = "FailServer"; Actions = @(); BackupFileName = "test" }
            )

            $servers | Invoke-IISConfigurationManagerAction

            Should -Not -Invoke Write-Host -ParameterFilter {
                $Object -like "*FailServer*successful*"
            }
        }
    }

    Context "Failed server (error context) is logged" {

        It "Should warn about the failed server and log errors" {
            Mock Invoke-ScriptBlockHandler {
                return [PSCustomObject]@{
                    SuccessfulExecution = $false
                    ErrorContext        = @("Error1", "Error2")
                    RestoreActions      = @()
                }
            }
            Mock Write-VerboseErrorInformation { }

            $servers = @(
                [PSCustomObject]@{ ServerName = "ErrorServer"; Actions = @(); BackupFileName = "test" }
            )

            $servers | Invoke-IISConfigurationManagerAction

            Should -Invoke Write-Warning -ParameterFilter {
                $Message -like "*ErrorServer*"
            }
            Should -Invoke Write-VerboseErrorInformation -Times 2
        }
    }

    Context "Successful server is added to successfulServers" {

        It "Should log the successful server via Write-Host" {
            Mock Invoke-ScriptBlockHandler {
                return [PSCustomObject]@{
                    SuccessfulExecution = $true
                    ErrorContext        = @()
                    RestoreActions      = @()
                }
            }

            $servers = @(
                [PSCustomObject]@{ ServerName = "GoodServer"; Actions = @(); BackupFileName = "test" }
            )

            $servers | Invoke-IISConfigurationManagerAction

            Should -Invoke Write-Host -Times 1 -ParameterFilter {
                $Object -like "*was successful*GoodServer*"
            }
        }

        It "Should not warn about the successful server" {
            Mock Invoke-ScriptBlockHandler {
                return [PSCustomObject]@{
                    SuccessfulExecution = $true
                    ErrorContext        = @()
                    RestoreActions      = @()
                }
            }

            $servers = @(
                [PSCustomObject]@{ ServerName = "GoodServer"; Actions = @(); BackupFileName = "test" }
            )

            $servers | Invoke-IISConfigurationManagerAction

            Should -Not -Invoke Write-Warning -ParameterFilter {
                $Message -like "*GoodServer*"
            }
        }
    }

    Context "Mixed success and failure across servers" {

        It "Should process all servers and report success/failure correctly" {
            $Script:callIdx = 0
            Mock Invoke-ScriptBlockHandler {
                $Script:callIdx++
                if ($Script:callIdx -eq 2) {
                    return $null
                }
                return [PSCustomObject]@{
                    SuccessfulExecution = $true
                    ErrorContext        = @()
                    RestoreActions      = @()
                }
            }

            $servers = @(
                [PSCustomObject]@{ ServerName = "GoodServer1"; Actions = @(); BackupFileName = "t" },
                [PSCustomObject]@{ ServerName = "BadServer"; Actions = @(); BackupFileName = "t" },
                [PSCustomObject]@{ ServerName = "GoodServer2"; Actions = @(); BackupFileName = "t" }
            )

            $servers | Invoke-IISConfigurationManagerAction

            Should -Invoke Invoke-ScriptBlockHandler -Times 3
            Should -Invoke Write-Warning -ParameterFilter {
                $Message -like "*Failed to execute request*BadServer*"
            }
            Should -Invoke Write-Host -ParameterFilter {
                $Object -like "*was successful*GoodServer*"
            }
        }
    }
}
