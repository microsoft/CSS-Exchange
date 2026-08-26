# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Example test pattern for functions that call Exchange cmdlets.

.DESCRIPTION
    Demonstrates:
    - Mocking Exchange-specific cmdlets (Get-ExchangeServer, etc.)
    - Testing with realistic Exchange data structures
    - Handling date/time in tests
    - Testing certificate/expiration scenarios

#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    # Dot-source the script being tested (colocated in same directory)
    . $PSScriptRoot\Test-ServerHealth.ps1

    # Mock Exchange cmdlets (would require Exchange connection in production)
    function Get-ExchangeServer {
        param([string]$Identity)
        return [PSCustomObject]@{
            Name                = $Identity
            AdminDisplayVersion = "Version 15.2 (Build 1118.45)"
            Site                = "Default-First-Site-Name"
        }
    }

    function Get-ExchangeCertificate {
        param([string]$Server)
        Write-Verbose "Getting certificate for server: $Server"
        return @(
            [PSCustomObject]@{
                Thumbprint   = "ABC123"
                Subject      = "CN=mail.contoso.com"
                NotAfter     = (Get-Date).AddDays(365)
                FriendlyName = "Exchange Certificate"
            }
        )
    }
}

Describe "Testing Test-ServerHealth.ps1" {

    Context "Happy Path: Healthy Server" {
        BeforeAll {
            Mock Get-ExchangeServer {
                return [PSCustomObject]@{
                    Name                = "EX01"
                    AdminDisplayVersion = "Version 15.2 (Build 1118.45)"
                }
            }
            Mock Get-ExchangeCertificate {
                return @(
                    [PSCustomObject]@{
                        NotAfter = (Get-Date).AddDays(365)
                    }
                )
            }

            $Script:result = Test-ServerHealth -Identity "EX01"
        }

        It "Should return health status object" {
            $Script:result | Should -Not -BeNullOrEmpty
            $Script:result | Should -BeOfType [PSCustomObject]
        }

        It "Should have required properties" {
            $Script:result.PSObject.Properties.Name | Should -Contain "ServerName"
            $Script:result.PSObject.Properties.Name | Should -Contain "CertificateStatus"
            $Script:result.PSObject.Properties.Name | Should -Contain "DaysUntilExpire"
        }

        It "Should set ServerName from Exchange response" {
            $Script:result.ServerName | Should -Be "EX01"
        }

        It "Should report healthy status for valid certificate" {
            $Script:result.CertificateStatus | Should -Be "Healthy"
            $Script:result.DaysUntilExpire | Should -BeGreaterOrEqual 364
        }
    }

    Context "Error Handling: Server Not Found" {
        It "Should throw when server doesn't exist" {
            Mock Get-ExchangeServer { return $null }
            { Test-ServerHealth -Identity "INVALID" } | Should -Throw "*Exchange server not found*"
        }

        It "Should throw when Get-ExchangeServer fails" {
            Mock Get-ExchangeServer { throw "Access denied" }
            { Test-ServerHealth -Identity "EX01" -ErrorAction Stop } | Should -Throw
        }
    }

    Context "Parameter Validation" {
        It "Should throw when Identity is null" {
            { Test-ServerHealth -Identity $null } | Should -Throw
        }

        It "Should throw when Identity is empty" {
            { Test-ServerHealth -Identity "" } | Should -Throw
        }

        It "Should accept valid server names" {
            Mock Get-ExchangeServer {
                return [PSCustomObject]@{ Name = "EX01" }
            }
            { Test-ServerHealth -Identity "EX01" } | Should -Not -Throw
        }
    }

    Context "Certificate Expiration Scenarios" {
        It "Should report healthy for certificate expiring in 365 days" {
            Mock Get-ExchangeServer {
                return [PSCustomObject]@{ Name = "EX01" }
            }
            Mock Get-Date { return [DateTime]::Parse('2024-01-01T00:00:00') }
            Mock Get-ExchangeCertificate {
                return @(
                    [PSCustomObject]@{
                        NotAfter = [DateTime]::Parse('2024-12-31T00:00:00')
                    }
                )
            }

            $result = Test-ServerHealth -Identity "EX01"
            $result.DaysUntilExpire | Should -Be 365
            $result.CertificateStatus | Should -Be "Healthy"
        }

        It "Should report warning for certificate expiring within 90 days" {
            Mock Get-ExchangeServer {
                return [PSCustomObject]@{ Name = "EX01" }
            }
            Mock Get-Date { return [DateTime]::Parse('2024-01-01T00:00:00') }
            Mock Get-ExchangeCertificate {
                return @(
                    [PSCustomObject]@{
                        NotAfter = [DateTime]::Parse('2024-03-15T00:00:00')
                    }
                )
            }

            $result = Test-ServerHealth -Identity "EX01"
            $result.CertificateStatus | Should -Be "Warning"
        }

        It "Should report critical for certificate expiring within 30 days" {
            Mock Get-ExchangeServer {
                return [PSCustomObject]@{ Name = "EX01" }
            }
            Mock Get-Date { return [DateTime]::Parse('2024-01-01T00:00:00') }
            Mock Get-ExchangeCertificate {
                return @(
                    [PSCustomObject]@{
                        NotAfter = [DateTime]::Parse('2024-01-20T00:00:00')
                    }
                )
            }

            $result = Test-ServerHealth -Identity "EX01"
            $result.CertificateStatus | Should -Be "Critical"
        }
    }

    Context "Timestamp Handling" {
        It "Should set LastChecked to current time" {
            Mock Get-ExchangeServer {
                return [PSCustomObject]@{ Name = "EX01" }
            }
            Mock Get-Date { return [DateTime]::Parse('2024-01-15T10:30:00') }
            Mock Get-ExchangeCertificate {
                return @(
                    [PSCustomObject]@{
                        NotAfter = [DateTime]::Parse('2025-01-15T00:00:00')
                    }
                )
            }

            $result = Test-ServerHealth -Identity "EX01"
            $result.LastChecked | Should -Be ([DateTime]::Parse('2024-01-15T10:30:00'))
        }
    }
}
