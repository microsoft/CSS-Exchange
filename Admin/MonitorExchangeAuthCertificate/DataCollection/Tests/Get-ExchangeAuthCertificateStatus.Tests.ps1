# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Get-ExchangeAuthCertificateStatus.ps1

    function Invoke-CatchActionError {
        param()
    }

    function New-AuthCertificateUnitTestObject {
        param(
            [string]$Thumbprint = $null,
            [bool]$IsExpired = $false
        )

        return [PSCustomObject]@{
            Subject    = "CN=Microsoft Exchange Server Auth Certificate"
            Issuer     = "CN=Microsoft Exchange Server Auth Certificate"
            Thumbprint = $Thumbprint
            NotBefore  = [DateTime]::Parse('2023-01-01T00:00:00')
            NotAfter   = if ($IsExpired) { [DateTime]::Parse('2020-01-01T00:00:00') } else { [DateTime]::Parse('2029-01-01T00:00:00') }
        }
    }

    function Get-Date {
        param()

        return [DateTime]::Parse('2023-01-01T00:00:00')
    }

    function Get-ExchangeServer {
        param()
        return Import-Clixml $Script:parentPath\Tests\Data\GetExchangeServer.xml
    }

    function Get-ExchangeServerCertificate {
        param(
            [string]$Thumbprint = $null,
            [string]$Server = $null
        )

        if ($null -ne $Thumbprint) {
            return Import-Clixml $Script:parentPath\Tests\Data\GetExchangeCertificate.xml | Where-Object { $_.Thumbprint -eq $Thumbprint }
        }
        return Import-Clixml $Script:parentPath\Tests\Data\GetExchangeCertificate.xml
    }

    function Get-AuthConfig {
        param()
    }

    function Get-HybridConfiguration {
        param()
    }
}

Describe "Testing Get-ExchangeAuthCertificateStatus.ps1" {

    Context "Get-ExchangeAuthCertificateStatus Without Any Parameter" {
        BeforeAll {
            Mock Get-AuthConfig { return Import-Clixml $Script:parentPath\Tests\Data\GetAuthConfig.xml }
            $Script:results = Get-ExchangeAuthCertificateStatus
        }

        It "Should Return That The Auth Certificate Configuration Is Valid And No Action Is Required" {
            $results | Should -Not -BeNullOrEmpty
            $results.CurrentAuthCertificateLifetimeInDays | Should -BeGreaterThan 1800
            $results.ReplaceRequired | Should -Be $false
            $results.ConfigureNextAuthRequired | Should -Be $false
            $results.NumberOfUnreachableServers | Should -Be 0
            $results.HybridSetupDetected | Should -Be $false
            $results.StopProcessingDueToHybrid | Should -Be $false
            $results.MultipleExchangeADSites | Should -Be $false
        }
    }

    Context "Get-ExchangeAuthCertificateStatus With Hybrid Setup" {
        BeforeAll {
            Mock Get-AuthConfig { return Import-Clixml $Script:parentPath\Tests\Data\GetAuthConfig.xml }
            Mock Get-HybridConfiguration { return "Hybrid Configuration Detected" }
            Mock Get-Date { return [DateTime]::Parse('2028-02-01T00:00:00') }
        }

        It "Should Return That The Auth Certificate Configuration Is Invalid And Replace Action Is Required But Was Not Done Due To Hybrid Setup" {
            $Script:results = Get-ExchangeAuthCertificateStatus
            $results | Should -Not -BeNullOrEmpty
            $results.CurrentAuthCertificateLifetimeInDays | Should -BeLessThan 0
            $results.ReplaceRequired | Should -Be $true
            $results.ConfigureNextAuthRequired | Should -Be $false
            $results.NumberOfUnreachableServers | Should -Be 0
            $results.HybridSetupDetected | Should -Be $true
            $results.StopProcessingDueToHybrid | Should -Be $true
            $results.MultipleExchangeADSites | Should -Be $false
        }

        It "Should Return That The Auth Certificate Configuration Is Invalid And Replace Action Is Required And Hybrid Setup Will Be Ignored" {
            $Script:results = Get-ExchangeAuthCertificateStatus -IgnoreHybridSetup $true
            $results | Should -Not -BeNullOrEmpty
            $results.CurrentAuthCertificateLifetimeInDays | Should -BeLessThan 0
            $results.ReplaceRequired | Should -Be $true
            $results.ConfigureNextAuthRequired | Should -Be $false
            $results.NumberOfUnreachableServers | Should -Be 0
            $results.HybridSetupDetected | Should -Be $true
            $results.StopProcessingDueToHybrid | Should -Be $false
            $results.MultipleExchangeADSites | Should -Be $false
        }
    }

    Context "Get-ExchangeAuthCertificateStatus With Unreachable Servers" {
        BeforeAll {
            Mock Get-AuthConfig { return Import-Clixml $Script:parentPath\Tests\Data\GetAuthConfig.xml }
            Mock Get-Date { return [DateTime]::Parse('2028-02-01T00:00:00') }
            Mock Get-ExchangeServerCertificate {
                throw "Some other exception than InvalidOperationException"
            } -ParameterFilter {
                $Server -eq "e2k16-2.contoso.lab"
            }
        }

        It "Replace Required Returns False as 1 Server Is Unreachable" {
            $Script:results = Get-ExchangeAuthCertificateStatus
            $results | Should -Not -BeNullOrEmpty
            $results.ConfigureNextAuthRequired | Should -Be $false
            $results.NumberOfUnreachableServers | Should -Be 1
            $results.UnreachableServersList | Should -Be "e2k16-2.contoso.lab"
        }

        It "Should Return That The Auth Certificate Configuration Is Invalid And Replace Action Is Required As Unreachable Servers Will Be Skipped" {
            $Script:results = Get-ExchangeAuthCertificateStatus -IgnoreUnreachableServers $true
            $results | Should -Not -BeNullOrEmpty
            $results.CurrentAuthCertificateLifetimeInDays | Should -BeLessThan 0
            $results.ReplaceRequired | Should -Be $true
            $results.ConfigureNextAuthRequired | Should -Be $false
            $results.NumberOfUnreachableServers | Should -Be 1
            $results.UnreachableServersList | Should -Be "e2k16-2.contoso.lab"
        }
    }

    Context "Scenario #1: Current Auth Certificate has expired and no next Auth Certificate defined or the next Auth Certificate has expired" {
        BeforeAll {
            Mock Get-AuthConfig { return Import-Clixml $Script:parentPath\Tests\Data\GetAuthConfig.xml }
            Mock Get-Date { return [DateTime]::Parse('2028-12-20T00:00:00') }
            $Script:results = Get-ExchangeAuthCertificateStatus
        }

        It "Should Return That The Active Auth Certificate Must To Be Replaced" {
            $results | Should -Not -BeNullOrEmpty
            $results.CurrentAuthCertificateLifetimeInDays | Should -BeLessThan 0
            $results.ReplaceRequired | Should -Be $true
            $results.ConfigureNextAuthRequired | Should -Be $false
        }
    }

    Context "Scenario #2: Current Auth Certificate is valid but no next Auth Certificate defined or next Auth Certificate will expire in < 120 days" {
        BeforeAll {
            Mock Get-AuthConfig { return Import-Clixml $Script:parentPath\Tests\Data\GetAuthConfig.xml }
            Mock Get-Date { return [DateTime]::Parse('2027-12-20T00:00:00') }
            $Script:results = Get-ExchangeAuthCertificateStatus
        }

        It "Should Return That The Next Auth Certificate Must To Be Configured To Replace The Active Auth Certificate Once Expired" {
            $results | Should -Not -BeNullOrEmpty
            $results.CurrentAuthCertificateLifetimeInDays | Should -BeGreaterOrEqual 0
            $results.CurrentAuthCertificateLifetimeInDays | Should -BeLessOrEqual 60
            $results.ReplaceRequired | Should -Be $false
            $results.ConfigureNextAuthRequired | Should -Be $true
        }
    }

    Context "Scenario #3: Unlikely but possible - current Auth Certificate has expired and next Auth Certificate is set but not yet active" {
        BeforeAll {
            Mock Get-AuthConfig { return Import-Clixml $Script:parentPath\Tests\Data\GetAuthConfig.xml }
            Mock Get-Date { return [DateTime]::Parse('2028-12-20T00:00:00') }
            Mock Get-ExchangeServerCertificate {
                return New-AuthCertificateUnitTestObject -Thumbprint "BC6BF924D6EF046E64F8D1987DC1D7D2F4C0042A"
            } -ParameterFilter {
                $Thumbprint -eq "BC6BF924D6EF046E64F8D1987DC1D7D2F4C0042A"
            }
            $Script:results = Get-ExchangeAuthCertificateStatus
        }

        It "Should Return That The Active Auth Certificate Must To Be Replaced" {
            $results | Should -Not -BeNullOrEmpty
            $results.CurrentAuthCertificateLifetimeInDays | Should -BeLessThan 0
            $results.ReplaceRequired | Should -Be $true
            $results.ConfigureNextAuthRequired | Should -Be $false
        }
    }

    Context "Scenario #4: Current Auth Certificate is missing on at least one (1) mailbox server" {
        BeforeAll {
            Mock Get-AuthConfig { return Import-Clixml $Script:parentPath\Tests\Data\GetAuthConfig.xml }
            Mock Get-Date { return [DateTime]::Parse('2026-12-20T00:00:00') }
            Mock Get-ExchangeServerCertificate {
                throw [System.InvalidOperationException]::New()
            } -ParameterFilter {
                ($Thumbprint -eq "E1BDF9AE58C93C75E76C9DD882138FB8FF0FA786") -and
                ($Server -eq "E2k16-2.Contoso.lab")
            }
            $Script:results = Get-ExchangeAuthCertificateStatus
        }

        It "Should Return That The Active Auth Certificate Must To Be Imported" {
            $results | Should -Not -BeNullOrEmpty
            $results.ReplaceRequired | Should -Be $false
            $results.CurrentAuthCertificateImportRequired | Should -Be $true
            $results.NextAuthCertificateImportRequired | Should -Be $false
            $results.ConfigureNextAuthRequired | Should -Be $false
            $results.NumberOfUnreachableServers | Should -Be 0
            $results.AuthCertificateMissingOnServers.Count | Should -Be 1
            $results.AuthCertificateMissingOnServers | Should -Contain "E2k16-2.Contoso.lab"
        }
    }

    Context "Scenario #5: Next Auth Certificate is missing on at least one (1) mailbox server" {
        BeforeAll {
            Mock Get-AuthConfig { return Import-Clixml $Script:parentPath\Tests\Data\GetAuthConfig.xml }
            Mock Get-Date { return [DateTime]::Parse('2026-12-20T00:00:00') }
            Mock Get-ExchangeServerCertificate {
                throw [System.InvalidOperationException]::New()
            } -ParameterFilter {
                ($Thumbprint -eq "BC6BF924D6EF046E64F8D1987DC1D7D2F4C0042A") -and
                ($Server -eq "E2k16-1.Contoso.lab")
            }
            $Script:results = Get-ExchangeAuthCertificateStatus
        }

        It "Should Return That The Next Auth Certificate Must To Be Imported" {
            $results | Should -Not -BeNullOrEmpty
            $results.CurrentAuthCertificateLifetimeInDays | Should -BeGreaterThan 60
            $results.ReplaceRequired | Should -Be $false
            $results.ConfigureNextAuthRequired | Should -Be $false
            $results.CurrentAuthCertificateImportRequired | Should -Be $false
            $results.NextAuthCertificateImportRequired | Should -Be $true
            $results.NumberOfUnreachableServers | Should -Be 0
            $results.NextAuthCertificateMissingOnServers.Count | Should -Be 1
            $results.NextAuthCertificateMissingOnServers | Should -Contain "E2k16-1.Contoso.lab"
        }
    }

    Context "Exception While Calling Get-ExchangeServerCertificate" {
        BeforeAll {
            Mock Get-ExchangeServerCertificate { throw "Some terminating exception was hit" }
            $Script:results = Get-ExchangeAuthCertificateStatus
        }

        It "Should Not Return That An Auth Certificate Renewal Action Is Required" {
            $results | Should -Not -BeNullOrEmpty
            $results.CurrentAuthCertificateLifetimeInDays | Should -Be -1
            $results.ReplaceRequired | Should -Be $false
            $results.ConfigureNextAuthRequired | Should -Be $false
        }
    }
}
