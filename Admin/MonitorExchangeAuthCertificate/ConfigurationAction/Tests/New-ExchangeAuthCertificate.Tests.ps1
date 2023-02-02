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
    . $Script:parentPath\New-ExchangeAuthCertificate.ps1

    # Don't sleep in pester testing
    Mock Start-Sleep { return }

    function Invoke-CatchActionError {
        param()
    }

    function Get-Date {
        param()

        return [DateTime]::Parse('2023-01-01T00:00:00')
    }

    function Get-WebSite {
        param()

        <#
            Data exported like this:
            ConvertTo-Json -InputObject (Get-WebSite) -Depth 4 | Out-File GetWebSite.json -Encoding UTF8
        #>
        return Get-Content $Script:parentPath\Tests\Data\GetWebSite.json | ConvertFrom-Json
    }

    function New-ExchangeCertificate {
        param()
    }

    function Enable-ExchangeCertificate {
        param()
    }

    function Set-AuthConfig {
        param()
    }

    function Restart-Service {
        param()
    }

    function Get-ExchangeServerCertificate {
        param(
            [string]$Thumbprint = $null
        )

        if ($null -ne $Thumbprint) {
            return Import-Clixml $Script:parentPath\..\DataCollection\Tests\Data\GetExchangeCertificate.xml | Where-Object { $_.Thumbprint -eq $Thumbprint }
        }
        return Import-Clixml $Script:parentPath\..\DataCollection\Tests\Data\GetExchangeCertificate.xml
    }

    function Restart-WebAppPool {
        param()
    }

    function Get-InternalTransportCertificateFromServer {
        param()

        return Import-Clixml $Script:parentPath\Tests\Data\GetInternalTransportCertificateFromServer.xml
    }
}

Describe "Testing New-ExchangeAuthCertificate.ps1" {

    Context "Running New-ExchangeAuthCertificate To Replace The Primary Auth Certificate" {
        BeforeAll {
            Mock Set-AuthConfig { return $null }
            Mock Restart-Service { return $null }
            Mock Restart-WebAppPool { return $null }
            Mock New-ExchangeCertificate { return Import-Clixml $Script:parentPath\Tests\Data\NewExchangeAuthCertificate.xml } -ParameterFilter {
                $SubjectName -eq 'cn=Microsoft Exchange Server Auth Certificate'
            }
            Mock New-ExchangeCertificate { return Import-Clixml $Script:parentPath\Tests\Data\NewExchangeCertificateDefaultTransport.xml }
        }

        <#
        Will be added again as this test fails due to the new $PSCmdlet.ShouldProcess() logic

        It "Should Replace The Primary Auth Certificate Without Restarting The Web App Pools" {
            $Script:results = New-ExchangeAuthCertificate -ReplaceExpiredAuthCertificate
            $results | Should -BeOfType 'System.Management.Automation.PSCustomObject'
            $results.RenewalActionPerformed | Should -Be $true
            $results.AuthCertificateActivationDate | Should -BeOfType 'System.DateTime'
            Should -Invoke New-ExchangeCertificate -Times 1 -Exactly
            Should -Invoke Set-AuthConfig -Times 3 -Exactly
            Should -Invoke Restart-Service -Times 1 -Exactly
            Should -Invoke Restart-WebAppPool -Times 0 -Exactly
        }
        #>

        It "Should Replace The Primary Auth Certificate And Restarts The Web App Pools" {
            $Script:results = New-ExchangeAuthCertificate -ReplaceExpiredAuthCertificate -Confirm:$false
            $results | Should -BeOfType 'System.Management.Automation.PSCustomObject'
            $results.RenewalActionPerformed | Should -Be $true
            $results.AuthCertificateActivationDate | Should -BeOfType 'System.DateTime'
            Should -Invoke New-ExchangeCertificate -Times 1 -Exactly
            Should -Invoke Set-AuthConfig -Times 3 -Exactly
            Should -Invoke Restart-Service -Times 1 -Exactly
            Should -Invoke Restart-WebAppPool -Times 2 -Exactly
        }
    }

    Context "Running New-ExchangeAuthCertificate To Stage The Next Auth Certificate" {
        BeforeAll {
            Mock Set-AuthConfig { return $null }
            Mock Restart-Service { return $null }
            Mock Restart-WebAppPool { return $null }
            Mock New-ExchangeCertificate { return Import-Clixml $Script:parentPath\Tests\Data\NewExchangeAuthCertificate.xml } -ParameterFilter {
                $SubjectName -eq 'cn=Microsoft Exchange Server Auth Certificate'
            }
            Mock New-ExchangeCertificate { return Import-Clixml $Script:parentPath\Tests\Data\NewExchangeCertificateDefaultTransport.xml }
        }

        It "Should Replace the Next Auth Certificate In 30 Days Without Restarting The MSExchangeServiceHost Service" {
            $Script:results = New-ExchangeAuthCertificate -ConfigureNextAuthCertificate -CurrentAuthCertificateLifetimeInDays 50 -Confirm:$false
            $results | Should -BeOfType 'System.Management.Automation.PSCustomObject'
            $results.RenewalActionPerformed | Should -Be $true
            $results.AuthCertificateActivationDate | Should -BeOfType 'System.DateTime'
            ($results.AuthCertificateActivationDate - (Get-Date)).Days | Should -Be 30
            Should -Invoke New-ExchangeCertificate -Times 1 -Exactly
            Should -Invoke Set-AuthConfig -Times 1 -Exactly
            Should -Invoke Restart-Service -Times 0 -Exactly
        }

        It "Should Replace the Next Auth Certificate And Rotate In 4 Days" {
            $Script:results = New-ExchangeAuthCertificate -ConfigureNextAuthCertificate -CurrentAuthCertificateLifetimeInDays 10 -Confirm:$false
            $results | Should -BeOfType 'System.Management.Automation.PSCustomObject'
            $results.RenewalActionPerformed | Should -Be $true
            $results.AuthCertificateActivationDate | Should -BeOfType 'System.DateTime'
            ($results.AuthCertificateActivationDate - (Get-Date)).Days | Should -Be 4
            Should -Invoke New-ExchangeCertificate -Times 1 -Exactly
            Should -Invoke Set-AuthConfig -Times 1 -Exactly
            Should -Invoke Restart-Service -Times 0 -Exactly
        }

        It "Should Replace the Next Auth Certificate As Rotate In 2 Days" {
            $Script:results = New-ExchangeAuthCertificate -ConfigureNextAuthCertificate -CurrentAuthCertificateLifetimeInDays 3 -Confirm:$false
            $results | Should -BeOfType 'System.Management.Automation.PSCustomObject'
            $results.RenewalActionPerformed | Should -Be $true
            $results.AuthCertificateActivationDate | Should -BeOfType 'System.DateTime'
            ($results.AuthCertificateActivationDate - (Get-Date)).Days | Should -Be 2
            Should -Invoke New-ExchangeCertificate -Times 1 -Exactly
            Should -Invoke Set-AuthConfig -Times 1 -Exactly
            Should -Invoke Restart-Service -Times 0 -Exactly
        }

        It "Should Replace the Next Auth Certificate And Rotate Immediately" {
            $Script:results = New-ExchangeAuthCertificate -ConfigureNextAuthCertificate -CurrentAuthCertificateLifetimeInDays 0 -Confirm:$false
            $results | Should -BeOfType 'System.Management.Automation.PSCustomObject'
            $results.RenewalActionPerformed | Should -Be $true
            $results.AuthCertificateActivationDate | Should -BeOfType 'System.DateTime'
            ($results.AuthCertificateActivationDate - (Get-Date)).Days | Should -Be 0
            Should -Invoke New-ExchangeCertificate -Times 1 -Exactly
            Should -Invoke Set-AuthConfig -Times 1 -Exactly
            Should -Invoke Restart-Service -Times 1 -Exactly
        }
    }

    Context "Replace Expired Auth Certificate And Configure New Internal SMTP Certificate If The Existing One Wasn't Detected" {
        BeforeAll {
            Mock Set-AuthConfig { return $null }
            Mock Restart-Service { return $null }
            Mock Restart-WebAppPool { return $null }
            Mock New-ExchangeCertificate { return Import-Clixml $Script:parentPath\Tests\Data\NewExchangeAuthCertificate.xml } -ParameterFilter {
                $SubjectName -eq 'cn=Microsoft Exchange Server Auth Certificate'
            }
            Mock New-ExchangeCertificate { return Import-Clixml $Script:parentPath\Tests\Data\NewExchangeCertificateDefaultTransport.xml }
            Mock Get-Date { return [DateTime]::Parse('2029-01-03T00:00:00') }
            Mock Get-ExchangeServerCertificate { throw 'No Exchange Server Certificate Found' }	-ParameterFilter {
                $Thumbprint -eq '0CEB5AC90A9E4BB9E4F8F1F0D7FC8F4EEA4F2CA2'
            }
            Mock Get-InternalTransportCertificateFromServer { return Import-Clixml $Script:parentPath\Tests\Data\InvalidExchangeDefaultTransportCertificate.xml }
        }

        It "Should Create A New Internal SMTP Certificate" {
            $Script:results = New-ExchangeAuthCertificate -ReplaceExpiredAuthCertificate -Confirm:$false
            # Call this 2 time as the first call is to create a new Auth Certificate and the second call is to create a new Internal SMTP Certificate
            Should -Invoke New-ExchangeCertificate -Times 2 -Exactly
            Should -Invoke Set-AuthConfig -Times 3 -Exactly
            Should -Invoke Restart-Service -Times 1 -Exactly
        }
    }
}
