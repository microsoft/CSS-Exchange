# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Module installation stub for Pester')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "ExchangeOnlineFunctions"

    # The module is not installed on every build agent, so the cmdlet is replaced by a stub that
    # records the arguments instead of connecting anywhere.
    function Connect-ExchangeOnline {
        [CmdletBinding()]
        param(
            [string]$ConnectionUri,
            [string]$AzureADAuthorizationEndpointUri,
            [PSCredential]$Credential,
            [string]$Prefix,
            [bool]$ShowBanner
        )
        throw "Exchange Online connections must be mocked."
    }

    function Install-Module {
        [CmdletBinding()]
        param(
            [string]$Name,
            [switch]$Force,
            [string]$Scope
        )
        throw "Module installation must be mocked."
    }

    . (Join-Path -Path $Script:parentPath -ChildPath "Connect-ExchangeOnlineEndpoint.ps1")
    . (Join-Path -Path $Script:parentPath -ChildPath "Test-ExchangeOnlineManagementModule.ps1")
}

Describe "Testing Connect-ExchangeOnlineEndpoint.ps1" {

    BeforeEach {
        Mock -CommandName Connect-ExchangeOnline -MockWith {}
    }

    Context "Keeping the module defaults" {

        It "Passes no arguments at all when the caller supplies none" {
            Connect-ExchangeOnlineEndpoint

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $PesterBoundParameters.Count -eq 0
            }
        }

        It "Omits <Name> when it is empty or null" -TestCases @(
            @{ Name = "ConnectionUri"; Value = "" }
            @{ Name = "ConnectionUri"; Value = $null }
            @{ Name = "AzureADAuthorizationEndpointUri"; Value = "" }
            @{ Name = "AzureADAuthorizationEndpointUri"; Value = $null }
            @{ Name = "Prefix"; Value = "" }
            @{ Name = "Prefix"; Value = $null }
            @{ Name = "Credential"; Value = $null }
        ) {
            param($Name, $Value)
            $arguments = @{ $Name = $Value }

            Connect-ExchangeOnlineEndpoint @arguments

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $PesterBoundParameters.Count -eq 0
            }
        }
    }

    Context "Forwarding the supplied endpoints" {

        It "Forwards the connection endpoint" {
            Connect-ExchangeOnlineEndpoint -ConnectionUri "https://outlook.contoso.com/powershell"

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $PesterBoundParameters.Count -eq 1 -and
                $ConnectionUri -ceq "https://outlook.contoso.com/powershell"
            }
        }

        It "Forwards the authorization endpoint" {
            Connect-ExchangeOnlineEndpoint -AzureADAuthorizationEndpointUri "https://login.contoso.com/organizations"

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $PesterBoundParameters.Count -eq 1 -and
                $AzureADAuthorizationEndpointUri -ceq "https://login.contoso.com/organizations"
            }
        }

        It "Forwards both endpoints together" {
            Connect-ExchangeOnlineEndpoint -ConnectionUri "https://outlook.contoso.com/powershell" -AzureADAuthorizationEndpointUri "https://login.contoso.com/organizations"

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $PesterBoundParameters.Count -eq 2 -and
                $ConnectionUri -ceq "https://outlook.contoso.com/powershell" -and
                $AzureADAuthorizationEndpointUri -ceq "https://login.contoso.com/organizations"
            }
        }

        It "Forwards the prefix" {
            Connect-ExchangeOnlineEndpoint -Prefix "Source"

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $PesterBoundParameters.Count -eq 1 -and $Prefix -ceq "Source"
            }
        }

        It "Forwards the credentials" {
            $expected = [PSCredential]::new("contoso\admin", [System.Security.SecureString]::new())

            Connect-ExchangeOnlineEndpoint -Credential $expected

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $PesterBoundParameters.Count -eq 1 -and
                $Credential.UserName -ceq $expected.UserName
            }
        }
    }

    Context "Controlling the error handling" {

        It "Omits ErrorAction so that the preference of the caller stays in effect" {
            Connect-ExchangeOnlineEndpoint -ConnectionUri "https://outlook.contoso.com/powershell"

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey("ErrorAction")
            }
        }

        It "Passes <ConnectErrorAction> on to the cmdlet" -TestCases @(
            @{ ConnectErrorAction = "Stop" }
            @{ ConnectErrorAction = "SilentlyContinue" }
            @{ ConnectErrorAction = "Continue" }
        ) {
            param($ConnectErrorAction)

            Connect-ExchangeOnlineEndpoint -ConnectErrorAction $ConnectErrorAction

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $PesterBoundParameters.ErrorAction -eq $ConnectErrorAction
            }
        }

        It "Rejects the unsupported error action <ConnectErrorAction>" -TestCases @(
            @{ ConnectErrorAction = "Terminate" }
            @{ ConnectErrorAction = "" }
            @{ ConnectErrorAction = $null }
        ) {
            param($ConnectErrorAction)
            { Connect-ExchangeOnlineEndpoint -ConnectErrorAction $ConnectErrorAction } | Should -Throw
        }
    }

    Context "Controlling the banner" {

        It "Omits the banner switch so that the module default stays in effect" {
            Connect-ExchangeOnlineEndpoint

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey("ShowBanner")
            }
        }

        It "Passes the banner value <ShowBanner> on to the cmdlet" -TestCases @(
            @{ ShowBanner = $true }
            @{ ShowBanner = $false }
        ) {
            param($ShowBanner)

            Connect-ExchangeOnlineEndpoint -ShowBanner $ShowBanner

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $PesterBoundParameters.ContainsKey("ShowBanner") -and
                $PesterBoundParameters.ShowBanner -eq $ShowBanner
            }
        }
    }
}

Describe "Testing Test-ExchangeOnlineManagementModule.ps1" {

    BeforeEach {
        $Script:moduleLoaded = $false
        Mock -CommandName Import-Module -MockWith {}
        Mock -CommandName Install-Module -MockWith { $Script:moduleLoaded = $true }
        Mock -CommandName Get-Module -MockWith {
            if ($Script:moduleLoaded) {
                [PSCustomObject]@{ Name = "ExchangeOnlineManagement" }
            }
        }
    }

    Context "Reporting an available module" {

        It "Returns true and installs nothing when the module is present" {
            $Script:moduleLoaded = $true

            Test-ExchangeOnlineManagementModule | Should -BeTrue

            Should -Invoke -CommandName Install-Module -Times 0 -Exactly
        }

        It "Returns true without installing when the module is present and InstallIfMissing is used" {
            $Script:moduleLoaded = $true

            Test-ExchangeOnlineManagementModule -InstallIfMissing | Should -BeTrue

            Should -Invoke -CommandName Install-Module -Times 0 -Exactly
        }
    }

    Context "Reporting a missing module" {

        It "Returns false and installs nothing without InstallIfMissing" {
            Test-ExchangeOnlineManagementModule | Should -BeFalse

            Should -Invoke -CommandName Install-Module -Times 0 -Exactly
        }

        It "Installs the module for the current user when InstallIfMissing is used" {
            Test-ExchangeOnlineManagementModule -InstallIfMissing | Should -BeTrue

            Should -Invoke -CommandName Install-Module -Times 1 -Exactly -ParameterFilter {
                $Name -eq "ExchangeOnlineManagement" -and $Force -and $Scope -eq "CurrentUser"
            }
        }

        It "Returns false when the installation fails" {
            Mock -CommandName Install-Module -MockWith { throw "The repository is not reachable." }

            Test-ExchangeOnlineManagementModule -InstallIfMissing | Should -BeFalse
        }

        It "Returns false when the installation reports success but the module stays unavailable" {
            Mock -CommandName Install-Module -MockWith {}

            Test-ExchangeOnlineManagementModule -InstallIfMissing | Should -BeFalse
        }
    }
}
