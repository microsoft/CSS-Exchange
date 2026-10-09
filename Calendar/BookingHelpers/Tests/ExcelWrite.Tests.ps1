# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test stubs for Microsoft Graph cmdlets; they change no state.')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)

    # Stub the module checks and the Microsoft Graph cmdlets before loading the script under test.
    # The real cmdlets come from Microsoft.Graph.Authentication, which is not required to run these tests.
    function CheckExcelModuleInstalled {}
    function CheckGraphAuthModuleInstalled {}
    function CheckGraphBookingsModuleInstalled {}
    function CheckGraphModulesInstalled { return $true }

    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome, $Environment) }
    function Get-MgEnvironment { param($Name) }
    function Add-MgEnvironment { param($Name, $GraphEndpoint, $AzureADEndpoint) }
    function Set-MgEnvironment { param($Name, $GraphEndpoint, $AzureADEndpoint) }
    function Remove-MgEnvironment { param($Name) }

    . "$Script:parentPath\ExcelWrite.ps1"

    $Script:graphUri = "https://graph.contoso.example"
    $Script:authUri = "https://login.contoso.example"
}

Describe "Testing ExcelWrite.ps1 Microsoft Graph endpoint overrides" {

    Context "TestGraphEndpointParameters" {

        It "Returns false when neither endpoint is supplied" {
            TestGraphEndpointParameters -GraphEndpointUri "" -AzureADEndpointUri "" | Should -BeFalse
        }

        It "Returns true when both endpoints are supplied" {
            TestGraphEndpointParameters -GraphEndpointUri $Script:graphUri -AzureADEndpointUri $Script:authUri | Should -BeTrue
        }

        It "Throws when only GraphEndpointUri is supplied" {
            { TestGraphEndpointParameters -GraphEndpointUri $Script:graphUri -AzureADEndpointUri "" } |
                Should -Throw -ExpectedMessage "GraphEndpointUri and AzureADEndpointUri must be specified together"
        }

        It "Throws when only AzureADEndpointUri is supplied" {
            { TestGraphEndpointParameters -GraphEndpointUri "" -AzureADEndpointUri $Script:authUri } |
                Should -Throw -ExpectedMessage "GraphEndpointUri and AzureADEndpointUri must be specified together"
        }
    }

    Context "CheckModulesAndConnectGraph without overrides" {

        BeforeEach {
            Mock CheckExcelModuleInstalled {}
            Mock CheckGraphAuthModuleInstalled {}
            Mock CheckGraphBookingsModuleInstalled {}
            Mock CheckGraphModulesInstalled { return $true }
            Mock Connect-MgGraph {}
            Mock Add-MgEnvironment {}
            Mock Set-MgEnvironment {}
            Mock Remove-MgEnvironment {}
            Mock Get-MgEnvironment { return $null }
            Mock Write-Host {}
        }

        It "Connects using the module defaults" {
            CheckModulesAndConnectGraph

            Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
                $null -eq $Environment -and $NoWelcome -eq $true
            }
        }

        It "Requests the scopes the Bookings data collection needs" {
            CheckModulesAndConnectGraph

            Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
                $Scopes -contains "User.Read.All" -and $Scopes -contains "Bookings.Read.All"
            }
        }

        It "Does not touch the Microsoft Graph settings file" {
            CheckModulesAndConnectGraph

            Should -Invoke Add-MgEnvironment -Times 0 -Exactly
            Should -Invoke Set-MgEnvironment -Times 0 -Exactly
            Should -Invoke Remove-MgEnvironment -Times 0 -Exactly
        }
    }

    Context "CheckModulesAndConnectGraph with overrides" {

        BeforeEach {
            # Track registration so Get-MgEnvironment reflects what Add/Set did, as the real cmdlets do.
            $Script:envState = @{ Registered = $false }

            Mock CheckExcelModuleInstalled {}
            Mock CheckGraphAuthModuleInstalled {}
            Mock CheckGraphBookingsModuleInstalled {}
            Mock CheckGraphModulesInstalled { return $true }
            Mock Connect-MgGraph {}
            Mock Add-MgEnvironment { $Script:envState.Registered = $true }
            Mock Set-MgEnvironment { $Script:envState.Registered = $true }
            Mock Remove-MgEnvironment { $Script:envState.Registered = $false }
            Mock Get-MgEnvironment {
                if ($Script:envState.Registered) {
                    return [PSCustomObject]@{ Name = "BookingsDiagnosticSummary" }
                }

                return $null
            }
            Mock Write-Host {}
        }

        It "Registers the supplied endpoints verbatim" {
            CheckModulesAndConnectGraph -GraphEndpointUri $Script:graphUri -AzureADEndpointUri $Script:authUri

            Should -Invoke Add-MgEnvironment -Times 1 -Exactly -ParameterFilter {
                $GraphEndpoint -eq $Script:graphUri -and $AzureADEndpoint -eq $Script:authUri
            }
        }

        It "Connects using the registered environment" {
            CheckModulesAndConnectGraph -GraphEndpointUri $Script:graphUri -AzureADEndpointUri $Script:authUri

            Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
                $Environment -eq "BookingsDiagnosticSummary"
            }
        }

        It "Removes the environment again so the settings file is left unchanged" {
            CheckModulesAndConnectGraph -GraphEndpointUri $Script:graphUri -AzureADEndpointUri $Script:authUri

            Should -Invoke Remove-MgEnvironment -Times 1 -Exactly -ParameterFilter {
                $Name -eq "BookingsDiagnosticSummary"
            }
        }

        It "Updates rather than adds when the environment already exists" {
            $Script:envState.Registered = $true

            CheckModulesAndConnectGraph -GraphEndpointUri $Script:graphUri -AzureADEndpointUri $Script:authUri

            Should -Invoke Set-MgEnvironment -Times 1 -Exactly
            Should -Invoke Add-MgEnvironment -Times 0 -Exactly
        }

        It "Removes the environment even when connecting fails" {
            Mock Connect-MgGraph { throw "connection refused" }

            { CheckModulesAndConnectGraph -GraphEndpointUri $Script:graphUri -AzureADEndpointUri $Script:authUri } | Should -Throw

            Should -Invoke Remove-MgEnvironment -Times 1 -Exactly
        }

        It "Throws before connecting when only one endpoint is supplied" {
            { CheckModulesAndConnectGraph -GraphEndpointUri $Script:graphUri -AzureADEndpointUri "" } | Should -Throw

            Should -Invoke Connect-MgGraph -Times 0 -Exactly
            Should -Invoke Add-MgEnvironment -Times 0 -Exactly
        }
    }

    Context "RemoveGraphEnvironment" {

        BeforeEach {
            Mock Remove-MgEnvironment {}
            Mock Write-Host {}
        }

        It "Does nothing when the environment is not registered" {
            Mock Get-MgEnvironment { return $null }

            RemoveGraphEnvironment

            Should -Invoke Remove-MgEnvironment -Times 0 -Exactly
        }

        It "Reports but does not rethrow when removal fails" {
            Mock Get-MgEnvironment { return [PSCustomObject]@{ Name = "BookingsDiagnosticSummary" } }
            Mock Remove-MgEnvironment { throw "settings file locked" }

            { RemoveGraphEnvironment } | Should -Not -Throw
        }
    }
}
