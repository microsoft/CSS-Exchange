# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\Get-ExchangeEmergencyMitigationServiceState.ps1

    # We need to overwrite the existing 'Get-Service' function because it doesn't support
    # the '-ComputerName' parameter on PowerShell 7
    function Get-Service {
        param(
            [Parameter(Mandatory = $false)]
            [string]
            $ComputerName,
            [Parameter(Mandatory = $false)]
            [string]
            $Name
        )
    }
}

Describe "Testing Get-ExchangeEmergencyMitigationServiceState.ps1" {

    BeforeAll {
        Mock Invoke-WebRequest -MockWith { return Import-Clixml $Script:parentPath\Tests\DataCollection\InvokeWebRequestEEMS.xml }
        Mock Get-Service -MockWith { return Import-Clixml $Script:parentPath\Tests\DataCollection\GetServiceMSExchangeMitigationRunning.xml } `
            -ParameterFilter { $ComputerName -eq $Script:Server }

        $Script:customObject = ([PSCustomObject]@{
                ComputerName       = $Script:Server
                MitigationsEnabled = $true
                GetExchangeServer  = [PSCustomObject]@{
                    InternetWebProxy      = $null
                    MitigationsEnabled    = $true
                    MitigationsApplied    = "PING01"
                    MitigationsBlocked    = $null
                    DataCollectionEnabled = $true
                }
            })
    }

    Context "Exchange Emergency Mitigation Service Default State" {

        BeforeAll {
            $Script:results = Get-ExchangeEmergencyMitigationServiceState -RequiredInformation $customObject
        }

        It "Mitigation Service Enabled On Org Level" {
            $results.MitigationServiceOrgState | Should -Be $true
        }

        It "Mitigation Service Enabled On Srv Level" {
            $results.MitigationServiceSrvState | Should -Be $true
        }

        It "Mitigation Windows Service Enabled And Running" {
            $results.MitigationWinServiceState | Should -Be "Running"
        }

        It "Mitigation Service Endpoint Reachable" {
            $results.MitigationServiceEndpoint | Should -Be 200
        }

        It "PING Mitigation Applied" {
            $results.MitigationsApplied | Should -Be "PING01"
        }

        It "Telemetry Enabled" {
            $results.DataCollectionEnabled | Should -Be $true
        }
    }

    Context "Exchange Emergency Mitigation Service Disabled State" {

        BeforeAll {
            Mock Get-Service -MockWith { return Import-Clixml $Script:parentPath\Tests\DataCollection\GetServiceMSExchangeMitigationDisabled.xml } `
                -ParameterFilter { $ComputerName -eq $Script:Server }

            $Script:customObject.MitigationsEnabled = $false
            $Script:customObject.GetExchangeServer.MitigationsEnabled = $false
            $Script:customObject.GetExchangeServer.DataCollectionEnabled = $false
            $Script:results = Get-ExchangeEmergencyMitigationServiceState -RequiredInformation $customObject
        }

        It "Mitigation Service Disabled On Org Level" {
            $results.MitigationServiceOrgState | Should -Be $false
        }

        It "Mitigation Service Disabled On Srv Level" {
            $results.MitigationServiceSrvState | Should -Be $false
        }

        It "Mitigation Windows Service Disabled And Stopped" {
            $results.MitigationWinServiceState | Should -Be "Investigate"
        }

        It "Mitigation Service Endpoint Reachable" {
            $results.MitigationServiceEndpoint | Should -Be 200
        }

        It "PING Mitigation Applied" {
            $results.MitigationsApplied | Should -Be "PING01"
        }

        It "Telemetry Disabled" {
            $results.DataCollectionEnabled | Should -Be $false
        }
    }

    Context "Exchange Emergency Mitigation Service OCS Not Reachable" {

        BeforeAll {
            Mock Invoke-WebRequest -MockWith { return $null }

            $Script:customObject.GetExchangeServer.MitigationsApplied = $null
            $Script:results = Get-ExchangeEmergencyMitigationServiceState -RequiredInformation $customObject
        }

        It "Mitigation Service Endpoint Not Reachable" {
            $results.MitigationServiceEndpoint | Should -Be $null
        }

        It "No Mitigation Applied" {
            $results.MitigationsApplied | Should -Be $null
        }

        It "No Mitigation Blocked" {
            $results.MitigationsBlocked | Should -Be $null
        }
    }

    Context "Exchange Emergency Mitigation Service Mitigations Applied/Blocked" {

        BeforeAll {
            Mock Invoke-WebRequest -MockWith { return $null }

            $mitigationsAppliedArray = @("PING01", "M01", "M03")
            $mitigationsBlockedArray = @("M02")
            $Script:customObject.GetExchangeServer.MitigationsApplied = $mitigationsAppliedArray
            $Script:customObject.GetExchangeServer.MitigationsBlocked = $mitigationsBlockedArray
            $Script:results = Get-ExchangeEmergencyMitigationServiceState -RequiredInformation $customObject
        }

        It "3 Mitigations Applied" {
            ($results.MitigationsApplied).Count | Should -Be 3
            $results.MitigationsApplied | Should -Be $mitigationsAppliedArray
        }

        It "1 Mitigation Blocked" {
            ($results.MitigationsBlocked).Count | Should -Be 1
            $results.MitigationsBlocked | Should -Be "M02"
        }
    }
}
