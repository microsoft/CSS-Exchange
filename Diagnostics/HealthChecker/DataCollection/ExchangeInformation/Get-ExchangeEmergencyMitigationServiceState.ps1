# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
Function Get-ExchangeEmergencyMitigationServiceState {
    [CmdletBinding()]
    [OutputType("System.Object")]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName,
        [Parameter(Mandatory = $false)]
        [scriptblock]
        $CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed - Computername: $ComputerName"
    }
    process {
        try {
            $emergencyMitigationServiceOrgState = (Get-OrganizationConfig).MitigationsEnabled
        } catch {
            Write-Verbose "Failed to run Get-OrganizationConfig to get EEMS organization state"
            Invoke-CatchActionError $CatchActionFunction
        }

        if ($null -ne $emergencyMitigationServiceOrgState) {
            Write-Verbose "Exchange Emergency Mitigation Service detected"
            try {
                $exchangeEmergencyMitigationWinServiceRating = $null
                $emergencyMitigationWinService = Get-Service -ComputerName $ComputerName -Name MSExchangeMitigation
                if (($emergencyMitigationWinService.Status -eq "Running") -and
                    ($emergencyMitigationWinService.StartType -eq "Automatic")) {
                    $exchangeEmergencyMitigationWinServiceRating = "Running"
                } else {
                    $exchangeEmergencyMitigationWinServiceRating = "Investigate"
                }
            } catch {
                Write-Verbose "Failed to query EEMS Windows service data"
                Invoke-CatchActionError $CatchActionFunction
            }

            try {
                $exchangeServerConfiguration = Get-ExchangeServer -Identity $ComputerName
            } catch {
                Write-Verbose "Failed to run Get-ExchangeServer to get EEMS server config"
                Invoke-CatchActionError $CatchActionFunction
            }

            $eemsEndpoint = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlockDescription "Test EEMS pattern service connectivity" `
                -CatchActionFunction $CatchActionFunction `
                -ScriptBlock {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `
                    Invoke-WebRequest -Method Get -Uri "https://officeclient.microsoft.com/getexchangemitigations" -UseBasicParsing
            }
        }
    }
    end {
        return [PSCustomObject]@{
            MitigationWinServiceState = $exchangeEmergencyMitigationWinServiceRating
            MitigationServiceOrgState = $emergencyMitigationServiceOrgState
            MitigationServiceSrvState = $exchangeServerConfiguration.MitigationsEnabled
            MitigationServiceEndpoint = $eemsEndpoint.StatusCode
            MitigationsApplied        = $exchangeServerConfiguration.MitigationsApplied
            MitigationsBlocked        = $exchangeServerConfiguration.MitigationsBlocked
            DataCollectionEnabled     = $exchangeServerConfiguration.DataCollectionEnabled
        }
    }
}
