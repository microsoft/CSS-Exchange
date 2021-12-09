# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
Function Get-ExchangeEmergencyMitigationServiceState {
    [CmdletBinding()]
    [OutputType("System.Object")]
    param(
        [Parameter(Mandatory = $true)]
        [object]
        $RequiredInformation,
        [Parameter(Mandatory = $false)]
        [scriptblock]
        $CatchActionFunction
    )
    begin {
        $computerName = $RequiredInformation.ComputerName
        $emergencyMitigationServiceOrgState = $RequiredInformation.MitigationsEnabled
        $exchangeServerConfiguration = $RequiredInformation.GetExchangeServer
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed - Computername: $ComputerName"
    }
    process {
        if ($null -ne $emergencyMitigationServiceOrgState) {
            Write-Verbose "Exchange Emergency Mitigation Service detected"
            try {
                $exchangeEmergencyMitigationWinServiceRating = $null
                $emergencyMitigationWinService = Get-Service -ComputerName $ComputerName -Name MSExchangeMitigation -ErrorAction Stop
                if (($emergencyMitigationWinService.Status.ToString() -eq "Running") -and
                    ($emergencyMitigationWinService.StartType.ToString() -eq "Automatic")) {
                    $exchangeEmergencyMitigationWinServiceRating = "Running"
                } else {
                    $exchangeEmergencyMitigationWinServiceRating = "Investigate"
                }
            } catch {
                Write-Verbose "Failed to query EEMS Windows service data"
                Invoke-CatchActionError $CatchActionFunction
            }

            $eemsEndpoint = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlockDescription "Test EEMS pattern service connectivity" `
                -CatchActionFunction $CatchActionFunction `
                -ScriptBlock {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `
                    if ($null -ne $args[0]) {
                    Write-Verbose "Proxy Server detected. Going to use: $($args[0])"
                    [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($args[0])
                    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                    [System.Net.WebRequest]::DefaultWebProxy.BypassProxyOnLocal = $true
                }; `
                    Invoke-WebRequest -Method Get -Uri "https://officeclient.microsoft.com/getexchangemitigations" -UseBasicParsing
            } `
                -ArgumentList $exchangeServerConfiguration.InternetWebProxy
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
