# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Invoke-CatchActions.ps1
Function Get-ExchangeDependentServices {
    [CmdletBinding()]
    param(
        [string]$MachineName
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $criticalWindowServices = @("WinMgmt", "W3Svc", "IISAdmin", "Pla")
        $criticalExchangeServices = @("MSExchangeADTopology", "MSExchangeDelivery",
            "MSExchangeFastSearch", "MSExchangeFrontEndTransport", "MSExchangeIS",
            "MSExchangeRepl", "MSExchangeRPC", "MSExchangeServiceHost",
            "MSExchangeSubmission", "MSExchangeTransport", "HostControllerService")
        $commonExchangeServices = @("MSExchangeAntispamUpdate", "MSExchangeCompliance",
            "MSExchangeDagMgmt", "MSExchangeDiagnostics", "MSExchangeEdgeSync",
            "MSExchangeHM", "MSExchangeHMRecovery", "MSExchangeMailboxAssistants",
            "MSExchangeMailboxReplication", "MSExchangeMitigation",
            "MSExchangeThrottling", "MSExchangeTransportLogSearch", "BITS")
        $criticalServices = New-Object 'System.Collections.Generic.List[object]'
        $commonServices = New-Object 'System.Collections.Generic.List[object]'
        Function TestServiceRunning {
            param(
                [object]$Service
            )
            Write-Verbose "Testing $($Service.Name) - Status: $($Service.Status)"
            if ($Service.Status.ToString() -eq "Running") { return $true }
            return $false
        }

        Function NewServiceObject {
            param(
                [object]$Service
            )
            return [PSCustomObject]@{
                Service   = $Service
                Name      = $Service.Name
                Status    = $Service.Status
                StartType = $Service.StartType
            }
        }
    } process {
        try {
            $getServices = Get-Service -ComputerName $MachineName -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to get the services on the server"
            Invoke-CatchActions
            return
        }

        foreach ($service in $getServices) {
            if (($criticalWindowServices.Contains($service.Name) -or
                    $criticalExchangeServices.Contains($service.Name)) -and
                (-not (TestServiceRunning $service))) {
                $criticalServices.Add((NewServiceObject $service))
            } elseif ($commonExchangeServices.Contains($service.Name) -and
                (-not (TestServiceRunning $service))) {
                $commonServices.Add((NewServiceObject $service))
            }
        }
    } end {
        return [PSCustomObject]@{
            Services = $getServices
            Critical = $criticalServices
            Common   = $commonServices
        }
    }
}
