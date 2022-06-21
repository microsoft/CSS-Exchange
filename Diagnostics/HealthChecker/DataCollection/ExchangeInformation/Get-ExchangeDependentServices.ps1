﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
function Get-ExchangeDependentServices {
    [CmdletBinding()]
    param(
        [string]$MachineName
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $criticalWindowServices = @("WinMgmt", "W3Svc", "IISAdmin", "Pla", "MpsSvc",
            "RpcEptMapper", "EventLog").ToLower()
        $criticalExchangeServices = @("MSExchangeADTopology", "MSExchangeDelivery",
            "MSExchangeFastSearch", "MSExchangeFrontEndTransport", "MSExchangeIS",
            "MSExchangeRepl", "MSExchangeRPC", "MSExchangeServiceHost",
            "MSExchangeSubmission", "MSExchangeTransport", "HostControllerService").ToLower()
        $commonExchangeServices = @("MSExchangeAntispamUpdate", "MSComplianceAudit", "MSExchangeCompliance",
            "MSExchangeDagMgmt", "MSExchangeDiagnostics", "MSExchangeEdgeSync",
            "MSExchangeHM", "MSExchangeHMRecovery", "MSExchangeMailboxAssistants",
            "MSExchangeMailboxReplication", "MSExchangeMitigation",
            "MSExchangeThrottling", "MSExchangeTransportLogSearch", "BITS").ToLower()
        $criticalServices = New-Object 'System.Collections.Generic.List[object]'
        $commonServices = New-Object 'System.Collections.Generic.List[object]'
        $getServicesList = New-Object 'System.Collections.Generic.List[object]'
        function TestServiceRunning {
            param(
                [object]$Service
            )
            Write-Verbose "Testing $($Service.Name) - Status: $($Service.Status)"
            if ($Service.Status.ToString() -eq "Running") { return $true }
            return $false
        }

        function NewServiceObject {
            param(
                [object]$Service
            )
            $name = $Service.Name
            $status = "Unknown"
            $startType = "Unknown"
            try {
                $status = $Service.Status.ToString()
            } catch {
                Write-Verbose "Failed to set Status of service '$name'"
                Invoke-CatchActions
            }
            try {
                $startType = $Service.StartType.ToString()
            } catch {
                Write-Verbose "Failed to set Start Type of service '$name'"
                Invoke-CatchActions
            }
            return [PSCustomObject]@{
                Name      = $name
                Status    = $status
                StartType = $startType
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
            if (($criticalWindowServices.Contains($service.Name.ToLower()) -or
                    $criticalExchangeServices.Contains($service.Name.ToLower())) -and
                (-not (TestServiceRunning $service))) {
                $criticalServices.Add((NewServiceObject $service))
            } elseif ($commonExchangeServices.Contains($service.Name.ToLower()) -and
                (-not (TestServiceRunning $service))) {
                $commonServices.Add((NewServiceObject $service))
            }
            $getServicesList.Add((NewServiceObject $service))
        }
    } end {
        return [PSCustomObject]@{
            Services = $getServicesList
            Critical = $criticalServices
            Common   = $commonServices
        }
    }
}
