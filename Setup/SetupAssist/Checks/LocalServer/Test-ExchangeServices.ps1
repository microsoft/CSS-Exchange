# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
function Test-ExchangeServices {
    [CmdletBinding()]
    param()
    begin {
        $exchangeServices = @(
            "MpsSvc",
            "FMS",
            "HostControllerService",
            "MSExchangeADTopology",
            "MSExchangeAntispamUpdate",
            "MSExchangeDagMgmt",
            "MSExchangeDelivery",
            "MSExchangeDiagnostics",
            "MSExchangeEdgeSync",
            "MSExchangeFastSearch",
            "MSExchangeFrontEndTransport",
            "MSExchangeHM",
            "MSExchangeIS",
            "MSExchangeMailboxAssistants",
            "MSExchangeMailboxReplication",
            "MSExchangeRepl",
            "MSExchangeRPC",
            "MSExchangeServiceHost",
            "MSExchangeSubmission",
            "MSExchangeThrottling",
            "MSExchangeTransport",
            "MSExchangeTransportLogSearch")
        $result = "Passed"
        $servicesNotRunning = New-Object 'System.Collections.Generic.List[object]'
        $context = [string]::Empty
    }
    process {
        $services = Get-Service -ErrorAction SilentlyContinue |
            Where-Object { $exchangeServices.Contains($_.Name) }

        foreach ($service in $services) {

            if ($service.Status.ToString() -ne "Running" -or
                $service.StartType.ToString() -eq "Disabled") {
                $servicesNotRunning.Add( [PSCustomObject]@{
                        Name      = $service.Name
                        Status    = $service.Status
                        StartType = $service.StartType
                    })
                $result = "Warning"
            }

            if ($result -eq "Warning") {
                $context = "$($servicesNotRunning.Count) services not running"
            }
        }
    }
    end {
        $params = @{
            TestName          = "Exchange Services"
            Result            = $result
            AdditionalContext = $context
            CustomData        = $servicesNotRunning
        }

        return (New-TestResult @params)
    }
}
