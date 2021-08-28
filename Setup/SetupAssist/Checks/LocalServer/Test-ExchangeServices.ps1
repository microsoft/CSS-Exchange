# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
function Test-ExchangeServices {

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

    $services = Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $exchangeServices.Contains($_.Name) }

    foreach ($service in $services) {

        $params = @{
            TestName      = "Exchange Services"
            Details       = "Service: $($service.Name) Status: $($service.Status) StartType: $($service.StartType)"
            ReferenceInfo = "Set the service to Automatic and start it"
        }

        if ($service.Status.ToString() -ne "Running" -or
            $service.StartType.ToString() -eq "Disabled") {
            New-TestResult @params -Result "Warning"
        } else {
            New-TestResult @params -Result "Passed"
        }
    }
}
