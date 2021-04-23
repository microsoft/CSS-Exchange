Function Test-CriticalService {
    $critical = @(
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

    $services = Get-Service -ErrorAction SilentlyContinue

    foreach ($name in $critical) {
        $service = $services | Where-Object { $_.Name -eq $name }

        if ($null -ne $service) {

            if ($service.Status.ToString() -ne "Running" -or
                $service.StartType.ToString() -eq "Disabled") {
                "Critical Service '$name' Status: $($service.Status) StartType: $($service.StartType). Must be running and not disabled." | Receive-Output -IsWarning
            }
        }
    }
}