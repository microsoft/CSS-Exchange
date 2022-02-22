# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function GetScenarioDefaults {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = "Include")]
        [Parameter(ParameterSetName = "Exclude")]
        [ValidateSet("None", "Exchange")]
        [string]
        $Scenario,

        [Parameter(ParameterSetName = "Include")]
        [switch]
        $Include,

        [Parameter(ParameterSetName = "Exclude")]
        [switch]
        $Exclude
    )

    begin {
        $scenarios = @{
            None     = @{
                Include = @()
                Exclude = @()
            }

            Exchange = @{
                Include = @(
                    "\.NET CLR Exceptions",
                    "\.NET CLR Memory",
                    "\.NET CLR Loading",
                    "\.NET CLR LocksAndThreads(*)\Contention Rate / sec",
                    "\APP_POOL_WAS",
                    "\ASP.NET",
                    "\HTTP Service Request Queues",
                    "\LogicalDisk",
                    "\Memory\",
                    "\MSExchange",
                    "\Microsoft Exchange",
                    "\Netlogon",
                    "\Network Interface",
                    "\Paging File",
                    "\PhysicalDisk",
                    "\Process",
                    "\RPC/HTTP Proxy",
                    "\Server\",
                    "\System\Context Switches/sec",
                    "\System\Processor Queue Length",
                    "\TCPv4",
                    "\TCPv6",
                    "\W3SVC_W3WP",
                    "\WAS_W3WP",
                    "\Web Service",
                    "\VM Memory",
                    "\VM Processor"
                )

                Exclude = @(
                    "\ASP.NET State Service",
                    "\MSExchange AD Forest Performance",
                    "\MSExchange AD Performance",
                    "\MSExchange AdfsAuth",
                    "\MSExchange CertificateAuthentication",
                    "\MSExchange Cfm Submission",
                    "\MSExchange ConsumerEasAuthentication",
                    "\MSExchange Content Classification",
                    "\MSExchange Database ==> Databases",
                    "\MSExchange Delivery ClientSubmissionAuthInBackendFailures",
                    "\MSExchange Delivery ControlFlow",
                    "\MSExchange Delivery Extensibility Runtimes",
                    "\MSExchange Delivery HttpReceive",
                    "\MSExchange Delivery SmtpErrors",
                    "\MSExchange Delivery SmtpReceivePerformance",
                    "\MSExchange Delivery SmtpResponseCode",
                    "\MSExchange Distributed Store",
                    "\MSExchange DlpPolicyTips",
                    "\MSExchange DxStore Server",
                    "\MSExchange Dynamic Attachment Time-Based Assistant",
                    "\MSExchange FBL",
                    "\MSExchange File Extraction",
                    "\MSExchange GoLocal",
                    "\MSExchange Http ",
                    "\MSExchange Hygiene Scan Engine",
                    "\MSExchange IIS Return Code",
                    "\MSExchange Infoworker Configuration Cache",
                    "\MSExchange Item Assistants",
                    "\MSExchange LAM Event",
                    "\MSExchange Mailbox Load Balancing",
                    "\MSExchange Meeting Series Message Ordering",
                    "\MSExchange MultiMailboxSearch",
                    "\MSExchange Notifications Broker",
                    "\MSExchange Owa Configuration Cache",
                    "\MSExchange Protocol Command Availability",
                    "\MSExchange Realtime Analytics Job",
                    "\MSExchange Routing",
                    "\MSExchange RPC Entry Points",
                    "\MSExchange Shared",
                    "\MSExchange Submission Extensibility Runtimes",
                    "\MSExchange Submission service",
                    "\MSExchange Submission SmtpErrors",
                    "\MSExchange Submission Store Driver Direct Delivery",
                    "\MSExchange Supervisory Review",
                    "\MSExchange Task Distribution",
                    "\MSExchange Unified",
                    "\MSExchange Weve Message",
                    "\MSExchangeCAR",
                    "\MSExchangeDelivery Throttling",
                    "\MSExchangeFrontEndTransport Extensibility Runtimes",
                    "\MSExchangeFrontEndTransport SmtpErrors",
                    "\MSExchangeFrontEndTransport SmtpReceivePerformance",
                    "\MSExchangeFrontEndTransport SmtpResponseCode",
                    "\MSExchangeTransport CatProcessor",
                    "\MSExchangeTransport CFM",
                    "\MSExchangeTransport Configuration\",
                    "\MSExchangeTransport ControlFlow",
                    "\MSExchangeTransport DSApiClient",
                    "\MSExchangeTransport E2E Latency SLA",
                    "\MSExchangeTransport Extensibility Runtimes",
                    "\MSExchangeTransport HTTP",
                    "\MSExchangeTransport MessageDepot",
                    "\MSExchangeTransport Poison Messages",
                    "\MSExchangeTransport Processing Scheduler",
                    "\MSExchangeTransport Queued Recipients By Traffic Type",
                    "\MSExchangeTransport Queues Cfm",
                    "\MSExchangeTransport Replication",
                    "\MSExchangeTransport Request Broker",
                    "\MSExchangeTransport ResourceThrottling",
                    "\MSExchangeTransport SmtpErrors",
                    "\MSExchangeTransport SmtpReceivePerformance",
                    "\MSExchangeTransport SmtpResponseCode",
                    "\MSExchangeTransport Storage RESTAPI"
                )
            }
        }
    }

    process {
        if ($Include) {
            return $scenarios[$Scenario].Include
        } else {
            return $scenarios[$Scenario].Exclude
        }
    }
}
