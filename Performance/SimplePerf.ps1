# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Simple performance log collector for Exchange.
.DESCRIPTION
    SimplePerf is a performance log collector for Exchange with the primary
    goal being simplicity. There are very few options and only two valid
    commands, -Start and -Stop.
.EXAMPLE
    PS C:\> .\SimplePerf.ps1 -Start
    Starts a non-circular data collector that will run for 8 hours, with a
    5-second interval, and a max file size of 1 GB, saving the logs to C:\SimplePerf.
.EXAMPLE
    PS C:\> .\SimplePerf.sp1 -Start -Duration 02:00:00 -Interval 30 -MaximumSizeInMB 512 -OutputPath C:\PerfLogs
    Starts a non-circular data collector that will run for 2 hours, with a
    30-second interval, a max file size of 512 MB, saving the logs to C:\PerfLogs.
.EXAMPLE
    PS C:\> .\SimplePerf.ps1 -Stop
    Stops a running SimplePerf.
.EXAMPLE
    PS C:\> Get-ExchangeServer | .\SimplePerf.ps1 -Start
    Starts a SimplePerf with the default options on all Exchange servers.
.EXAMPLE
    PS C:\> "SRV1", "SRV2", "SRV3" | .\SimplePerf.ps1 -Start
    Starts a SimplePerf with the default options on the three named servers.
.EXAMPLE
    PS C:\> "SRV1", "SRV2", "SRV3" | .\SimplePerf.ps1 -Stop
    Stops a running SimplePerf on the three named servers.
#>
[CmdletBinding(DefaultParameterSetName = "Start")]
param (
    [Parameter(ParameterSetName = "Start", ValueFromPipeline = $true)]
    [Parameter(ParameterSetName = "Stop", ValueFromPipeline = $true)]
    [string[]]
    $ComputerName,

    [Parameter(ParameterSetName = "Start")]
    [switch]
    $Start,

    [Parameter(ParameterSetName = "Start")]
    [string]
    $Duration = "8:00:00",

    [Parameter(ParameterSetName = "Start")]
    [string]
    $Interval = "00:00:05",

    [Parameter(ParameterSetName = "Start")]
    [int]
    $MaximumSizeInMB = 1024,

    [Parameter(ParameterSetName = "Start")]
    [string]
    $OutputFolder = "C:\SimplePerf\",

    [Parameter(ParameterSetName = "Start")]
    [string[]]
    $IncludeCounters = @(),

    [Parameter(ParameterSetName = "Start")]
    [string[]]
    $ExcludeCounters = @(),

    [Parameter(ParameterSetName = "Start")]
    [switch]
    $Circular,

    [Parameter(ParameterSetName = "Stop")]
    [switch]
    $Stop
)

begin {
    function StartSimplePerf {
        param (
            [Parameter(Mandatory = $true, Position = 0)]
            [string]
            $Duration,

            [Parameter(Mandatory = $true, Position = 1)]
            [string]
            $Interval,

            [Parameter(Mandatory = $true, Position = 2)]
            [int]
            $MaximumSizeInMB,

            [Parameter(Mandatory = $true, Position = 3)]
            [string]
            $OutputFolder,

            [Parameter(Mandatory = $true, Position = 4)]
            [AllowEmptyCollection()]
            [string[]]
            $IncludeCounters,

            [Parameter(Mandatory = $true, Position = 5)]
            [AllowEmptyCollection()]
            [string[]]
            $ExcludeCounters,

            [Parameter(Mandatory = $true, Position = 6)]
            [bool]
            $Circular
        )

        $statusMatch = logman | Select-String "SimplePerf.*(Running|Stopped)"
        if ($null -ne $statusMatch) {
            if ($statusMatch.Matches.Groups[1].Value -eq "Running") {
                Write-Host "$($env:COMPUTERNAME): SimplePerf is already running."
                return
            } else {
                Write-Host "$($env:COMPUTERNAME): Removing existing SimplePerf collector."
                logman delete "SimplePerf"
            }
        }

        Write-Host "$($env:COMPUTERNAME): Getting list of counters."

        $counters = (Get-Counter -ListSet *).Counter | Sort-Object

        $defaultIncludeList = @(
            "\.NET CLR Exceptions",
            "\.NET CLR Memory",
            "\.NET CLR Loading",
            "\.NET CLR LocksAndThreads(*)\Contention Rate / sec",
            "\APP_POOL_WAS",
            "\ASP.NET\",
            "\ASP.NET Applications",
            "\ASP.NET Apps v4.0",
            "\ASP.NET v4.0",
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

        $defaultExcludeList = @(
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

        Write-Host "$($env:COMPUTERNAME): Applying filters."

        $countersFiltered = New-Object 'System.Collections.Generic.HashSet[string]'

        # Include everything from the default list.
        foreach ($counter in $counters) {
            foreach ($simpleMatchString in $defaultIncludeList) {
                if ($counter.StartsWith($simpleMatchString, "OrdinalIgnoreCase")) {
                    [void]$countersFiltered.Add($counter)
                }
            }
        }

        # Apply the default exclusions.
        foreach ($excludeString in $defaultExcludeList) {
            [void]$countersFiltered.RemoveWhere({ param($c) $c.StartsWith($excludeString, "OrdinalIgnoreCase") })
        }

        # Now add any user-specified inclusions. This is done after the default exclusions so that the user can override the default exclusions.
        foreach ($simpleMatchString in $IncludeCounters) {
            $counters -like "$($simpleMatchString)*" | ForEach-Object { [void]$countersFiltered.Add($_) }
        }

        # Now apply the user-specified exclusions, which override everything else.
        foreach ($excludeString in $ExcludeCounters) {
            [void]$countersFiltered.RemoveWhere({ param($c) $c.StartsWith($excludeString, "OrdinalIgnoreCase") })
        }

        $counterFullNames = $countersFiltered | ForEach-Object { ("\\localhost\" + $_) } | Sort-Object

        $counterFile = (Join-Path $env:TEMP "counters.txt")

        $counterFullNames | Out-File $counterFile

        $OutputFolder = Join-Path $OutputFolder ([DateTime]::Now.ToString("yyMMddhhmmss"))

        Write-Host "$($env:COMPUTERNAME): Creating SimplePerf collector, writing to $OutputFolder."

        [IO.Directory]::CreateDirectory($OutputFolder) | Out-Null

        $OutputFile = "SimplePerf-" + $env:COMPUTERNAME + ".blg"

        if ($Circular) {
            logman create counter -n "SimplePerf" -cf $counterFile -rf $Duration -si $Interval -max $MaximumSizeInMB -o (Join-Path $OutputFolder $OutputFile) -f bincirc
        } else {
            logman create counter -n "SimplePerf" -cf $counterFile -rf $Duration -si $Interval -max $MaximumSizeInMB -o (Join-Path $OutputFolder $OutputFile) -f bin -cnf 0
        }

        Write-Host "$($env:COMPUTERNAME): Starting SimplePerf collector."

        logman start "SimplePerf"
    }

    function StopSimplePerf {
        Write-Host "$($env:COMPUTERNAME): Stopping SimplePerf."
        logman stop "SimplePerf"
    }

    $computerTargets = New-Object System.Collections.ArrayList
}

process {
    foreach ($computer in $ComputerName) {
        [void]$computerTargets.Add($computer)
    }
}

end {
    if (-not $Start -and -not $Stop) {
        Write-Host "Either -Start or -Stop must be specified."
        return
    }

    if ($computerTargets.Length -gt 0) {
        foreach ($computer in $computerTargets) {
            if ($Start) {
                Invoke-Command -ComputerName $computer -ScriptBlock ${function:StartSimplePerf} -ArgumentList $Duration, $Interval, $MaximumSizeInMB, $OutputFolder, $IncludeCounters, $ExcludeCounters, $Circular
            } elseif ($Stop) {
                Invoke-Command -ComputerName $computer -ScriptBlock ${function:StopSimplePerf}
            }
        }
    } else {
        if ($Start) {
            StartSimplePerf -Duration $Duration -Interval $Interval -MaximumSizeInMB $MaximumSizeInMB -OutputFolder $OutputFolder -IncludeCounters $IncludeCounters -ExcludeCounters $ExcludeCounters -Circular $Circular
        } else {
            StopSimplePerf
        }
    }
}
