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
    [switch]
    $IncludeThread,

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
            [bool]
            $IncludeThread,

            [Parameter(Mandatory = $true, Position = 5)]
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

        $counters = (Get-Counter -ListSet * | Sort-Object CounterSetName)

        $defaultIncludeList = @(
            "^.NET CLR .+",
            "^APP_POOL_WAS",
            "^ASP.NET.+",
            "^HTTP Service Request Queues",
            "^LogicalDisk",
            "^Memory",
            "^MSExchange.+",
            "^Microsoft Exchange .+",
            "^Netlogon",
            "^Network Interface",
            "^Paging File",
            "^PhysicalDisk",
            "^Process",
            "^RPC/HTTP .+",
            "^Server",
            "^System",
            "^TCPv.",
            "^W3SVC_W3WP",
            "^WAS_W3WP",
            "^Web Service",
            "^VM Memory",
            "^VM Processor"
        )

        if ($IncludeThread) {
            $defaultIncludeList += "^Thread"
        }

        $countersFiltered = $defaultIncludeList | ForEach-Object { $regexString = $_; $counters | Where-Object { $_.CounterSetName -match $regexString } }

        $counterFullNames = $countersFiltered | ForEach-Object { ("\\localhost\" + $_.CounterSetName + $(if ($_.CounterSetType -eq "MultiInstance") { "(*)" } else { "" }) + "\*") }

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
                Invoke-Command -ComputerName $computer -ScriptBlock ${function:StartSimplePerf} -ArgumentList $Duration, $Interval, $MaximumSizeInMB, $OutputFolder, $IncludeThread, $Circular
            } elseif ($Stop) {
                Invoke-Command -ComputerName $computer -ScriptBlock ${function:StopSimplePerf}
            }
        }
    } else {
        if ($Start) {
            StartSimplePerf -Duration $Duration -Interval $Interval -MaximumSizeInMB $MaximumSizeInMB -OutputFolder $OutputFolder -IncludeThread $IncludeThread -Circular $Circular
        } else {
            StopSimplePerf
        }
    }
}
