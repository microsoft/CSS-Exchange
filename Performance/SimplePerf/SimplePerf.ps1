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
    [ValidateSet("None", "Exchange")]
    [string]
    $Scenario = "Exchange",

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
    . $PSScriptRoot\Scenarios.ps1

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
            $ScenarioIncludeList,

            [Parameter(Mandatory = $true, Position = 5)]
            [AllowEmptyCollection()]
            [string[]]
            $ScenarioExcludeList,

            [Parameter(Mandatory = $true, Position = 6)]
            [AllowEmptyCollection()]
            [string[]]
            $IncludeCounters,

            [Parameter(Mandatory = $true, Position = 7)]
            [AllowEmptyCollection()]
            [string[]]
            $ExcludeCounters,

            [Parameter(Mandatory = $true, Position = 8)]
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

        $counterSets = Get-Counter -ListSet * | Sort-Object CounterSetName

        Write-Host "$($env:COMPUTERNAME): Applying filters."

        $countersFiltered = New-Object 'System.Collections.Generic.HashSet[string]'

        foreach ($set in $counterSets) {
            $counters = $set.Counter
            $matchingCounters = New-Object 'System.Collections.Generic.HashSet[string]'

            for ($i = 0; $i -lt $counters.Count; $i++) {
                $userExclude = $false
                foreach ($simpleMatchString in $ExcludeCounters) {
                    if ($counters[$i].StartsWith($simpleMatchString, "OrdinalIgnoreCase")) {
                        $userExclude = $true
                        break
                    }
                }

                if ($userExclude) {
                    continue
                }

                $userInclude = $false
                foreach ($simpleMatchString in $IncludeCounters) {
                    if ($counters[$i].StartsWith($simpleMatchString, "OrdinalIgnoreCase")) {
                        $userInclude = $true
                        break
                    }
                }

                if ($userInclude) {
                    [void]$matchingCounters.Add($counters[$i])
                }

                $defaultExclude = $false
                foreach ($simpleMatchString in $ScenarioExcludeList) {
                    if ($counters[$i].StartsWith($simpleMatchString, "OrdinalIgnoreCase")) {
                        $defaultExclude = $true
                        break
                    }
                }

                if ($defaultExclude) {
                    continue
                }

                $defaultInclude = $false
                foreach ($simpleMatchString in $ScenarioIncludeList) {
                    if ($counters[$i].StartsWith($simpleMatchString, "OrdinalIgnoreCase")) {
                        $defaultInclude = $true
                        break
                    }
                }

                if ($defaultInclude) {
                    [void]$matchingCounters.Add($counters[$i])
                }
            }

            if ($matchingCounters.Count -gt 0) {
                if ($matchingCounters.Count -eq $set.Counter.Count) {
                    [void]$countersFiltered.Add("\" + $set.CounterSetName + $(if ($set.CounterSetType -eq "MultiInstance") { "(*)" } else { "" }) + "\*")
                } else {
                    $countersFiltered.UnionWith($matchingCounters)
                }
            }
        }

        $counterFullNames = $countersFiltered | ForEach-Object { ("\\localhost" + $_) }

        $counterFullNames | ForEach-Object { Write-Verbose $_ }

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

    $argumentList = @(
        $Duration,
        $Interval,
        $MaximumSizeInMB,
        $OutputFolder,
        $(if ($null -ne $Scenario -and $Scenario -ne "None") { GetScenarioDefaults -Scenario $Scenario -Include } else { @() }),
        $(if ($null -ne $Scenario -and $Scenario -ne "None") { GetScenarioDefaults -Scenario $Scenario -Exclude } else { @() }),
        $IncludeCounters,
        $ExcludeCounters,
        $Circular
    )

    if ($computerTargets.Length -gt 0) {
        foreach ($computer in $computerTargets) {
            if ($Start) {
                Invoke-Command -ComputerName $computer -ScriptBlock ${function:StartSimplePerf} -ArgumentList $argumentList
            } elseif ($Stop) {
                Invoke-Command -ComputerName $computer -ScriptBlock ${function:StopSimplePerf}
            }
        }
    } else {
        if ($Start) {
            StartSimplePerf @argumentList
        } else {
            StopSimplePerf
        }
    }
}
