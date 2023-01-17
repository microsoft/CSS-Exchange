# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Simple performance log collector.
.DESCRIPTION
    SimplePerf is a performance log collector with the primary
    goal being simplicity.
.EXAMPLE
    PS C:\> .\SimplePerf.ps1 -Start
    Starts a collector using Exchange counter defaults. The collector is non-circular, will run for 8 hours, has a
    5-second interval, has a max file size of 1 GB, and saves the logs to C:\SimplePerf.
.EXAMPLE
    PS C:\> .\SimplePerf.ps1 -Start -IncludeCounters "\Thread"
    Starts a collector using Exchange counter defaults plus all \Thread counters. The collector is non-circular,
    will run for 8 hours, has a 5-second interval, has a max file size of 1 GB, and saves the logs to C:\SimplePerf.
.EXAMPLE
    PS C:\> .\SimplePerf.ps1 -Start -Duration 02:00:00 -Interval 30 -MaximumSizeInMB 512 -OutputFolder C:\PerfLogs
    Starts a collector using Exchange counter defaults. The collector is non-circular, will run for 2 hours, has a
    30-second interval, has a max file size of 512 MB, and saves the logs to C:\PerfLogs.
.EXAMPLE
    PS C:\> .\SimplePerf.ps1 -Start -Duration 02:00:00 -Interval 30 -MaximumSizeInMB 1024 -Circular -OutputFolder C:\PerfLogs
    Starts a collector using Exchange counter defaults. The collector is circular, will run for 2 hours, has a
    30-second interval, has a max file size of 1024 MB, and saves the logs to C:\PerfLogs.
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
    $Stop,

    [Parameter(ParameterSetName = "Start")]
    [Parameter(ParameterSetName = "Stop")]
    [string]
    $CollectorName = ""
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
            $Circular,

            [Parameter(Mandatory = $true, Position = 9)]
            [AllowEmptyString()]
            [string]
            $CollectorName,

            [Parameter(Mandatory = $true, Position = 10)]
            [bool]
            $DisplayFilterResults
        )

        . $PSScriptRoot\GetCountersWithTranslations.ps1

        $dataCollectorSetList = New-Object -ComObject Pla.DataCollectorSetCollection
        $dataCollectorSetList.GetDataCollectorSets($null, $null)
        $existingSimplePerf = $dataCollectorSetList | Where-Object { $_.name -eq "SimplePerf$($CollectorName)" }
        if ($null -ne $existingSimplePerf) {
            if ($existingSimplePerf.Status -eq 1) {
                Write-Host "$($env:COMPUTERNAME): SimplePerf$($CollectorName) is already running."
                return
            } else {
                Write-Host "$($env:COMPUTERNAME): Removing existing SimplePerf$($CollectorName) collector."
                $existingSimplePerf.Delete()
            }

            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($dataCollectorSetList) | Out-Null
        }

        Write-Host "$($env:COMPUTERNAME): Getting list of counters."

        $counterSets = GetCountersWithTranslations

        Write-Host "$($env:COMPUTERNAME): Applying filters."

        $countersFiltered = New-Object 'System.Collections.Generic.HashSet[string]'

        foreach ($set in $counterSets) {
            $counters = $set.CounterEnglish
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
                    [void]$matchingCounters.Add($set.Counter[$i])
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
                    [void]$matchingCounters.Add($set.Counter[$i])
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

        if ($countersFiltered.Count -lt 1) {
            Write-Host "Filters resulted in 0 counters to collect."
            return
        }

        $counterFullNames = $countersFiltered | ForEach-Object { ("\\$env:COMPUTERNAME" + $_) }

        if ($DisplayFilterResults) {
            Write-Host "$($env:COMPUTERNAME): The following counters matched the specified filters:"
            $counterFullNames | ForEach-Object { Write-Host "$($env:COMPUTERNAME): $_" }
        }

        $counterFile = (Join-Path $env:TEMP "SimplePerf$($CollectorName)-counters.txt")

        $counterFullNames | Out-File $counterFile

        $OutputFolder = Join-Path $OutputFolder ("$($CollectorName)$([DateTime]::Now.ToString("yyMMddhhmmss"))")

        Write-Host "$($env:COMPUTERNAME): Creating SimplePerf$($CollectorName) collector, writing to $OutputFolder."

        [IO.Directory]::CreateDirectory($OutputFolder) | Out-Null

        $OutputFile = "SimplePerf$($CollectorName)-" + $env:COMPUTERNAME + ".blg"

        if ($Circular) {
            logman create counter -n "SimplePerf$($CollectorName)" -cf $counterFile -rf $Duration -si $Interval -max $MaximumSizeInMB -o (Join-Path $OutputFolder $OutputFile) -f bincirc
        } else {
            logman create counter -n "SimplePerf$($CollectorName)" -cf $counterFile -rf $Duration -si $Interval -max $MaximumSizeInMB -o (Join-Path $OutputFolder $OutputFile) -f bin -cnf 0
        }

        Write-Host "$($env:COMPUTERNAME): Starting SimplePerf$($CollectorName) collector."

        logman start "SimplePerf$($CollectorName)"
    }

    function StopSimplePerf {
        [CmdletBinding()]
        param (
            [Parameter(Position = 0)]
            [string]
            $CollectorName = ""
        )
        Write-Host "$($env:COMPUTERNAME): Stopping SimplePerf$($CollectorName)."
        logman stop "SimplePerf$($CollectorName)"
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

    if ($Scenario -eq "None" -and $IncludeCounters.Count -eq 0) {
        Write-Host "-IncludeCounters is required when Scenario is None."
        return
    }

    $argumentList = @(
        $Duration,
        $Interval,
        $MaximumSizeInMB,
        $OutputFolder,
        @(GetScenarioDefaults -Scenario $Scenario -Include),
        @(GetScenarioDefaults -Scenario $Scenario -Exclude),
        $IncludeCounters,
        $ExcludeCounters,
        $Circular,
        $CollectorName,
        $($VerbosePreference -ne 'SilentlyContinue')
    )

    if ($computerTargets.Length -gt 0) {
        foreach ($computer in $computerTargets) {
            if ($Start) {
                Invoke-Command -ComputerName $computer -ScriptBlock ${function:StartSimplePerf} -ArgumentList $argumentList
            } elseif ($Stop) {
                Invoke-Command -ComputerName $computer -ScriptBlock ${function:StopSimplePerf} -ArgumentList $CollectorName
            }
        }
    } else {
        if ($Start) {
            StartSimplePerf @argumentList
        } else {
            StopSimplePerf -CollectorName $CollectorName
        }
    }
}
