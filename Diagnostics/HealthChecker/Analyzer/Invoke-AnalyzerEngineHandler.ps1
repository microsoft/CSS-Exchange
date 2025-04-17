﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    This function handles how we need to call the Analyzer Engine. If that is done by a job or done on this main session.
#>
function Invoke-AnalyzerEngineHandler {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ServerDataCollection,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Legacy", "StartNow")]
        [string]$RunType
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $finalResultsProcessed = @{}
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    }
    process {
        if ($RunType -eq "Legacy") {
            foreach ($healthServerObject in $ServerDataCollection) {
                $singleServerStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
                $analyzedResults = Invoke-AnalyzerEngine -HealthServerObject $healthServerObject
                Write-Verbose "$($healthServerObject.ServerName) Analyzer Engine took $($singleServerStopWatch.Elapsed.TotalSeconds) seconds"
                $finalResultsProcessed.Add($healthServerObject.ServerName, $analyzedResults)
            }
        } else {
            foreach ($healthServerObject in $ServerDataCollection) {
            }
        }
    }
    end {
        Write-Verbose "Completed $($MyInvocation.MyCommand) and took $($stopWatch.Elapsed.TotalSeconds) seconds"
        return $finalResultsProcessed
    }
}
