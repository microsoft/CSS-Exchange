# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-JobAnalyzerEngine.ps1
. $PSScriptRoot\..\..\..\Shared\JobManagementFunctions\GetJobManagementFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\JobManagementFunctions\Wait-JobQueue.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptBlockFunctions\RemoteSBLoggingFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptDebugFunctions.ps1

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
        [ValidateSet("CurrentSession", "StartNow")]
        [string]$RunType
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $finalResultsProcessed = @{}
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $progressAnalyzerParams = @{
            Activity        = "Setting up jobs to queue for analysis"
            ParentId        = 0
            Id              = 1
            Status          = [string]::Empty
            PercentComplete = -1
        }
        $analysisCounter = 1
    }
    process {
        if ($RunType -eq "CurrentSession") {
            foreach ($healthServerObject in $ServerDataCollection) {
                $singleServerStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
                $progressAnalyzerParams.Activity = "Analysis to execute in current PowerShell session"
                $progressAnalyzerParams.Status = "Executing analysis on $($healthServerObject.ServerName)"
                $progressAnalyzerParams.PercentComplete = ($analysisCounter++ / $ServerDataCollection.Count * 100)
                Write-Progress @progressAnalyzerParams
                $analyzedResults = Invoke-JobAnalyzerEngine -HealthServerObject $healthServerObject
                Write-Verbose "$($healthServerObject.ServerName) Analyzer Engine took $($singleServerStopWatch.Elapsed.TotalSeconds) seconds"
                $finalResultsProcessed.Add($healthServerObject.ServerName, $analyzedResults.HCAnalyzedResults)
            }
        } else {
            foreach ($healthServerObject in $ServerDataCollection) {
                $progressAnalyzerParams.Status = "Add job for Server $($healthServerObject.ServerName)"
                $progressAnalyzerParams.PercentComplete = ($analysisCounter++ / $ServerDataCollection.Count * 100)
                Write-Progress @progressAnalyzerParams
                Add-JobAnalyzerEngine -HealthServerObject $healthServerObject -ExecutingServer $healthServerObject.ServerName #TODO: Improve this logic
            }
            Wait-JobQueue -ProcessReceiveJobAction ${Function:Invoke-RemotePipelineLoggingLocal}
            $getJobQueueResult = Get-JobQueueResult
            Write-Verbose "Saving out the JobQueue"
            Add-DebugObject -ObjectKeyName "GetJobQueue-AfterDataCollection" -ObjectValueEntry ((Get-JobQueue).Clone())
            Write-Verbose "All servers to complete analyzed results $($stopWatch.Elapsed.TotalSeconds) seconds"

            foreach ($key in $getJobQueueResult.Keys) {
                $analyzedResults = $getJobQueueResult[$key].HCAnalyzedResults
                $serverName = $analyzedResults.HealthCheckerExchangeServer.ServerName
                $finalResultsProcessed.Add($serverName, $analyzedResults)
            }
        }
    }
    end {
        Write-Progress @progressAnalyzerParams -Completed
        Write-Verbose "Completed $($MyInvocation.MyCommand) and took $($stopWatch.Elapsed.TotalSeconds) seconds"
        return $finalResultsProcessed
    }
}
