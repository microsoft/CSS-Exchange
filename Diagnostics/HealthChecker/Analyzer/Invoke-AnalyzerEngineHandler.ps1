# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-JobAnalyzerEngine.ps1
. $PSScriptRoot\..\Helpers\HiddenJobUnhandledErrorFunctions.ps1
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

        function InvokeRemoteAnalyzerCatchActions {
            param(
                [object]$CurrentError = $Error[0]
            )
            if ($CurrentError.Exception -is [System.Management.Automation.Remoting.PSRemotingTransportException] -or
                $CurrentError.Exception.StackTrace -is [System.Management.Automation.Remoting.PSRemotingTransportException]) {
                # This would be is if we can't send the payload remotely, we are going to "handle" this and not have customers report it.
                Invoke-CatchActions $CurrentError
            } else {
                Write-Verbose "Exception didn't match. Exception: $($CurrentError.Exception) StackTrace: $($CurrentError.Exception.StackTrace)"
            }
        }

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
                try {
                    $singleServerStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
                    $progressAnalyzerParams.Activity = "Analysis to execute in current PowerShell session"
                    $progressAnalyzerParams.Status = "Executing analysis on $($healthServerObject.ServerName)"
                    $progressAnalyzerParams.PercentComplete = ($analysisCounter++ / $ServerDataCollection.Count * 100)
                    Write-Progress @progressAnalyzerParams
                    $analyzedResults = Invoke-JobAnalyzerEngine -HealthServerObject $healthServerObject
                    Write-Verbose "$($healthServerObject.ServerName) Analyzer Engine took $($singleServerStopWatch.Elapsed.TotalSeconds) seconds"
                    $finalResultsProcessed.Add($healthServerObject.ServerName, $analyzedResults.HCAnalyzedResults)
                } catch {
                    Invoke-CatchActions
                    # Use Write-Error to bubble up the error to us.
                    Write-Error "Failed to process $($healthServerObject.ServerName) for analysis"
                }
            }
        } else {
            # Initial Attempt of executing the jobs on the server the data was collected from. There is a chance this can fail due to the object being too large.
            foreach ($healthServerObject in $ServerDataCollection) {
                $progressAnalyzerParams.Status = "Add job for Server $($healthServerObject.ServerName)"
                $progressAnalyzerParams.PercentComplete = ($analysisCounter++ / $ServerDataCollection.Count * 100)
                Write-Progress @progressAnalyzerParams
                # We are going to attempt to execute the analyzer on the server the data came from. This way we can start up a lot of jobs all at the same time and be done quickly.
                Add-JobAnalyzerEngine -HealthServerObject $healthServerObject -ExecutingServer $healthServerObject.ServerName
            }
            Wait-JobQueue -ProcessReceiveJobAction ${Function:Invoke-RemotePipelineLoggingLocal} -CatchActionFunction ${Function:InvokeRemoteAnalyzerCatchActions}
            $getJobQueueResult = Get-JobQueueResult
            Write-Verbose "Saving out the JobQueue"
            Add-DebugObject -ObjectKeyName "GetJobQueue-AfterDataCollection" -ObjectValueEntry ((Get-JobQueue).Clone())
            $noResults = $getJobQueueResult.Keys | Where-Object { $null -eq $getJobQueueResult[$_] }
            $getJobQueueResult.Values | Where-Object { $null -ne $_ } | Invoke-HiddenJobUnhandledErrors

            if ($null -ne $noResults) {
                # We have had some results fail.
                Write-Verbose "Analyzer failed for the following servers: $([string]::Join(", ", [array]$noResults))"
                $getJobQueueClone = (Get-JobQueue).Clone()

                # To speed up this process, we should attempt to do local jobs.
                if ($noResults.Count -ge 3) {
                    Clear-JobQueue
                    $analysisCounter = 1
                    foreach ($failedJobKey in $noResults) {
                        $serverName = $getJobQueueClone[$failedJobKey].JobParameter.ArgumentList.ServerName
                        $progressAnalyzerParams.Status = "Add job for Server $serverName to retry locally"
                        $progressAnalyzerParams.PercentComplete = ($analysisCounter++ / $noResults.Count * 100)
                        Write-Progress @progressAnalyzerParams
                        Add-JobAnalyzerEngine -HealthServerObject $getJobQueueClone[$failedJobKey].JobParameter.ArgumentList -ExecutingServer $env:COMPUTERNAME
                    }
                    Wait-JobQueue -ProcessReceiveJobAction ${Function:Invoke-RemotePipelineLoggingLocal} -CatchActionFunction ${Function:InvokeRemoteAnalyzerCatchActions}
                    $getJobQueueResult2 = Get-JobQueueResult
                    $getJobQueueResult2.Keys | ForEach-Object { $getJobQueueResult[$_] = $getJobQueueResult2[$_] }
                    $getJobQueueResult2.Values | Where-Object { $null -ne $_ } | Invoke-HiddenJobUnhandledErrors
                    $noResults = $getJobQueueResult.Keys | Where-Object { $null -eq $getJobQueueResult[$_] }
                    Add-DebugObject -ObjectKeyName "GetJobQueue-AfterDataCollectionLocalAttempt" -ObjectValueEntry ((Get-JobQueue).Clone())
                }

                if ($null -ne $noResults) {
                    Write-Verbose "Analyzer failed for the following servers on the local server: $([string]::Join(", ", [array]$noResults))"
                    $getJobQueue = Get-JobQueue
                    $analysisCounter = 1
                    $progressAnalyzerParams.Activity = "Analysis to execute in current PowerShell session"
                    foreach ($failedJobKey in $noResults) {
                        try {
                            $serverName = $getJobQueue[$failedJobKey].JobParameter.ArgumentList.ServerName
                            Write-Verbose "Working on Server $serverName"
                            $progressAnalyzerParams.Status = "Executing analysis on $serverName"
                            $progressAnalyzerParams.PercentComplete = ($analysisCounter++ / $noResults.Count * 100)
                            Write-Progress @progressAnalyzerParams
                            $singleServerStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
                            $analyzedResults = Invoke-JobAnalyzerEngine -HealthServerObject $getJobQueue[$failedJobKey].JobParameter.ArgumentList
                            Write-Verbose "$serverName Analyzer Engine took $($singleServerStopWatch.Elapsed.TotalSeconds) seconds"
                            $finalResultsProcessed.Add($serverName, $analyzedResults.HCAnalyzedResults)
                        } catch {
                            Invoke-CatchActions
                            # Use Write-Error to bubble up the error to us.
                            Write-Error "Failed to process $serverName for analysis"
                        }
                    }
                }
            }
            Write-Verbose "All servers to complete analyzed results $($stopWatch.Elapsed.TotalSeconds) seconds"

            foreach ($key in $getJobQueueResult.Keys) {
                if ( $null -eq $getJobQueueResult[$key]) {
                    # Skip over jobs that are null out.
                    continue
                }
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
