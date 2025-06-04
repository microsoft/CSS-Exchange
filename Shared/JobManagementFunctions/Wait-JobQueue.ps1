# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\GetJobManagementFunctions.ps1
. $PSScriptRoot\Invoke-TryStartJobQueue.ps1

<#
.SYNOPSIS
    Executes and waits for all the jobs in the queue to process
.DESCRIPTION
    From all the jobs that were added to the queue from Add-JobQueue, it will attempt to execute all the jobs and store them back in the hashtable
    This is the function that you call to execute a batch of jobs that you wish to complete before moving onto the next job.
#>

function Wait-JobQueue {
    [CmdletBinding()]
    param(
        [int]$MaxJobsPerServer = 5,

        [ScriptBlock]$ProcessReceiveJobAction
    )
    begin {

        $getJobQueue = Get-JobQueue

        if ($getJobQueue.Count -eq 0) {
            throw "No Jobs in Queue"
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $stopwatchMain = [System.Diagnostics.Stopwatch]::StartNew()
    }
    process {
        do {
            # Check to see if we need to add any more jobs
            $tryStartJobQueue = $null -ne ($getJobQueue.Values | Where-Object { $null -eq $_.Job })

            if ($tryStartJobQueue) {
                Invoke-TryStartJobQueue
            }

            [array]$completedJobs = $getJobQueue.Values | Where-Object { $null -ne $_.Job -and $_.JobEndTime -ne [DateTime]::MinValue -and $_.Job.State -eq "Completed" }
            [array]$completedJobsToProcess = $getJobQueue.Values | Where-Object { $null -ne $_.Job -and $_.JobEndTime -eq [DateTime]::MinValue -and $_.Job.State -ne "Running" }

            $jobQueueProgressParams = @{
                Activity         = "Waiting for $($getJobQueue.Values.Count) Total Jobs to Complete"
                Status           = "$($completedJobs.Count) jobs completed. Running for $($stopwatchMain.Elapsed.TotalSeconds) seconds."
                CurrentOperation = [string]::Empty
                ParentId         = 0
                Id               = 1
                PercentComplete  = ($completedJobs.Count * 100 / $getJobQueue.Values.Count)
            }

            if ($completedJobsToProcess.Count -eq 0) {
                Write-Progress @jobQueueProgressParams
            } else {
                $jobReceivedCompleted = 0
                foreach ($jobInfo in $completedJobsToProcess) {
                    $JobError = $null
                    $jobReceivedCompleted++
                    $jobQueueProgressParams.CurrentOperation = "Receiving Job '$($jobInfo.JobId)' $jobReceivedCompleted of $($completedJobsToProcess.Count)"
                    Write-Progress @jobQueueProgressParams

                    Write-Verbose "Attempting to receive job $($jobInfo.JobId)"
                    $jobInfo.JobEndTime = [DateTime]::Now
                    $receiveJobStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
                    $result = Receive-Job $jobInfo.Job -ErrorVariable "JobError"
                    Write-Verbose "Receive-Job took $($receiveJobStopWatch.Elapsed.TotalSeconds) seconds to complete"

                    if ($jobInfo.Job.ChildJobs.Progress.Count -gt 1) {
                        $lastProgress = $jobInfo.Job.ChildJobs.Progress | Select-Object -Last 1
                        if ($lastProgress) {
                            Write-Progress -Activity $lastProgress.Activity -ParentId 1 -Id ($jobInfo.Job.Id + 1) -Completed
                        }
                    }

                    Write-Verbose "Successfully received the job"

                    if ($null -ne $ProcessReceiveJobAction -and
                        $null -ne $result) {
                        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
                        $result = & $ProcessReceiveJobAction $result
                        Write-Verbose "Successfully processed job action $($jobInfo.JobId) and took $($stopWatch.Elapsed.TotalSeconds) seconds"
                    }

                    $jobInfo.Results = $result
                    $jobInfo.Error = $JobError
                    $timeTaken = $jobInfo.JobEndTime - $jobInfo.JobStartTime
                    $psTimeTaken = $jobInfo.Job.PSEndTime - $jobInfo.Job.PSBeginTime
                    Write-Verbose "Job $($jobInfo.JobId) took $($timeTaken.TotalSeconds) seconds for when the job start to when it was received"
                    Write-Verbose "The PS Job Time took $($psTimeTaken.TotalSeconds) seconds for when the job was created to completed"
                    Write-Verbose "Difference between the times $($timeTaken - $psTimeTaken)"
                    Remove-Job $jobInfo.Job -Force
                }
            }

            Start-Sleep 1
            $continue = $null -ne ($getJobQueue.Values | Where-Object { $_.JobEndTime -eq [DateTime]::MinValue })
        } while ($continue)
        Write-Progress @jobQueueProgressParams -Completed
        Write-Verbose "End $($MyInvocation.MyCommand) and took $($stopwatchMain.Elapsed.TotalSeconds) seconds"
    }
}
