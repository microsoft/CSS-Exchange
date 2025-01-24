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
    TODO:
        Add in logic for Write-Progress, we want to know how many jobs are running and a summary of what they are.
        Improve the debug logic here
        Add in timeout logic to timeout job requests
        Add in logic for maxJobsRunning
        Add in Read ME page for this section of code
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
    }
    process {
        do {
            # Check to see if we need to add any more jobs
            $tryStartJobQueue = $null -ne ($getJobQueue.Values | Where-Object { $null -eq $_.Job })

            if ($tryStartJobQueue) {
                Invoke-TryStartJobQueue
            }

            # Check all the current jobs running to see if they have finished
            [array]$completedJobsToProcess = $getJobQueue.Values | Where-Object { $null -ne $_.Job -and $_.JobEndTime -eq [DateTime]::MinValue  -and $_.Job.State -ne "Running" }

            if ($completedJobsToProcess.Count -gt 0) {
                foreach ($jobInfo in $completedJobsToProcess) {
                    $JobError = $null
                    Write-Verbose "Attempting to receive job $($jobInfo.JobId)"
                    $jobInfo.JobEndTime = [DateTime]::Now
                    $result = Receive-Job $jobInfo.Job -ErrorVariable "JobError"
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
    }
}
