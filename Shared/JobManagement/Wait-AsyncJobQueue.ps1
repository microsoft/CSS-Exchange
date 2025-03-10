# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\GetJobManagementFunctions.ps1

function Wait-AsyncJobQueue {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[string]]$AwaitJobId,

        [ScriptBlock]$ProcessReceiveJobAction
    )
    begin {
        $getAsyncJobQueue = Get-AsyncJobQueue

        if ($getAsyncJobQueue.Count -eq 0) {
            throw "No Async Jobs in queue"
        }

        $awaitFilterJobsOnly = $null -ne $AwaitJobId -and $AwaitJobId.count -gt 0
        $alreadyProcessJobs = New-Object System.Collections.Generic.List[string]
        $currentPossibleJobs = Get-Job
    }
    process {
        do {
            $completedJobs = $getAsyncJobQueue.Values | Where-Object { $_.Job.State -ne "Running" -and (-not ($alreadyProcessJobs.Contains($_.JobId))) }

            foreach ($jobInfo in $completedJobs) {
                $JobError = $null
                Write-Verbose "Attempting to receive job $($jobInfo.JobId)"

                if (-not ($currentPossibleJobs.Name.Contains($jobInfo.JobId))) {
                    Write-Verbose "Job was already removed, moving onto the next job."
                    $alreadyProcessJobs.Add($jobInfo.JobId)
                }

                $result = Receive-Job $jobInfo.Job -ErrorVariable "JobError"
                Write-Verbose "Successfully received the job"
                if ($null -ne $ProcessReceiveJobAction -and
                    $null -ne $result) {
                    $result = & $ProcessReceiveJobAction $result
                    Write-Verbose "Successfully processed job action $($jobInfo.JobId)"
                }

                $jobInfo.Results = $result
                $jobInfo.Error = $JobError
                $jobInfo.JobEndTime = [DateTime]::Now
                $timeTaken = $jobInfo.JobEndTime - $jobInfo.JobStartTime
                $psTimeTaken = $jobInfo.Job.PSEndTime - $jobInfo.Job.PSBeginTime
                Write-Verbose "Job $($jobInfo.JobId) took $($timeTaken.TotalSeconds) seconds and PS Job Time $($psTimeTaken.TotalSeconds)"
                $alreadyProcessJobs.Add($jobInfo.JobId)
                Remove-Job $jobInfo.Job -Force

                if ($AwaitJobId.Count -gt 0) {
                    $index = $AwaitJobId.IndexOf($jobInfo.JobId)

                    if ($index -ne -1) { $AwaitJobId.RemoveAt($index) }
                }
            }
            Start-Sleep -Milliseconds 100
            $continue = ($awaitFilterJobsOnly -and $AwaitJobId.Count -ne 0) -or
            ($null -ne ($getAsyncJobQueue.Values | Where-Object { $_.JobEndTime -eq [DateTime]::MinValue }))
        } while ($continue)
    }
}
