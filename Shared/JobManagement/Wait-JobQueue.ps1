# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\GetJobManagementFunctions.ps1

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

function Wait-JobQueued {
    [CmdletBinding()]
    param(
        [int]$MaxJobsPerServer = 5
    )
    begin {

        function AddToRunList {
            param(
                [Parameter(Mandatory = $true)]
                $Job
            )

            if ($Job.JobCommand -eq "Invoke-Command") {
                $computerName = $Job.JobParameter.ComputerName

                if (-not ($jobsRunningPerServer.ContainsKey($computerName))) {
                    $jobsRunningPerServer.Add($computerName, 1)
                    return $true
                } elseif ($jobsRunningPerServer[$computerName] -le $MaxJobsPerServer) {
                    $jobsRunningPerServer[$computerName] += 1
                    return $true
                }
            } elseif ($Job.JobCommand -eq "Start-Job") {
                if (-not ($jobsRunningPerServer.ContainsKey($env:COMPUTERNAME))) {
                    $jobsRunningPerServer.Add($env:COMPUTERNAME, 1)
                } elseif ($jobsRunningPerServer[$env:COMPUTERNAME] -le $MaxJobsPerServer) {
                    $jobsRunningPerServer[$env:COMPUTERNAME] += 1
                    return $true
                }
            }
            return $false
        }

        $runningJobs = New-Object System.Collections.Generic.List[object]
        $maxJobsRunning = $false
        $jobsRunningPerServer = @{}
        $getJobQueue = Get-JobQueue

        if ($getJobQueue.Count -eq 0) {
            throw "No Jobs in Queue"
        }
    }
    process {
        do {
            # Check to see if we need to add any more jobs
            if ($getJobQueue.Count -gt 0 -and $maxJobsRunning -eq $false) {
                $jobsToAdd = New-Object System.Collections.Generic.Queue[object]
                # Filter on priority
                $highPriorityJobs = New-Object System.Collections.Generic.List[object]
                $normalPriorityJobs = New-Object System.Collections.Generic.List[object]
                $lowPriorityJobs = New-Object System.Collections.Generic.List[object]

                $getJobQueue.Values | Where-Object { $null -eq $_.Job } | ForEach-Object {
                    if ($_.Priority -eq "High") { $highPriorityJobs.Add($_) }
                    elseif ($_.Priority -eq "Normal") { $normalPriorityJobs.Add($_) }
                    elseif ($_.Priority -eq "Low") { $lowPriorityJobs.Add($_) }
                    else { throw "Unknown Priority Level" }
                }

                foreach ($highJob in $highPriorityJobs) {
                    if ((AddToRunList $highJob)) {
                        $jobsToAdd.Enqueue($highJob)
                    }
                }

                foreach ($normalJob in $normalPriorityJobs) {
                    if ((AddToRunList $normalJob)) {
                        $jobsToAdd.Enqueue($normalJob)
                    }
                }

                foreach ($lowJob in $lowPriorityJobs) {
                    if ((AddToRunList $lowJob)) {
                        $jobsToAdd.Enqueue($lowJob)
                    }
                }

                # Kick off what is in the jobsToAdd queue
                while ($jobsToAdd.Count -gt 0) {
                    $currentJob = $jobsToAdd.Dequeue()
                    $jobCommand = $currentJob.JobCommand
                    $jobParameter = $currentJob.JobParameter

                    if ($jobCommand -eq "Invoke-Command") {
                        $jobParameter["AsJob"] = $true
                    }
                    Write-Verbose "Starting to execute job '$($currentJob.JobId)'"

                    $newJob = & $jobCommand @JobParameter
                    $jobInfo = $getJobQueue.Values | Where-Object { $_.JobId -eq $currentJob.JobId }
                    $jobInfo.Job = $newJob
                    $jobInfo.JobStartTime = [DateTime]::Now
                    $runningJobs.Add($jobInfo)
                }
            }

            # Check all the current jobs running to see if they have finished
            $nonRunningJobs = @($runningJobs | Where-Object { $_.Job.State -ne "Running" } )

            if ($nonRunningJobs.Count -gt 0) {
                foreach ($jobInfo in $nonRunningJobs) {
                    $JobError = $null
                    $result = Receive-Job $jobInfo.Job -ErrorVariable "JobError"
                    $jobInfo.Results = $result
                    $jobInfo.Error = $JobError
                    $jobInfo.JobEndTime = [DateTime]::Now
                    Remove-Job $jobInfo.Job -Force
                    $runningJobs.Remove($jobInfo)

                    if ($jobInfo.JobCommand -eq "Start-Job") {
                        $jobsRunningPerServer[$env:COMPUTERNAME] += -1
                    } else {
                        $jobsRunningPerServer[$jobInfo.Job.Location] += -1
                    }
                }
            }

            Start-Sleep 1
            $continue = $null -ne ($getJobQueue.Values | Where-Object { $_.JobEndTime -eq [DateTime]::MinValue })
        } while ($continue -or $runningJobs.Count -gt 0)
    }
}
