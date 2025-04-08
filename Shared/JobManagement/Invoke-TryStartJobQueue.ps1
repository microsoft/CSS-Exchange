﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\GetJobManagementFunctions.ps1

function Invoke-TryStartJobQueue {
    [CmdletBinding()]
    param()
    begin {
        function TryAddToRunQueue {
            param(
                [Parameter(Mandatory = $true)]
                $Job
            )

            if ($Job.JobCommand -eq "Invoke-Command") {
                $computerName = $Job.JobParameter.ComputerName

                if (-not ($jobsRunningPerServer.ContainsKey($computerName))) {
                    $jobsRunningPerServer.Add($computerName, 1)
                    return $true
                } elseif ($jobsRunningPerServer[$computerName] -le $maxJobsPerServer) {
                    $jobsRunningPerServer[$computerName] += 1
                    return $true
                }
            } elseif ($Job.JobCommand -eq "Start-Job") {
                if (-not ($jobsRunningPerServer.ContainsKey($env:COMPUTERNAME))) {
                    $jobsRunningPerServer.Add($env:COMPUTERNAME, 1)
                    return $true
                } elseif ($jobsRunningPerServer[$env:COMPUTERNAME] -le $maxJobsPerServer) {
                    $jobsRunningPerServer[$env:COMPUTERNAME] += 1
                    return $true
                }
            }
            return $false
        }
        $jobsRunningPerServer = @{}
        $maxJobsPerServer = 5
        $jobsToAdd = New-Object System.Collections.Generic.Queue[object]
    }
    process {
        $getJobQueue = Get-JobQueue

        if ($getJobQueue.Count -eq 0) {
            throw "No Jobs in Queue"
        }

        # Go through all the jobs and get the current number of jobs running per server
        $allRunningJobs = $getJobQueue.Values | Where-Object { $null -ne $_.Job -and $_.Job.State -eq "Running" }

        foreach ($runningJob in $allRunningJobs) {
            TryAddToRunQueue $runningJob | Out-Null
        }

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
            if ((TryAddToRunQueue $highJob)) {
                $jobsToAdd.Enqueue($highJob)
            }
        }

        foreach($normalJob in $normalPriorityJobs) {
            if ((TryAddToRunQueue $normalJob)) {
                $jobsToAdd.Enqueue($normalJob)
            }
        }

        foreach ($lowJob in $lowPriorityJobs) {
            if ((TryAddToRunQueue $lowJob)) {
                $jobsToAdd.Enqueue($lowJob)
            }
        }

        if ($jobsToAdd.Count -eq 0) {
            Write-Verbose "No jobs able to be started."
        }
        while ($jobsToAdd.Count -gt 0) {
            $currentJob = $jobsToAdd.Dequeue()
            $jobCommand = $currentJob.JobCommand
            $jobParameter = $currentJob.JobParameter

            if ($jobCommand -eq "Invoke-Command") {
                $jobParameter["AsJob"] = $true
            }
            Write-Verbose "Starting to execute job '$($currentJob.JobId)'"

            $newJob = & $jobCommand @jobParameter
            $jobInfo = $getJobQueue.Values | Where-Object { $_.JobId -eq $currentJob.JobId }
            $jobInfo.Job = $newJob
            $jobInfo.JobStartTime = [DateTime]::Now
        }
    }
}
