# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$jobsQueued = New-Object 'System.Collections.Generic.Queue[object]'

function Add-JobQueueJob {
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSCustomObject]
        $JobParameters
    )

    begin {
    }

    process {
        $jobsQueued.Enqueue($JobParameters)
        Write-Host "Added job $($JobParameters.Name) to queue."
    }

    end {
    }
}

function Wait-QueuedJob {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (

    )

    begin {
        $jobsRunning = @()
        $jobQueueMaxConcurrency = 5
    }

    process {
        while ($jobsQueued.Count -gt 0 -or $jobsRunning.Count -gt 0) {
            if ($jobsRunning.Count -lt $jobQueueMaxConcurrency -and $jobsQueued.Count -gt 0) {
                $jobArgs = $jobsQueued.Dequeue()
                $newJob = Start-Job @jobArgs
                $jobsRunning += $newJob
                Write-Host "Started executing job $($jobArgs.Name)."
            }

            $justFinished = @($jobsRunning | Where-Object { $_.State -ne "Running" })
            if ($justFinished.Count -gt 0) {
                foreach ($job in $justFinished) {
                    $result = Receive-Job $job
                    $lastProgress = $job.ChildJobs.Progress | Select-Object -Last 1
                    if ($lastProgress) {
                        Write-Progress -Activity $lastProgress.Activity -ParentId 1 -Id ($job.Id + 1) -Completed
                    }
                    Write-Host $job.Name "job finished."
                    Remove-Job $job -Force
                    $result
                }

                $jobsRunning = @($jobsRunning | Where-Object { -not $justFinished.Contains($_) })
            }

            for ($i = 0; $i -lt $jobQueueMaxConcurrency; $i++) {
                if ($jobsRunning.Count -gt $i) {
                    $lastProgress = $jobsRunning[$i].ChildJobs.Progress | Select-Object -Last 1
                    if ($lastProgress) {
                        Write-Progress -Activity $lastProgress.Activity -Status $lastProgress.StatusDescription -PercentComplete $lastProgress.PercentComplete -ParentId 1 -Id ($jobsRunning[$i].Id + 1)
                    }
                }
            }

            Start-Sleep 1
        }
    }
}
