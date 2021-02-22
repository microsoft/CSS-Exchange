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
        $jobResults = @()
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
                    Write-Host $job.Name "job finished."
                    Remove-Job $job -Force
                    $jobResults += $result
                }

                $jobsRunning = @($jobsRunning | Where-Object { -not $justFinished.Contains($_) })
            }

            for ($i = 0; $i -lt $jobQueueMaxConcurrency; $i++) {
                if ($jobsRunning.Count -gt $i) {
                    $lastProgress = $jobsRunning[$i].ChildJobs.Progress | Select-Object -Last 1
                    if ($lastProgress) {
                        Write-Progress -Activity $lastProgress.Activity -Status $lastProgress.StatusDescription -PercentComplete $lastProgress.PercentComplete -Id $i
                    }
                } else {
                    Write-Progress -Activity "None" -Id $i -Completed
                }
            }

            Start-Sleep 1
        }
    }

    end {
        $jobsToReturn = $jobResults
        $jobResults = @()
        return $jobsToReturn
    }
}
