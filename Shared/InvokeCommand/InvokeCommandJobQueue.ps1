# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Add-InvokeCommandJobQueue {
    [CmdletBinding()]
    param (
        [Parameter()]
        [object]
        $InvokeCommandParameters
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        if ($null -eq $Script:InvokeCommandJobQueue) {
            $Script:InvokeCommandJobQueue = New-Object 'System.Collections.Generic.Queue[object]'
        }

        # Make sure AsJob is always set to $true
        $InvokeCommandParameters.AsJob = $true
    }
    process {
        $Script:InvokeCommandJobQueue.Enqueue($InvokeCommandParameters)
        Write-Verbose "Added job $($InvokeCommandParameters.JobName) to queue."
    }
}

# Only use IncludeProgress if Write-Progress is within the ScriptBlock
function Wait-InvokeCommandJobQueue {
    [CmdletBinding()]
    param(
        [switch]$IncludeProgress,
        [int]$JobQueueMaxConcurrency = [int]::MaxValue
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $jobsRunning = New-Object 'System.Collections.Generic.List[object]'
        $timerMain = [System.Diagnostics.Stopwatch]::StartNew()
    }
    process {
        while ($Script:InvokeCommandJobQueue.Count -gt 0 -or $jobsRunning.Count -gt 0) {
            # Start the jobs
            if ($jobsRunning.Count -lt $JobQueueMaxConcurrency -and $Script:InvokeCommandJobQueue.Count -gt 0) {
                $jobArgs = $Script:InvokeCommandJobQueue.Dequeue()
                $newJob = Invoke-Command @jobArgs
                $jobsRunning.Add($newJob)
                Write-Verbose "Starting executing job $($jobArgs.JobName)."
            }

            # Get the finished jobs and place the information onto the pipeline
            $justFinished = @($jobsRunning | Where-Object { $_.State -ne "Running" })
            if ($justFinished.Count -gt 0) {
                foreach ($job in $justFinished) {
                    $result = Receive-Job $job
                    $lastProgress = $job.ChildJobs.Progress | Select-Object -Last 1
                    if ($lastProgress -and $IncludeProgress) {
                        $params = @{
                            Activity  = $lastProgress.Activity
                            ParentId  = 1
                            Id        = ($job.Id + 1)
                            Completed = $true
                        }
                        Write-Progress @params
                    }
                    Write-Verbose "$($job.Name) job finished."
                    $jobsRunning.Remove($job) | Out-Null
                    Remove-Job $job -Force
                    [PSCustomObject]@{
                        ComputerName = $job.Location
                        ReturnJob    = $result
                    }
                }
            }

            # Only need to attempt to display Write-Progress if we want to display
            if ($IncludeProgress) {
                for ($i = 0; $i -lt $jobsRunning.Count; $i++) {
                    $lastProgress = $jobsRunning[$i].ChildJobs.Progress | Select-Object -Last 1
                    if ($lastProgress) {
                        $params = @{
                            Activity        = $lastProgress.Activity
                            Status          = $lastProgress.StatusDescription
                            PercentComplete = $lastProgress.PercentComplete
                            ParentId        = 1
                            Id              = ($jobsRunning[$i].Id + 1)
                        }
                        Write-Progress @params
                    }
                }
            }

            Start-Sleep 1
        }
        Write-Verbose "Total time in seconds waiting for jobs to complete: $($timerMain.Elapsed.TotalSeconds)"
    }
}
