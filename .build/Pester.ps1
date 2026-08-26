# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '', Justification = 'Variable passed via -ArgumentList param()')]
[CmdletBinding()]
param(
    [switch]
    $NoProgress,

    [string]
    $Branch
)

begin {
    . $PSScriptRoot\Load-Module.ps1
    . $PSScriptRoot\HelpFunctions\Get-CommitFilesOnBranch.ps1

    if (-not (Load-Module -Name Pester -MinimumVersion 5.2.0)) {
        throw "Pester module could not be loaded"
    }

    $jobsCompleted = @{}
    $jobsProgress = @{}
    $jobsRunning = New-Object 'System.Collections.Generic.List[PSCustomObject]'
    $childIds = 1
    # on Azure pipeline we have noticed 2 or 4 cores available. to get the most of out jobs, need at least a min of 2 threads running.
    $jobQueueMaxConcurrency = [System.Math]::Max(([System.Math]::Min(([System.Environment]::ProcessorCount - 1), 5)), 2)
    Write-Host "Max Job Threads: $jobQueueMaxConcurrency"
    $failPipeline = $false
    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
} process {

    if (-not ([string]::IsNullOrEmpty($Branch))) {
        Write-Host "Checking commits on Branch $Branch"
        $committedFiles = Get-CommitFilesOnBranch -Branch $Branch
        # if the branch only has doc changes return
        if ($null -eq ($committedFiles | Where-Object { $_.EndsWith(".ps1") } )) {
            Write-Host "No Commits on PS1 files, skipping over pester testing."
            return
        }
    }

    $root = Get-Item "$PSScriptRoot\.."
    $scripts = @(Get-ChildItem -Recurse $root |
            Where-Object { $_.Name -like "*.Tests.ps1" -and $_.FullName -notmatch "\.github" })

    # Categorize test files by priority using comment tag: # PesterPriority: High
    $highPriorityQueue = New-Object 'System.Collections.Generic.Queue[object]'
    $lowPriorityQueue = New-Object 'System.Collections.Generic.Queue[object]'

    foreach ($script in $scripts) {
        $firstLines = Get-Content $script.FullName -TotalCount 15
        if ($firstLines -match "# PesterPriority: High") {
            $highPriorityQueue.Enqueue($script)
        } else {
            $lowPriorityQueue.Enqueue($script)
        }
    }

    Write-Host "High Priority Tests: $($highPriorityQueue.Count) | Low Priority Tests: $($lowPriorityQueue.Count)"

    # Thread allocation: high priority gets up to (threads - 1) slots, always leaving at least 1 for low.
    # This ensures heavy tests start immediately while small tests still make progress.
    $highThreadMax = [System.Math]::Min($highPriorityQueue.Count, $jobQueueMaxConcurrency - 1)
    $lowThreadMax = $jobQueueMaxConcurrency - $highThreadMax

    # If no high priority tests exist, all threads go to low priority
    if ($highPriorityQueue.Count -eq 0) {
        $lowThreadMax = $jobQueueMaxConcurrency
        $highThreadMax = 0
    }

    Write-Host "Thread Allocation: High=$highThreadMax Low=$lowThreadMax"

    $parentProgress = @{
        Id              = 0
        Activity        = "Running Pester Tests"
        Status          = "Initializing"
        PercentComplete = 0
    }

    if (-not $NoProgress) {
        Write-Progress @parentProgress
    }

    while ($highPriorityQueue.Count -gt 0 -or $lowPriorityQueue.Count -gt 0 -or $jobsRunning.Count -gt 0) {

        # Determine if low priority work is fully drained (queue empty AND no low jobs running)
        $lowDrained = ($lowPriorityQueue.Count -eq 0 -and
            (@($jobsRunning | Where-Object { $_.Priority -eq "Low" }).Count -eq 0))

        $runningHigh = @($jobsRunning | Where-Object { $_.Priority -eq "High" }).Count
        $runningLow = @($jobsRunning | Where-Object { $_.Priority -eq "Low" }).Count

        # Once low priority is drained, all threads become available for high priority
        $effectiveHighMax = if ($lowDrained) { $jobQueueMaxConcurrency } else { $highThreadMax }
        $effectiveLowMax = if ($lowDrained) { 0 } else { $lowThreadMax }

        # Start new jobs up to concurrency limit
        while ($jobsRunning.Count -lt $jobQueueMaxConcurrency) {
            $nextScript = $null
            $nextPriority = $null

            # Try high priority first if under high thread limit
            if ($runningHigh -lt $effectiveHighMax -and $highPriorityQueue.Count -gt 0) {
                $nextScript = $highPriorityQueue.Dequeue()
                $nextPriority = "High"
            } elseif ($runningLow -lt $effectiveLowMax -and $lowPriorityQueue.Count -gt 0) {
                $nextScript = $lowPriorityQueue.Dequeue()
                $nextPriority = "Low"
            } elseif ($highPriorityQueue.Count -gt 0 -and $runningHigh -lt $jobQueueMaxConcurrency) {
                # Fill any remaining slots with high priority
                $nextScript = $highPriorityQueue.Dequeue()
                $nextPriority = "High"
            } elseif ($lowPriorityQueue.Count -gt 0 -and $runningLow -lt $jobQueueMaxConcurrency) {
                # Fill any remaining slots with low priority
                $nextScript = $lowPriorityQueue.Dequeue()
                $nextPriority = "Low"
            }

            if ($null -eq $nextScript) { break }

            if ($VerbosePreference -eq "Continue") {
                $elapsed = [math]::Round($stopWatch.Elapsed.TotalSeconds, 1)
                Write-Verbose "[DEBUG T+${elapsed}s] Starting [$nextPriority] $($nextScript.Name) (H:$runningHigh/$effectiveHighMax L:$runningLow/$effectiveLowMax)"
            }

            $newJob = Start-Job -ScriptBlock {
                param([string]$FileName)
                return Invoke-Pester -Path $FileName -PassThru
            } -ArgumentList $nextScript.FullName -Name $nextScript.Name

            $jobsRunning.Add([PSCustomObject]@{
                    Job      = $newJob
                    Priority = $nextPriority
                    Name     = $nextScript.Name
                })

            $progress = @{
                Id       = $childIds++
                ParentId = 0
                Activity = "Running [$nextPriority]: $($nextScript.Name)"
            }
            $jobsProgress.Add($newJob.Name, $progress)

            if (-not $NoProgress) {
                Write-Progress @progress
            }

            $runningHigh = @($jobsRunning | Where-Object { $_.Priority -eq "High" }).Count
            $runningLow = @($jobsRunning | Where-Object { $_.Priority -eq "Low" }).Count
        }

        # Check for completed jobs
        $justFinished = @($jobsRunning | Where-Object { $_.Job.State -ne "Running" })

        if ($justFinished.Count -gt 0) {
            foreach ($item in $justFinished) {
                $result = Receive-Job $item.Job
                $jobsCompleted.Add($item.Name, [PSCustomObject]@{
                        Job      = $item.Job
                        Priority = $item.Priority
                        Result   = $result
                    })
                $progress = $jobsProgress[$item.Name]

                if (-not $NoProgress) {
                    Write-Progress @progress -Completed
                }

                $jobDuration = [math]::Round(($item.Job.PSEndTime - $item.Job.PSBeginTime).TotalSeconds, 1)
                Write-Host "[$($item.Priority)] $($item.Name) job finished. (${jobDuration}s)"

                if ($VerbosePreference -eq "Continue") {
                    $elapsed = [math]::Round($stopWatch.Elapsed.TotalSeconds, 1)
                    Write-Verbose "[DEBUG T+${elapsed}s] Completed [$($item.Priority)] $($item.Name) - Pester: $([math]::Round($result.Duration.TotalSeconds, 1))s Job: ${jobDuration}s"
                }

                Remove-Job $item.Job -Force
                $result

                if ($result.Result -eq "Failed" -or
                    $null -eq $result.Result) {
                    $failPipeline = $true
                }
            }

            foreach ($item in $justFinished) {
                $jobsRunning.Remove($item) | Out-Null
            }
        }

        $highRunning = @($jobsRunning | Where-Object { $_.Priority -eq "High" }).Count
        $lowRunning = @($jobsRunning | Where-Object { $_.Priority -eq "Low" }).Count
        $highCompleted = @($jobsCompleted.Values | Where-Object { $_.Priority -eq "High" }).Count
        $lowCompleted = @($jobsCompleted.Values | Where-Object { $_.Priority -eq "Low" }).Count
        $highTotal = $highCompleted + $highRunning + $highPriorityQueue.Count
        $lowTotal = $lowCompleted + $lowRunning + $lowPriorityQueue.Count

        $parentProgress.PercentComplete = ($jobsCompleted.Count / $scripts.Count * 100)
        $parentProgress.Status = "Running: $($jobsRunning.Count) | High: $highRunning running, $highCompleted/$highTotal done | Low: $lowRunning running, $lowCompleted/$lowTotal done"

        if (-not $NoProgress) {
            Write-Progress @parentProgress
        }

        if ($jobsRunning.Count -ge $jobQueueMaxConcurrency -or
            ($highPriorityQueue.Count -eq 0 -and $lowPriorityQueue.Count -eq 0)) {
            Start-Sleep -Milliseconds 500
        }
    }
} end {

    Write-Host

    if (-not $NoProgress -and
        $null -ne $parentProgress) {
        Write-Progress @parentProgress -Completed
    }
    $sumTotalSeconds = 0
    $sumTotalPesterSeconds = 0

    foreach ($job in $jobsCompleted.Keys) {
        $value = $jobsCompleted[$job]
        $totalSeconds = ($value.Job.PSEndTime - $value.Job.PSBeginTime).TotalSeconds
        $sumTotalPesterSeconds += $value.Result.Duration.TotalSeconds
        Write-Host "[$($value.Priority)] $job took $totalSeconds seconds to complete"
        $sumTotalSeconds += $totalSeconds

        if ($value.Result.Result -eq "Failed") {
            Write-Host "Failed Tests"
            $value.Result.Failed | Write-Host
        }
    }

    Write-Host
    Write-Host
    Write-Host "Total seconds for jobs: $sumTotalSeconds"
    Write-Host "Total seconds for pester results: $sumTotalPesterSeconds"
    Write-Host "Average seconds per threads allowed: $($sumTotalSeconds / $jobQueueMaxConcurrency)"
    Write-Host "Total Seconds script took: $($stopWatch.Elapsed.TotalSeconds)"

    if ($VerbosePreference -eq "Continue") {
        $highJobs = $jobsCompleted.Values | Where-Object { $_.Priority -eq "High" }
        $lowJobs = $jobsCompleted.Values | Where-Object { $_.Priority -eq "Low" }
        $highSum = ($highJobs | ForEach-Object { ($_.Job.PSEndTime - $_.Job.PSBeginTime).TotalSeconds } | Measure-Object -Sum).Sum
        $lowSum = ($lowJobs | ForEach-Object { ($_.Job.PSEndTime - $_.Job.PSBeginTime).TotalSeconds } | Measure-Object -Sum).Sum
        $longestJob = $jobsCompleted.Values | Sort-Object { ($_.Job.PSEndTime - $_.Job.PSBeginTime).TotalSeconds } | Select-Object -Last 1
        $longestDuration = [math]::Round(($longestJob.Job.PSEndTime - $longestJob.Job.PSBeginTime).TotalSeconds, 1)
        $efficiency = [math]::Round(($sumTotalSeconds / ($stopWatch.Elapsed.TotalSeconds * $jobQueueMaxConcurrency)) * 100, 1)

        Write-Verbose ""
        Write-Verbose "=== Scheduling Debug ==="
        Write-Verbose "High priority: $($highJobs.Count) jobs, $([math]::Round($highSum, 1))s total"
        Write-Verbose "Low priority: $($lowJobs.Count) jobs, $([math]::Round($lowSum, 1))s total"
        Write-Verbose "Longest job: [$($longestJob.Priority)] $($longestJob.Job.Name) (${longestDuration}s)"
        Write-Verbose "Thread utilization: $efficiency% (ideal=100%)"
        Write-Verbose "Theoretical minimum: $([math]::Round($sumTotalSeconds / $jobQueueMaxConcurrency, 1))s"
        Write-Verbose "Actual wall clock: $([math]::Round($stopWatch.Elapsed.TotalSeconds, 1))s"
        Write-Verbose "Overhead: $([math]::Round($stopWatch.Elapsed.TotalSeconds - ($sumTotalSeconds / $jobQueueMaxConcurrency), 1))s"
    }

    if ($failPipeline) {
        throw "Failed Pester Testing Results"
    }
}
