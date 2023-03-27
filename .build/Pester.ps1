# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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

    $jobsQueued = New-Object 'System.Collections.Generic.Queue[object]'
    $childIds = 1
    $jobsCompleted = @{}
    $jobsProgress = @{}
    $jobsRunning = @()
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
            Where-Object { $_.Name -like "*.Tests.ps1" })

    $parentProgress = @{
        Id              = 0
        Activity        = "Running Pester Tests"
        Status          = [string]::Empty
        PercentComplete = 0
    }

    $scripts | ForEach-Object {
        $jobsQueued.Enqueue(@{
                ScriptBlock  = {
                    param(
                        [string]$FileName
                    )
                    return Invoke-Pester -Path $FileName -PassThru
                }
                ArgumentList = $_.FullName
                Name         = $_.Name
            })
    }

    $parentProgress.PercentComplete = ($jobsCompleted.Count / $scripts.Count * 100)
    $parentProgress.Status = "Number of Jobs Running $($jobsRunning.Count)"

    if (-not $NoProgress) {
        Write-Progress @parentProgress
    }

    while ($jobsQueued.Count -gt 0 -or $jobsRunning.Count -gt 0) {

        if ($jobsRunning.Count -lt $jobQueueMaxConcurrency -and $jobsQueued.Count -gt 0) {
            $jobArgs = $jobsQueued.Dequeue()
            # Using Start-Job instead of Start-ThreadJob as this is faster for this script block
            # If Start-ThreadJob is used, need to have $justFinished also use NotStarted State Filter
            $newJob = Start-Job @jobArgs
            $jobsRunning += $newJob
            $progress = @{
                Id       = $childIds++
                ParentId = 0
                Activity = "Running: $($newJob.Name)"
            }
            $jobsProgress.Add($newJob.Name, $progress)

            if (-not $NoProgress) {
                Write-Progress @progress
            }
        }

        $justFinished = @($jobsRunning | Where-Object { $_.State -ne "Running" })

        if ($justFinished.Count -gt 0) {
            foreach ($job in $justFinished) {
                $result = Receive-Job $job
                $jobsCompleted.Add($job.Name, [PSCustomObject]@{
                        Job    = $job
                        Result = $result
                    })
                $progress = $jobsProgress[$job.Name]

                if (-not $NoProgress) {
                    Write-Progress @progress -Completed
                }
                Write-Host $job.Name "job finished."
                Remove-Job $job -Force
                $result

                if ($result.Result -eq "Failed" -or
                    $null -eq $result.Result) {
                    $failPipeline = $true
                }
            }

            $jobsRunning = @($jobsRunning | Where-Object { -not $justFinished.Contains($_) })
        }

        $parentProgress.PercentComplete = ($jobsCompleted.Count / $scripts.Count * 100)
        $parentProgress.Status = "Number of Jobs Running $($jobsRunning.Count)"

        if (-not $NoProgress) {
            Write-Progress @parentProgress
        }

        if ($jobsRunning.Count -eq $jobQueueMaxConcurrency -or $jobsQueued.Count -eq 0) {
            Start-Sleep 1
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
        Write-Host "$job took $totalSeconds seconds to complete"
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
    Write-Host "Average seconds per threads allowed: $($sumTotalSeconds/ $jobQueueMaxConcurrency)"
    Write-Host "Total Seconds script took: $($stopWatch.Elapsed.TotalSeconds)"

    if ($failPipeline) {
        throw "Failed Pester Testing Results"
    }
}
