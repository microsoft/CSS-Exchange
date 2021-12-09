# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Start-JobManager/Start-JobManager.ps1
#v21.01.22.2234
Function Start-JobManager {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'I prefer Start here')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$ServersWithArguments,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $false)][string]$JobBatchName,
        [Parameter(Mandatory = $false)][bool]$DisplayReceiveJob = $true,
        [Parameter(Mandatory = $false)][bool]$DisplayReceiveJobInVerboseFunction,
        [Parameter(Mandatory = $false)][bool]$DisplayReceiveJobInCorrectFunction,
        [Parameter(Mandatory = $false)][bool]$NeedReturnData = $false
    )
    #Function Version #v21.01.22.2234
    <#
        [array]ServersWithArguments
            [string]ServerName
            [object]ArgumentList #customized for your scriptblock
    #>

    Function Write-ReceiveJobData {
        param(
            [Parameter(Mandatory = $true)][array]$ReceiveJobData
        )
        $returnJob = [string]::Empty
        foreach ($job in $ReceiveJobData) {
            if ($job["Verbose"]) {
                Write-VerboseWriter($job["Verbose"])
            } elseif ($job["Host"]) {
                Write-HostWriter($job["Host"])
            } elseif ($job["ReturnObject"]) {
                $returnJob = $job["ReturnObject"]
            } else {
                Write-VerboseWriter("Unable to determine the key for the return type.")
            }
        }
        return $returnJob
    }

    Function Start-Jobs {
        Write-VerboseWriter("Calling Start-Jobs")
        foreach ($serverObject in $ServersWithArguments) {
            $server = $serverObject.ServerName
            $argumentList = $serverObject.ArgumentList
            Write-VerboseWriter("Starting job on server {0}" -f $server)
            Invoke-Command -ComputerName $server -ScriptBlock $ScriptBlock -ArgumentList $argumentList -AsJob -JobName $server | Out-Null
        }
    }

    Function Confirm-JobsPending {
        $jobs = Get-Job
        if ($null -ne $jobs) {
            return $true
        }
        return $false
    }

    Function Wait-JobsCompleted {
        Write-VerboseWriter("Calling Wait-JobsCompleted")
        [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
        $returnData = @{}
        while (Confirm-JobsPending) {
            $completedJobs = Get-Job | Where-Object { $_.State -ne "Running" }
            if ($null -eq $completedJobs) {
                Start-Sleep 1
                continue
            }

            foreach ($job in $completedJobs) {
                $receiveJobNull = $false
                $jobName = $job.Name
                Write-VerboseWriter("Job {0} received. State: {1} | HasMoreData: {2}" -f $job.Name, $job.State, $job.HasMoreData)
                if ($NeedReturnData -eq $false -and $DisplayReceiveJob -eq $false -and $job.HasMoreData -eq $true) {
                    Write-VerboseWriter("This job has data and you provided you didn't want to return it or display it.")
                }
                $receiveJob = Receive-Job $job
                Remove-Job $job
                if ($null -eq $receiveJob) {
                    $receiveJobNull = $True
                    Write-VerboseWriter("Job {0} didn't have any receive job data" -f $jobName)
                }
                if ($DisplayReceiveJobInVerboseFunction -and (-not($receiveJobNull))) {
                    Write-VerboseWriter("[JobName: {0}] : {1}" -f $jobName, $receiveJob)
                } elseif ($DisplayReceiveJobInCorrectFunction -and (-not ($receiveJobNull))) {
                    $returnJobData = Write-ReceiveJobData -ReceiveJobData $receiveJob
                    if ($null -ne $returnJobData) {
                        $returnData.Add($jobName, $returnJobData)
                    }
                } elseif ($DisplayReceiveJob -and (-not($receiveJobNull))) {
                    Write-HostWriter $receiveJob
                }
                if ($NeedReturnData -and (-not($DisplayReceiveJobInCorrectFunction))) {
                    $returnData.Add($job.Name, $receiveJob)
                }
            }
        }
        $timer.Stop()
        Write-VerboseWriter("Waiting for jobs to complete took {0} seconds" -f $timer.Elapsed.TotalSeconds)
        if ($NeedReturnData) {
            return $returnData
        }
        return $null
    }

    [System.Diagnostics.Stopwatch]$timerMain = [System.Diagnostics.Stopwatch]::StartNew()
    Write-VerboseWriter("Calling Start-JobManager")
    Write-VerboseWriter("Passed: [bool]DisplayReceiveJob: {0} | [string]JobBatchName: {1} | [bool]DisplayReceiveJobInVerboseFunction: {2} | [bool]NeedReturnData:{3}" -f $DisplayReceiveJob,
        $JobBatchName,
        $DisplayReceiveJobInVerboseFunction,
        $NeedReturnData)

    Start-Jobs
    $data = Wait-JobsCompleted
    $timerMain.Stop()
    Write-VerboseWriter("Exiting: Start-JobManager | Time in Start-JobManager: {0} seconds" -f $timerMain.Elapsed.TotalSeconds)
    if ($NeedReturnData) {
        return $data
    }
    return $null
}
