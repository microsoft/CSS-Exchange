# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Start-JobManager {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'I prefer Start here')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ServersWithArguments,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,

        [string]$JobBatchName,

        [bool]$DisplayReceiveJob = $true,

        [bool]$NeedReturnData = $false,

        [ScriptBlock]$RemotePipelineHandler
    )
    <# It needs to be this way incase of different arguments being passed to different machines
        [array]ServersWithArguments
            [string]ServerName
            [object]ArgumentList #customized for your ScriptBlock
    #>

    function Wait-JobsCompleted {
        Write-Verbose "Calling Wait-JobsCompleted"
        [System.Diagnostics.Stopwatch]$timer = [System.Diagnostics.Stopwatch]::StartNew()
        # Data returned is a Hash Table that matches to the Server the Script Block ran against
        $returnData = @{}
        do {
            $completedJobs = Get-Job | Where-Object { $_.State -ne "Running" }
            if ($null -eq $completedJobs) {
                Start-Sleep 1
                continue
            }

            foreach ($job in $completedJobs) {
                $jobName = $job.Name
                Write-Verbose "Job $($job.Name) received. State: $($job.State) | HasMoreData: $($job.HasMoreData)"
                if ($NeedReturnData -eq $false -and $DisplayReceiveJob -eq $false -and $job.HasMoreData -eq $true) {
                    Write-Verbose "This job has data and you provided you didn't want to return it or display it."
                }
                $receiveJob = Receive-Job $job
                Remove-Job $job
                if ($null -eq $receiveJob) {
                    Write-Verbose "Job $jobName didn't have any receive job data"
                }

                # If more things are added to the pipeline than just the desired result (like custom Write-Verbose data to the pipeline)
                # The caller needs to handle this by having a custom ScriptBlock to process the data
                # Then return the desired result back
                if ($null -ne $RemotePipelineHandler -and $receiveJob) {
                    Write-Verbose "Starting to call RemotePipelineHandler"
                    $returnJobData = & $RemotePipelineHandler $receiveJob
                    Write-Verbose "Finished RemotePipelineHandler"
                    if ($null -ne $returnJobData) {
                        $returnData.Add($jobName, $returnJobData)
                    } else {
                        Write-Verbose "Nothing came back from the RemotePipelineHandler"
                    }
                } elseif ($NeedReturnData) {
                    $returnData.Add($jobName, $receiveJob)
                }
            }
        } while ($true -eq (Get-Job))
        $timer.Stop()
        Write-Verbose "Waiting for jobs to complete took $($timer.Elapsed.TotalSeconds) seconds"
        if ($NeedReturnData) {
            return $returnData
        }
        return $null
    }

    [System.Diagnostics.Stopwatch]$timerMain = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "Calling Start-JobManager"
    Write-Verbose "Passed: [bool]DisplayReceiveJob: $DisplayReceiveJob | [string]JobBatchName: $JobBatchName | [bool]NeedReturnData:$NeedReturnData"

    foreach ($serverObject in $ServersWithArguments) {
        $server = $serverObject.ServerName
        $argumentList = $serverObject.ArgumentList
        Write-Verbose "Starting job on server $server"
        Invoke-Command -ComputerName $server -ScriptBlock $ScriptBlock -ArgumentList $argumentList -AsJob -JobName $server | Out-Null
    }

    $data = Wait-JobsCompleted
    $timerMain.Stop()
    Write-Verbose "Exiting: Start-JobManager | Time in Start-JobManager: $($timerMain.Elapsed.TotalSeconds) seconds"
    if ($NeedReturnData) {
        return $data
    }
    return $null
}
