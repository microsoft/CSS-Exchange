# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Add-AsyncJobQueue {
    [CmdletBinding()]
    param(
        [ValidateSet("Invoke-Command", "Start-Job")]
        [string]$JobCommand = "Invoke-Command",
        [Parameter(Mandatory = $true)]
        [object]$JobParameter,
        [Parameter(Mandatory = $true)]
        [string]$JobId,
        [string]$FriendlyName
    )
    begin {
        $getAsyncJobQueue = Get-AsyncJobQueue
    }
    process {
        $obj = [PSCustomObject]@{
            JobCommand   = $JobCommand
            JobParameter = $JobParameter
            JobId        = $JobId
            JobStartTime = [DateTime]::MinValue
            JobEndTime   = [DateTime]::MinValue
            Job          = $null
            Results      = $null
            Error        = $null
        }

        if ($getAsyncJobQueue.ContainsKey($JobId)) {
            throw "Already contains the JobID: $JobId"
        }

        # Instantly start the job
        # TODO: Need to determine how to spin up background worker to monitor things being added to the queue and executed.
        # This is to limit the number of threads that we will allow to be executed on a single server. Otherwise, right now there are no limits.
        if ($JobCommand -eq "Invoke-Command") {
            $JobParameter["AsJob"] = $true
        }

        Write-Verbose "Starting to execute async job '$JobId'"
        $obj.Job = (& $JobCommand @JobParameter)
        $obj.JobStartTime = [DateTime]::Now
        $getAsyncJobQueue.Add($JobId, $obj)
        Write-Verbose "Successfully added and started async JobId: $JobId"
    }
}
