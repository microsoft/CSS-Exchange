# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    Gets the stored queue from a script variable.
#>
function Get-JobQueue {
    [CmdletBinding()]
    param()
    process {
        if ($null -eq $Script:getJobQueueHash) {
            Write-Verbose "Creating Get-JobQueue Hashtable"
            $Script:getJobQueueHash = @{}
        }
        $Script:getJobQueueHash
    }
}

<#
.DESCRIPTION
    Returns only the results from the jobs that was in the queue. Currently, all the jobs in the queue must be completed to get the results.
#>
function Get-JobQueueResult {
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param()
    begin {

        $getJobQueue = Get-JobQueue

        if ($null -eq $getJobQueue) {
            throw "Jobs Queued is null"
        }

        if ($null -ne ($getJobQueue.Values | Where-Object { $_.JobEndTime -eq [DateTime]::MinValue })) {
            throw "Not all jobs appear to be completed"
        }

        $results = @{}
    }
    process {
        foreach ($key in $getJobQueue.Keys) {
            $results.Add($key, $getJobQueue[$key].Results)
        }
    }
    end {
        $results
    }
}

<#
.DESCRIPTION
    Clear the current queue. This can only be called if all jobs have been completed. Does not check to make sure that you retrieved the data before clearing,
    but it does require all the jobs to have been completed.
#>
function Clear-JobQueue {
    [CmdletBinding()]
    param()
    process {
        $getJobQueue = Get-JobQueue

        if ($null -eq $getJobQueue) {
            throw "Jobs Queued is null"
        }

        if ($null -ne ($getJobQueue.Values | Where-Object { $_.JobEndTime -eq [DateTime]::MinValue })) {
            throw "Not all jobs appear to be completed"
        }
        $getJobQueue.Clear()
    }
}
