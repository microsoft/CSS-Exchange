# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-AsyncJobQueue {
    [CmdletBinding()]
    param()
    process {
        if ($null -eq $Script:getAsyncJobQueueHash) {
            Write-Verbose "Creating Get-AsyncJobQueue Hashtable"
            $Script:getAsyncJobQueueHash = @{}
        }
        $Script:getAsyncJobQueueHash
    }
}

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

function Get-AsyncJobQueueResult {
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param()
    begin {
        $getAsyncJobQueue = Get-AsyncJobQueue

        if ($null -eq $getAsyncJobQueue) {
            throw "Async Jobs Queued is null"
        }

        # Add some additional logic check
        $results = @{}
    }
    process {
        foreach ($key in $getAsyncJobQueue.Keys) {
            $results.Add($key, $getAsyncJobQueue[$key].Results)
        }
    }
    end {
        $results
    }
}

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

function Clear-JobQueue {
    [CmdletBinding()]
    param()
    process {
        $getJobQueue = Get-JobQueue

        if ($null -eq $getJobQueue) {
            throw "Jobs Queued is null"
        }

        if ($null -eq ($getJobQueue.Values | Where-Object { $_.JobEndTime -eq [DateTime]::MinValue })) {
            throw "Not all jobs appear to be completed"
        }
        $getJobQueue.Clear()
    }
}
