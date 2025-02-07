# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
