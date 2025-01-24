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

function Get-JobResultList {
    [CmdletBinding()]
    param()
    process {
        if ($null -eq $Script:jobsQueued) {
            throw "Jobs Queued is null"
        }

        if ($null -ne ($Script:jobsQueued.Values | Where-Object { $_.JobEndTime -eq [DateTime]::MinValue })) {
            throw "Not all jobs appear to be completed"
        }

        $result = New-Object System.Collections.Generic.List[System.Object]
        $result.AddRange(@($Script:jobsQueued.Values))
        $result
    }
}
