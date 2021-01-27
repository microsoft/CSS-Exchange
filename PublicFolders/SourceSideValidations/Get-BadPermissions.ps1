function Get-BadPermissions {
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSCustomObject]
        $FolderData
    )

    begin {
        $startTime = Get-Date
        $badPermissions = @()
    }

    process {
        $folderData.IpmSubtreeByMailbox | Foreach-Object {
            $argumentList = $FolderData.MailboxToServerMap[$_.Name], $_.Name, $_.Group
            $name = $_.Name
            $scriptBlock = ${Function:Get-BadPermissionsJob}
            Add-JobQueueJob @{
                ArgumentList = $argumentList
                Name         = "$name Permissions Check"
                ScriptBlock  = $scriptBlock
            }
        }

        $completedJobs = Wait-QueuedJobs
        foreach ($job in $completedJobs) {
            if ($job.BadPermissions.Count -gt 0) {
                $badPermissions = $badPermissions + $job.BadPermissions
            }
        }
    }

    end {
        Write-Host "Get-BadPermissions duration" ((Get-Date) - $startTime)
        return $badPermissions
    }
}
