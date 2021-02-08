function Get-BadPermission {
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
        $folderData.IpmSubtreeByMailbox | ForEach-Object {
            $argumentList = $FolderData.MailboxToServerMap[$_.Name], $_.Name, $_.Group
            $name = $_.Name
            $scriptBlock = ${Function:Get-BadPermissionJob}
            Add-JobQueueJob @{
                ArgumentList = $argumentList
                Name         = "$name Permissions Check"
                ScriptBlock  = $scriptBlock
            }
        }

        $completedJobs = Wait-QueuedJob
        foreach ($job in $completedJobs) {
            if ($job.BadPermissions.Count -gt 0) {
                $badPermissions = $badPermissions + $job.BadPermissions
            }
        }
    }

    end {
        Write-Host "Get-BadPermission duration" ((Get-Date) - $startTime)
        return $badPermissions
    }
}
