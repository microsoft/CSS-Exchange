function Get-LimitsExceeded {
    <#
    .SYNOPSIS
        Flags folders that exceed the child count limit, depth limit,
        or item limit.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSObject]
        $FolderData
    )

    begin {
        $startTime = Get-Date
        $progressCount = 0
        $limitsExceeded = [PSCustomObject]@{
            ChildCount      = @()
            FolderPathDepth = @()
            ItemCount       = @()
        }
    }

    process {
        $FolderData.IpmSubtree | ForEach-Object {
            if (++$progressCount % 100 -eq 0) {
                Write-Progress -Activity "Checking limits" -Status $progressCount -PercentComplete ($progressCount * 100 / $FolderData.IpmSubtree.Count)
            }

            if ($FolderData.ParentEntryIdCounts[$_.EntryId] -gt 10000) {
                $limitsExceeded.ChildCount += $_.Identity.ToString()
            }

            if ([int]$_.FolderPathDepth -gt 299) {
                $limitsExceeded.FolderPathDepth += $_.Identity.ToString()
            }

            if ($_.ItemCount -gt 1000000) {
                $limitsExceeded.ItemCount += $_.Identity.ToString()
            }
        }
    }

    end {
        Write-Progress -Activity "None" -Completed
        Write-Host "Get-LimitsExceeded duration" ((Get-Date) - $startTime)
        return $limitsExceeded
    }
}
