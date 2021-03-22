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
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Checking limits"
            Id = 2
            ParentId = 1
        }
    }

    process {
        $FolderData.IpmSubtree | ForEach-Object {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress @progressParams -Status $progressCount -PercentComplete ($progressCount * 100 / $FolderData.IpmSubtree.Count)
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
        Write-Progress @progressParams -Completed
        Write-Host "Get-LimitsExceeded duration" ((Get-Date) - $startTime)
        return $limitsExceeded
    }
}
