function Get-ItemCount {
    <#
    .SYNOPSIS
        Populates the ItemCount property on our PSCustomObjects.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSCustomObject]
        $FolderData
    )

    begin {
        $startTime = Get-Date
        $progressCount = 0
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Getting public folder statistics"
            Id       = 2
            ParentId = 1
        }
    }

    process {
        $highestItemCountFolder = $FolderData.IpmSubtree | Sort-Object ItemCount -Descending | Select-Object -First 1
        if ($highestItemCountFolder.ItemCount -lt 1) {
            Get-PublicFolderStatistics -ResultSize Unlimited | ForEach-Object {
                $progressCount++
                if ($sw.ElapsedMilliseconds -gt 1000) {
                    $sw.Restart()
                    Write-Progress @progressParams -Status $progressCount
                }

                if ($_.ItemCount -gt 0) {
                    $folder = $FolderData.EntryIdDictionary[$_.EntryId.ToString()]

                    if ($null -ne $folder) {
                        $folder.ItemCount = $_.ItemCount
                    }
                }
            }
        }
    }

    end {
        if ($progressCount -gt 0) {
            Write-Progress @progressParams -Status "Saving"
            $FolderData.IpmSubtree | Export-Csv $PSScriptRoot\IpmSubtree.csv
        }

        Write-Progress @progressParams -Completed
        Write-Host "Get-ItemCount duration" ((Get-Date) - $startTime)
    }
}
