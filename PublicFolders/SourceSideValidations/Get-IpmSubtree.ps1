function Get-IpmSubtree {
    [CmdletBinding()]
    param (
        [Parameter()]
        [bool]
        $startFresh = $true
    )

    begin {
        $startTime = Get-Date
        $progressCount = 0
        $errors = 0
        $ipmSubtree = @()
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Retrieving IPM_SUBTREE folders"
            Id = 2
            ParentId = 1
        }
    }

    process {
        if (-not $startFresh -and (Test-Path $PSScriptRoot\IpmSubtree.csv)) {
            Write-Progress @progressParams
            $ipmSubtree = Import-Csv $PSScriptRoot\IpmSubtree.csv
        } else {
            $ipmSubtree = Get-PublicFolder -Recurse -ResultSize Unlimited |
                Select-Object Identity, EntryId, ParentFolder, DumpsterEntryId, FolderPath, FolderSize, HasSubfolders, ContentMailboxName |
                ForEach-Object {
                    $progressCount++
                    $currentFolder = $_.Identity.ToString()
                    try {
                        if ($sw.ElapsedMilliseconds -gt 1000) {
                            $sw.Restart()
                            Write-Progress @progressParams -Status $progressCount
                        }

                        [PSCustomObject]@{
                            Identity        = $_.Identity.ToString()
                            EntryId         = $_.EntryId.ToString()
                            ParentEntryId   = $_.ParentFolder.ToString()
                            DumpsterEntryId = if ($_.DumpsterEntryId) { $_.DumpsterEntryId.ToString() } else { $null }
                            FolderPathDepth = $_.FolderPath.Depth
                            FolderSize      = $_.FolderSize
                            HasSubfolders   = $_.HasSubfolders
                            ContentMailbox  = $_.ContentMailboxName
                            ItemCount       = 0
                        }
                    } catch {
                        $errors++
                        Write-Error -Message $currentFolder -Exception $_.Exception
                        break
                    }
                }
        }
    }

    end {
        if ($errors -lt 1) {
            if ($progressCount -gt 0) {
                Write-Progress @progressParams -Status "Saving"
                $ipmSubtree | Export-Csv $PSScriptRoot\IpmSubtree.csv
            }
        } else {
            $ipmSubtree = @()
        }

        Write-Progress @progressParams -Completed

        Write-Host "Get-IpmSubtree duration $((Get-Date) - $startTime) folder count $($ipmSubtree.Count)"

        return $ipmSubtree
    }
}
