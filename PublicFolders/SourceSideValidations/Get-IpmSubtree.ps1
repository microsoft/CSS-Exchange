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
    }

    process {
        if (-not $startFresh -and (Test-Path $PSScriptRoot\IpmSubtree.csv)) {
            Write-Progress -Activity "Reading IPM_SUBTREE from file"
            $ipmSubtree = Import-Csv $PSScriptRoot\IpmSubtree.csv
        } else {
            $ipmSubtree = Get-PublicFolder -Recurse -ResultSize Unlimited |
                Select-Object Identity, EntryId, ParentFolder, DumpsterEntryId, FolderPath, FolderSize, HasSubfolders, ContentMailboxName |
                ForEach-Object {
                    $currentFolder = $_.Identity.ToString()
                    try {
                        if (++$progressCount % 100 -eq 0) {
                            Write-Progress -Activity "Retrieving IPM_SUBTREE folders" -Status $progressCount
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
                Write-Progress -Activity "Saving IPM_SUBTREE to a file"
                $ipmSubtree | Export-Csv $PSScriptRoot\IpmSubtree.csv
            }
        } else {
            $ipmSubtree = @()
        }

        Write-Host "Get-IpmSubtree duration $((Get-Date) - $startTime) folder count $($ipmSubtree.Count)"

        return $ipmSubtree
    }
}
