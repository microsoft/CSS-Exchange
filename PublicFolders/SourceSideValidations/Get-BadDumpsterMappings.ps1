function Get-BadDumpsterMappings {
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSCustomObject]
        $FolderData
    )
    
    begin {
        $startTime = Get-Date
        $progressCount = 0
        $badDumpsterMappings = @()
    }
    
    process {
        $FolderData.IpmSubtree | ForEach-Object {
            if (++$progressCount % 100 -eq 0) {
                Write-Progress -Activity "Checking dumpster mappings" -Status $progressCount -PercentComplete ($progressCount * 100 / $FolderData.IpmSubtree.Count)
            }

            $dumpster = $FolderData.NonIpmEntryIdDictionary[$_.DumpsterEntryId]

            if ($null -eq $dumpster -or
                (-not $dumpster.Identity.StartsWith("\NON_IPM_SUBTREE\DUMPSTER_ROOT", "OrdinalIgnoreCase")) -or 
                $dumpster.DumpsterEntryId -ne $_.EntryId) {

                $badDumpsterMappings += $_
            }
        }
    }
    
    end {
        Write-Progress -Activity "None" -Completed
        Write-Host "Get-BadDumpsterMappings duration" ((Get-Date) - $startTime)
        return $badDumpsterMappings
    }
}