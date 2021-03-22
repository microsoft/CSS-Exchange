function Get-BadDumpsterMappings {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter()]
        [PSCustomObject]
        $FolderData
    )

    begin {
        $startTime = Get-Date
        $progressCount = 0
        $badDumpsterMappings = @()
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Checking dumpster mappings"
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

            if (-not (Test-DumpsterValid $_ $FolderData)) {
                $badDumpsterMappings += $_
            }
        }

        Write-Progress @progressParams -Status "Checking EFORMS dumpster mappings"

        $FolderData.NonIpmSubtree | Where-Object { $_.Identity -like "\NON_IPM_SUBTREE\EFORMS REGISTRY\*" } | ForEach-Object {
            if (-not (Test-DumpsterValid $_ $FolderData)) {
                $badDumpsterMappings += $_
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed
        Write-Host "Get-BadDumpsterMappings duration" ((Get-Date) - $startTime)
        return $badDumpsterMappings
    }
}

function Test-DumpsterValid {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter()]
        [PSCustomObject]
        $Folder,

        [Parameter()]
        [PSCustomObject]
        $FolderData
    )

    begin {
        $valid = $true
    }

    process {
        $dumpster = $FolderData.NonIpmEntryIdDictionary[$Folder.DumpsterEntryId]

        if ($null -eq $dumpster -or
            (-not $dumpster.Identity.StartsWith("\NON_IPM_SUBTREE\DUMPSTER_ROOT", "OrdinalIgnoreCase")) -or
            $dumpster.DumpsterEntryId -ne $Folder.EntryId) {

            $valid = $false
        }
    }

    end {
        return $valid
    }
}
