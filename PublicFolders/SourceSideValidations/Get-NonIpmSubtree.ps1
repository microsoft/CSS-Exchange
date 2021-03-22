function Get-NonIpmSubtree {
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
        $nonIpmSubtree = @()
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Retrieving NON_IPM_SUBTREE folders"
            Id       = 2
            ParentId = 1
        }
    }

    process {
        if (-not $startFresh -and (Test-Path $PSScriptRoot\NonIpmSubtree.csv)) {
            Write-Progress @progressParams
            $nonIpmSubtree = Import-Csv $PSScriptRoot\NonIpmSubtree.csv
        } else {
            $nonIpmSubtree = Get-PublicFolder \non_ipm_subtree -Recurse -ResultSize Unlimited |
                Select-Object Identity, EntryId, DumpsterEntryId |
                ForEach-Object {
                    $progressCount++
                    $currentFolder = $_.Identity.ToString()
                    try {
                        # Updating progress too often has a perf impact, so we only update every 100 folders.
                        if ($sw.ElapsedMilliseconds -gt 1000) {
                            $sw.Restart()
                            Write-Progress @progressParams -Status $progressCount
                        }

                        [PSCustomObject]@{
                            Identity        = $_.Identity.ToString()
                            EntryId         = $_.EntryId.ToString()
                            DumpsterEntryId = if ($_.DumpsterEntryId) { $_.DumpsterEntryId.ToString() } else { $null }
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
                $nonIpmSubtree | Export-Csv $PSScriptRoot\NonIpmSubtree.csv
            }
        } else {
            $nonIpmSubtree = @()
        }

        Write-Progress @progressParams -Completed

        Write-Host "Get-NonIpmSubtree duration $((Get-Date) - $startTime) folder count $($nonIpmSubtree.Count)"

        return $nonIpmSubtree
    }
}
