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
    }

    process {
        if (-not $startFresh -and (Test-Path $PSScriptRoot\NonIpmSubtree.csv)) {
            Write-Progress -Activity "Reading NON_IPM_SUBTREE from file"
            $nonIpmSubtree = Import-Csv $PSScriptRoot\NonIpmSubtree.csv
        } else {
            $nonIpmSubtree = Get-PublicFolder \non_ipm_subtree -Recurse -ResultSize Unlimited |
                Select-Object Identity, EntryId, DumpsterEntryId |
                ForEach-Object {
                    $currentFolder = $_.Identity.ToString()
                    try {
                        # Updating progress too often has a perf impact, so we only update every 100 folders.
                        if (++$progressCount % 100 -eq 0) {
                            Write-Progress -Activity "Retrieving NON_IPM_SUBTREE folders" -Status $progressCount
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
                Write-Progress -Activity "Saving NON_IPM_SUBTREE to a file"
                $nonIpmSubtree | Export-Csv $PSScriptRoot\NonIpmSubtree.csv
            }
        } else {
            $nonIpmSubtree = @()
        }

        Write-Host "Get-NonIpmSubtree duration $((Get-Date) - $startTime) folder count $($nonIpmSubtree.Count)"

        return $nonIpmSubtree
    }
}
