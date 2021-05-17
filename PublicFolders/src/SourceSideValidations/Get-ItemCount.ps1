function Get-ItemCount {
    <#
    .SYNOPSIS
        Populates the ItemCount property on our PSCustomObjects.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [string]
        $Server,

        [Parameter(Position = 1)]
        [object[]]
        $FolderList = $null
    )

    begin {
        $WarningPreference = "SilentlyContinue"
        if ($null -eq $FolderList) {
            Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) | Out-Null
        }

        $progressCount = 0
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Getting public folder statistics"
        }
    }

    process {
        if ($null -eq $FolderList) {
            $itemCounts = Get-PublicFolderStatistics -ResultSize Unlimited | ForEach-Object {
                $progressCount++
                if ($sw.ElapsedMilliseconds -gt 1000) {
                    $sw.Restart()
                    Write-Progress @progressParams -Status $progressCount
                }

                Select-Object -InputObject $_ -Property EntryId, ItemCount
            }
        } else {
            $itemCounts = New-Object System.Collections.ArrayList
            foreach ($folder in $FolderList) {
                $progressCount++
                if ($sw.ElapsedMilliseconds -gt 1000) {
                    $sw.Restart()
                    Write-Progress @progressParams -Status $progressCount
                }

                $stats = Get-PublicFolderStatistics $folder.EntryId | Select-Object EntryId, ItemCount
                $itemCounts.Add($stats)
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed

        return [PSCustomObject]@{
            ItemCounts = $itemCounts
        }
    }
}
