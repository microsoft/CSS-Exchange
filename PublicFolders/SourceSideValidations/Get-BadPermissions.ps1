function Get-BadPermissions {
    [CmdletBinding()]
    [OutputType("System.Object[]")]
    param (
        [Parameter()]
        [PSCustomObject]
        $FolderData
    )

    begin {
        $startTime = Get-Date
        $progressCount = 0
        $badPermissions = @()
    }

    process {
        $FolderData.IpmSubtree | ForEach-Object {
            if (++$progressCount % 10 -eq 0) {
                $elapsed = ((Get-Date) - $startTime)
                $estimatedRemaining = [TimeSpan]::FromTicks($FolderData.IpmSubtree.Count / $progressCount * $elapsed.Ticks - $elapsed.Ticks).ToString("hh\:mm\:ss")
                Write-Progress -Activity "Checking permissions. Estimated time remaining: $estimatedRemaining" -Status $progressCount -PercentComplete ($progressCount * 100 / $FolderData.IpmSubtree.Count)
            }

            Get-PublicFolderClientPermission $_.EntryId | ForEach-Object {
                if (
                    ($_.User.DisplayName -ne "Default") -and
                    ($_.User.DisplayName -ne "Anonymous") -and
                    ($null -eq $_.User.ADRecipient) -and
                    ($_.User.UserType -eq "Unknown")
                ) {
                    $badPermissions += $_
                }
            }
        }
    }

    end {
        Write-Host "Get-BadPermissions duration" ((Get-Date) - $startTime)
        return $badPermissions
    }
}
