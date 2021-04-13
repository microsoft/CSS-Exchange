function Remove-InvalidPermission {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter()]
        [string]
        $CsvFile
    )

    begin {

        $progressParams = @{
            Activity = "Removing invalid permissions"
        }

        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
    }

    process {

        $badPermissions = Import-Csv $csvFile
        $progressCount = 0
        $entryIdsProcessed = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($permission in $badPermissions) {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress @progressParams -Status "$progressCount / $($badPermissions.Count)" -PercentComplete ($progressCount * 100 / $badPermissions.Count) -CurrentOperation $permission.Identity
            }

            if ($entryIdsProcessed.Add($permission.EntryId)) {
                $permsOnFolder = Get-PublicFolderClientPermission -Identity $permission.EntryId
                $permsOnFolder | ForEach-Object {
                    if (
                        ($_.User.DisplayName -ne "Default") -and
                        ($_.User.DisplayName -ne "Anonymous") -and
                        ($null -eq $_.User.ADRecipient) -and
                        ($_.User.UserType -eq "Unknown")
                    ) {
                        if ($PSCmdlet.ShouldProcess("$($permission.Identity)", "Remove $($_.User.DisplayName)")) {
                            Write-Host "Removing $($_.User.DisplayName) from folder $($permission.Identity)"
                            $_ | Remove-PublicFolderClientPermission -Confirm:$false
                        }
                    }
                }
            }
        }
    }

    end {}
}