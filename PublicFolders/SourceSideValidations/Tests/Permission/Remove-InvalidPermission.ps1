# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Remove-InvalidPermission {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $TestResult
    )

    begin {
        $progressParams = @{
            Activity = "Repairing folder permissions"
        }

        $progressCount = 0
        $entryIdsProcessed = New-Object 'System.Collections.Generic.HashSet[string]'
        $badPermissions = New-Object System.Collections.ArrayList

        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
    }

    process {
        if ($TestResult.TestName -eq "Permission" -and $TestResult.ResultType -eq "BadPermission") {
            [void]$badPermissions.Add($TestResult)
        }
    }

    end {
        foreach ($result in $badPermissions) {
            $progressCount++

            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress @progressParams -Status "$progressCount / $($badPermissions.Count)" -PercentComplete ($progressCount * 100 / $badPermissions.Count) -CurrentOperation $permission.Identity
            }

            if ($entryIdsProcessed.Add($result.FolderEntryId)) {
                $permsOnFolder = Get-PublicFolderClientPermission -Identity $result.FolderEntryId
                foreach ($perm in $permsOnFolder) {
                    if (
                        ($perm.User.DisplayName -ne "Default") -and
                        ($perm.User.DisplayName -ne "Anonymous") -and
                        ($null -eq $perm.User.ADRecipient) -and
                        ($perm.User.UserType -eq "Unknown")
                    ) {
                        if ($PSCmdlet.ShouldProcess("$($result.FolderIdentity)", "Remove $($perm.User.DisplayName)")) {
                            Write-Host "Removing $($perm.User.DisplayName) from folder $($result.FolderIdentity)"
                            $perm | Remove-PublicFolderClientPermission -Confirm:$false
                        }
                    }
                }
            }
        }
    }
}
