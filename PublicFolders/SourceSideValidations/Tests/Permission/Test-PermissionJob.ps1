# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-BadPermissionJob {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [string]
        $Server,

        [Parameter(Position = 1)]
        [string]
        $Mailbox,

        [Parameter(Position = 2)]
        [PSCustomObject[]]
        $Folders
    )

    begin {
        $WarningPreference = "SilentlyContinue"
        Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) | Out-Null
        $startTime = Get-Date
        $progressCount = 0
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Checking permissions in mailbox $Mailbox"
        }
        $validACLableRecipientTypes = @(
            "ACLableSyncedMailboxUser",
            "ACLableMailboxUser",
            "SecurityDistributionGroup")
    }

    process {
        $Folders | ForEach-Object {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                $elapsed = ((Get-Date) - $startTime)
                $estimatedRemaining = [TimeSpan]::FromTicks($Folders.Count / $progressCount * $elapsed.Ticks - $elapsed.Ticks).ToString("hh\:mm\:ss")
                Write-Progress @progressParams -Status "$progressCount / $($Folders.Count) Estimated time remaining: $estimatedRemaining" -PercentComplete ($progressCount * 100 / $Folders.Count)
            }

            $identity = $_.Identity.ToString()
            $entryId = $_.EntryId.ToString()
            $permissions = Get-PublicFolderClientPermission $entryId
            foreach ($permission in $permissions) {
                if (
                    ($permission.User.DisplayName -ne "Default") -and
                    ($permission.User.DisplayName -ne "Anonymous")
                ) {
                    if (
                        ($null -eq $permission.User.ADRecipient) -and
                        ($permission.User.UserType.ToString() -eq "Unknown")
                    ) {
                        # We can't use New-TestResult here since we are inside a job
                        [PSCustomObject]@{
                            TestName       = "Permission"
                            ResultType     = "BadPermission"
                            Severity       = "Error"
                            FolderIdentity = $identity
                            FolderEntryId  = $entryId
                            ResultData     = $permission.User.DisplayName
                        }
                    }

                    if (
                        ($null -ne $permission.User.ADRecipient) -and
                        ($permission.User.ADRecipient.RecipientDisplayType.ToString() -notin $validACLableRecipientTypes)
                    ) {
                        $id = $permission.User.ADRecipient.PrimarySmtpAddress.ToString()
                        if ($id -eq "") {
                            $id = $permission.User.ADRecipient.Identity
                        }

                        # We can't use New-TestResult here since we are inside a job
                        [PSCustomObject]@{
                            TestName       = "Permission"
                            ResultType     = "NonACLableRecipient"
                            Severity       = "Error"
                            FolderIdentity = $identity
                            FolderEntryId  = $entryId
                            ResultData     = $id
                        }
                    }
                }
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed
        [PSCustomObject]@{
            TestName       = "Permission"
            ResultType     = "$Mailbox Duration"
            Severity       = "Information"
            FolderIdentity = ""
            FolderEntryId  = ""
            ResultData     = ((Get-Date) - $startTime)
        }
    }
}
