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
            Get-PublicFolderClientPermission $entryId | ForEach-Object {
                if (
                    ($_.User.DisplayName -ne "Default") -and
                    ($_.User.DisplayName -ne "Anonymous") -and
                    ($null -eq $_.User.ADRecipient) -and
                    ($_.User.UserType.ToString() -eq "Unknown")
                ) {
                    # We can't use New-TestResult here since we are inside a job
                    [PSCustomObject]@{
                        TestName       = "Permission"
                        ResultType     = "BadPermission"
                        Severity       = "Error"
                        FolderIdentity = $identity
                        FolderEntryId  = $entryId
                        ResultData     = $_.User.DisplayName
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
