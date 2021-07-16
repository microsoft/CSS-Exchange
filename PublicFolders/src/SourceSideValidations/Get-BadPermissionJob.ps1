# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-BadPermissionJob {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Incorrect rule result')]
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
        $badPermissions = @()
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
                    $badPermissions += [PSCustomObject]@{
                        Identity = $identity
                        EntryId  = $entryId
                        User     = $_.User.DisplayName
                    }
                }
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed
        $duration = ((Get-Date) - $startTime)
        return [PSCustomObject]@{
            Count          = $progressCount
            Duration       = $duration
            BadPermissions = $badPermissions
        }
    }
}
