# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ItemCountJob {
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
        $retryDelay = [TimeSpan]::FromMinutes(5)
        $WarningPreference = "SilentlyContinue"
        Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) | Out-Null
        $startTime = Get-Date
        $progressCount = 0
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Getting public folder statistics"
        }

        $itemCounts = New-Object System.Collections.ArrayList
        $errors = New-Object System.Collections.ArrayList
    }

    process {
        $ErrorActionPreference = "Stop" # So our try/catch works
        $itemCounts = New-Object System.Collections.ArrayList
        foreach ($folder in $Folders) {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress @progressParams -Status $progressCount
            }

            $maxRetries = 5
            for ($retryCount = 1; $retryCount -le $maxRetries; $retryCount++) {
                try {
                    $stats = Get-PublicFolderStatistics $folder.EntryId | Select-Object EntryId, ItemCount
                    [void]$itemCounts.Add($stats)
                    break
                } catch {
                    # Only retry Kerberos errors
                    if ($_.ToString().Contains("Kerberos")) {
                        $sw.Restart()
                        while ($sw.ElapsedMilliseconds -lt $retryDelay.TotalMilliseconds) {
                            Write-Progress @progressParams -Status "Retry $retryCount of $maxRetries. Error: $($_.Message)"
                            Start-Sleep -Seconds 5
                            $remainingMilliseconds = $retryDelay.TotalMilliseconds - $sw.ElapsedMilliseconds
                            if ($remainingMilliseconds -lt 0) { $remainingMilliseconds = 0 }
                            Write-Progress @progressParams -Status "Retry $retryCount of $maxRetries. Will retry in $([TimeSpan]::FromMilliseconds($remainingMilliseconds))"
                            Start-Sleep -Seconds 5
                        }

                        Get-PSSession | Remove-PSSession
                        Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) -AllowClobber | Out-Null
                    } else {
                        $errorReport = @{
                            TestName       = "Get-ItemCount"
                            ResultType     = "CouldNotGetItemCount"
                            Severity       = "Error"
                            FolderIdentity = $folder.Identity
                            FolderEntryId  = $folder.EntryId
                            ResultData     = $_.ToString()
                        }

                        [void]$errors.Add($errorReport)
                    }
                }
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed
        $duration = ((Get-Date) - $startTime)
        return [PSCustomObject]@{
            ItemCounts = $itemCounts
            Errors     = $errors
            Duration   = $duration
        }
    }
}
