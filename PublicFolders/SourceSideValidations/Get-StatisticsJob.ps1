# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-StatisticsJob {
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
        $statistics = New-Object System.Collections.ArrayList
        $errors = New-Object System.Collections.ArrayList
        $permanentFailureOccurred = $false
        $retryDelay = [TimeSpan]::FromMinutes(5)
        $WarningPreference = "SilentlyContinue"
        $Error.Clear()
        Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) -AllowClobber | Out-Null
        if ($Error.Count -gt 0) {
            $permanentFailureOccurred = $true
            foreach ($err in $Error) {
                $errorReport = @{
                    TestName       = "Get-Statistics"
                    ResultType     = "ImportSessionFailure"
                    Severity       = "Error"
                    FolderIdentity = ""
                    FolderEntryId  = ""
                    ResultData     = $err.ToString()
                }

                [void]$errors.Add($errorReport)
            }
        }

        if (-not $permanentFailureOccurred -and $null -eq (Get-Command Get-PublicFolderStatistics -ErrorAction SilentlyContinue)) {
            $permanentFailureOccurred = $true
            $errorReport = @{
                TestName       = "Get-Statistics"
                ResultType     = "CommandNotFound"
                Severity       = "Error"
                FolderIdentity = ""
                FolderEntryId  = ""
                ResultData     = ""
            }

            [void]$errors.Add($errorReport)
        }

        $startTime = Get-Date
        $progressCount = 0
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Getting public folder statistics"
        }
    }

    process {
        if ($permanentFailureOccurred) {
            return
        }

        $ErrorActionPreference = "Stop" # So our try/catch works
        $statistics = New-Object System.Collections.ArrayList
        foreach ($folder in $Folders) {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress @progressParams -Status $progressCount
            }

            $maxRetries = 5
            for ($retryCount = 1; $retryCount -le $maxRetries; $retryCount++) {
                try {
                    $stats = Get-PublicFolderStatistics $folder.EntryId | Select-Object EntryId, ItemCount, TotalItemSize

                    [Int64]$totalItemSize = -1
                    if ($stats.TotalItemSize.ToString() -match "\(([\d|,|.]+) bytes\)") {
                        $totalItemSize = [Int64]::Parse($Matches[1], "AllowThousands")
                    }

                    [void]$statistics.Add([PSCustomObject]@{
                            EntryId       = $stats.EntryId
                            ItemCount     = $stats.ItemCount
                            TotalItemSize = $totalItemSize
                        })
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
                            TestName       = "Get-Statistics"
                            ResultType     = "CouldNotGetStatistics"
                            Severity       = "Error"
                            FolderIdentity = $folder.Identity
                            FolderEntryId  = $folder.EntryId
                            ResultData     = $_.ToString()
                        }

                        [void]$errors.Add($errorReport)

                        break
                    }
                }
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed
        $duration = ((Get-Date) - $startTime)
        return [PSCustomObject]@{
            Statistics = $statistics
            Errors     = $errors
            Duration   = $duration
        }
    }
}
