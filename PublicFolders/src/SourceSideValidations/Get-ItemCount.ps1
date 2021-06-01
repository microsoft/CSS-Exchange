function Get-ItemCount {
    <#
    .SYNOPSIS
        Gets the item count for each folder.
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

        $retryDelay = [TimeSpan]::FromMinutes(5)
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

                $maxRetries = 5
                for ($retryCount = 1; $retryCount -le $maxRetries; $retryCount++) {
                    try {
                        $stats = Get-PublicFolderStatistics $folder.EntryId | Select-Object EntryId, ItemCount
                        $itemCounts.Add($stats)
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
                        } else {
                            $errorReport = @{
                                TestName       = "Get-ItemCount"
                                ResultType     = "CouldNotGetItemCount"
                                Severity       = "Error"
                                FolderIdentity = $folder.Identity
                                FolderEntryId  = $folder.EntryId
                                ResultData     = $_.ToString()
                            }

                            $error = New-TestResult @errorReport
                            $errors.Add($error)
                        }
                    }
                }
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed

        return [PSCustomObject]@{
            ItemCounts = $itemCounts
            Errors     = $errors
        }
    }
}
