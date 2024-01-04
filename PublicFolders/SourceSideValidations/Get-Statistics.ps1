# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-StatisticsJob.ps1

function Get-Statistics {
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
        [PSCustomObject]
        $FolderData = $null
    )

    begin {
        Write-Verbose "$($MyInvocation.MyCommand) called."

        $progressCount = 0
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Getting public folder statistics"
        }

        $statistics = New-Object System.Collections.ArrayList
        $errors = New-Object System.Collections.ArrayList
    }

    process {
        if ($null -eq $FolderData) {
            $WarningPreference = "SilentlyContinue"
            Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) | Out-Null
            $statistics = Get-PublicFolderStatistics -ResultSize Unlimited | ForEach-Object {
                $progressCount++
                if ($sw.ElapsedMilliseconds -gt 1000) {
                    $sw.Restart()
                    Write-Progress @progressParams -Status $progressCount
                }

                [Int64]$totalItemSize = -1
                if ($_.TotalItemSize.ToString() -match "\(([\d|,|.]+) bytes\)") {
                    $numberString = $Matches[1] -replace "\D", ""
                    $totalItemSize = [Int64]::Parse($numberString)
                }

                [PSCustomObject]@{
                    EntryId       = $_.EntryId
                    ItemCount     = $_.ItemCount
                    TotalItemSize = $totalItemSize
                }
            }
        } else {
            $batchSize = 10000
            $jobsToCreate = New-Object 'System.Collections.Generic.Dictionary[string, System.Collections.ArrayList]'
            foreach ($group in $folderData.IpmSubtreeByMailbox) {
                # MailboxToServerMap is not populated yet, so we can't use it here
                $server = (Get-MailboxDatabase (Get-Mailbox -PublicFolder $group.Name).Database).Server.Name
                [int]$mailboxBatchCount = ($group.Group.Count / $batchSize) + 1
                Write-Verbose "Creating $mailboxBatchCount statistics jobs for $($group.Group.Count) folders in mailbox $($group.Name) on server $server."
                $jobsForThisMailbox = New-Object System.Collections.ArrayList
                for ($i = 0; $i -lt $mailboxBatchCount; $i++) {
                    $batch = $group.Group | Select-Object -First $batchSize -Skip ($batchSize * $i)
                    if ($batch.Count -gt 0) {
                        $argumentList = $server, $group.Name, $batch
                        [void]$jobsForThisMailbox.Add(@{
                                ArgumentList = $argumentList
                                Name         = "Statistics $($group.Name) Job $($i + 1)"
                                ScriptBlock  = ${Function:Get-StatisticsJob}
                            })
                    }
                }

                [void]$jobsToCreate.Add($group.Name, $jobsForThisMailbox)
            }

            # Add the jobs by round-robin among the mailboxes so we don't execute all jobs
            # for one mailbox in parallel unless we have to
            $jobsAddedThisRound = 0
            $index = 0
            do {
                $jobsAddedThisRound = 0
                foreach ($mailboxName in $jobsToCreate.Keys) {
                    $batchesForThisMailbox = $jobsToCreate[$mailboxName]
                    if ($batchesForThisMailbox.Count -gt $index) {
                        $jobParams = $batchesForThisMailbox[$index]
                        Add-JobQueueJob $jobParams
                        $jobsAddedThisRound++
                    }
                }

                $index++
            } while ($jobsAddedThisRound -gt 0)

            $hierarchyMailbox = Get-Mailbox -PublicFolder (Get-OrganizationConfig).RootPublicFolderMailbox.ToString()
            $serverWithHierarchy = (Get-MailboxDatabase $hierarchyMailbox.Database).Server.Name
            $retryJobNumber = 1

            Wait-QueuedJob | ForEach-Object {
                $finishedJob = $_
                $statistics.AddRange($finishedJob.Statistics)
                $errors.AddRange($finishedJob.Errors)
                Write-Verbose "Retrieved item counts for $($statistics.Count) folders so far. $($errors.Count) errors encountered."
                if ($finishedJob.PermanentFailure) {
                    # If a permanent failure occurred, re-queue remaining items on the server that has the writable
                    # hierarchy, and hope it works there.
                    Write-Host "Job experienced a permanent failure."
                    if ($finishedJob.Server -eq $serverWithHierarchy) {
                        Write-Host "Permanent failure on root mailbox server is not retryable."
                    } else {
                        $entryIdsProcessed = New-Object 'System.Collections.Generic.HashSet[string]'
                        $finishedJob.Statistics | ForEach-Object { [void]$entryIdsProcessed.Add($_.EntryId) }
                        $foldersRemaining = @($finishedJob.Folders | Where-Object { -not $entryIdsProcessed.Contains($_.EntryId) })
                        if ($foldersRemaining.Count -gt 0) {
                            Write-Host "$($foldersRemaining.Count) folders remaining in the failed job. Re-queueing for $serverWithHierarchy."
                            $retryJob = @{
                                ArgumentList = $serverWithHierarchy, $hierarchyMailbox.Name, $foldersRemaining
                                Name         = "Statistics Retry Job $($retryJobNumber++)"
                                ScriptBlock  = ${Function:Get-StatisticsJob}
                            }

                            Add-JobQueueJob $retryJob
                        }
                    }
                }
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed

        return [PSCustomObject]@{
            Statistics = $statistics
            Errors     = $errors
        }
    }
}
