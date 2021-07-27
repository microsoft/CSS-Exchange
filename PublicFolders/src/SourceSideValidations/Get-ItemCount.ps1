# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. .\Get-ItemCountJob.ps1

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
        [PSCustomObject]
        $FolderData = $null
    )

    begin {
        Write-Verbose "$($MyInvocation.MyCommand) called."
        $progressFile = Join-Path $PSScriptRoot "ItemCountProgress.csv"
        if (Test-Path $progressFile) {
            Remove-Item $progressFile
        }

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
        if ($null -eq $FolderData) {
            $WarningPreference = "SilentlyContinue"
            Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) | Out-Null
            $itemCounts = Get-PublicFolderStatistics -ResultSize Unlimited | ForEach-Object {
                $progressCount++
                if ($sw.ElapsedMilliseconds -gt 1000) {
                    $sw.Restart()
                    Write-Progress @progressParams -Status $progressCount
                }

                Select-Object -InputObject $_ -Property EntryId, ItemCount
            }
        } else {
            $batchSize = 10000
            $jobsToCreate = New-Object 'System.Collections.Generic.Dictionary[string, System.Collections.ArrayList]'
            foreach ($group in $folderData.IpmSubtreeByMailbox) {
                # MailboxToServerMap is not populated yet, so we can't use it here
                $server = (Get-Mailbox $group.Name -PublicFolder).ServerName
                [int]$mailboxBatchCount = ($group.Group.Count / $batchSize) + 1
                Write-Verbose "Creating $mailboxBatchCount item count jobs for $($group.Group.Count) folders in mailbox $($group.Name) on server $server."
                $jobsForThisMailbox = New-Object System.Collections.ArrayList
                for ($i = 0; $i -lt $mailboxBatchCount; $i++) {
                    $batch = $group.Group | Select-Object -First $batchSize -Skip ($batchSize * $i)
                    $argumentList = $server, $group.Name, $batch
                    $jobsForThisMailbox.Add(@{
                            ArgumentList = $argumentList
                            Name         = "Item Count $($group.Name) Job $($i + 1)"
                            ScriptBlock  = ${Function:Get-ItemCountJob}
                        })
                }

                $jobsToCreate.Add($group.Name, $jobsForThisMailbox)
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

            $foldersDone = 0
            Wait-QueuedJob | ForEach-Object {
                $foldersDone += $_.ItemCounts.Count
                Write-Verbose "Retrieved item counts for $foldersDone folders so far..."
                $itemCounts.AddRange($_.ItemCounts)
                $errors.AddRange($_.Errors)

                if ($_.ItemCounts.Count -gt 0) {
                    $_.ItemCounts | Export-Csv -Path $progressFile -Append
                }
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed

        Remove-Item $progressFile

        return [PSCustomObject]@{
            ItemCounts = $itemCounts
            Errors     = $errors
        }
    }
}
