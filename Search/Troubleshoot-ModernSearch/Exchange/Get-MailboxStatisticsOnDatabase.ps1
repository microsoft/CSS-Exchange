﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Get a simple results of Mailbox Statistics of all the mailboxes on the database(s).
# Don't want to store all the mailboxes full mailbox stats as that could be rather large
# and don't require all the information.
function Get-MailboxStatisticsOnDatabase {
    [CmdletBinding()]
    param(
        [string[]]$MailboxDatabase
    )
    begin {
        $mailboxStatisticsList = New-Object 'System.Collections.Generic.List[object]'
        Write-Host "Getting the mailbox statistics of all these databases"
        $MailboxDatabase |
            Out-String |
            Write-Host
        Write-Host "This may take some time..."
        # TODO: Add Write-Progress
    }
    process {

        foreach ($database in $MailboxDatabase) {
            Get-MailboxStatistics -Database $database |
                ForEach-Object {

                    if ($_.DisplayName -notlike "SystemMailbox*" -and
                        $_.DisplayName -notlike "*HealthMailbox-*" -and
                        $_.MailboxTypeDetail.ToString() -ne "ArbitrationMailbox" -and
                        $null -eq $_.DisconnectReason) {

                        $totalMailboxItems = $_.ItemCount + $_.AssociatedItemCount + $_.DeletedItemCount
                        $totalBigFunnelItems = $_.BigFunnelIndexedCount + $_.BigFunnelPartiallyIndexedCount + $_.BigFunnelNotIndexedCount + `
                            $_.BigFunnelCorruptedCount + $_.BigFunnelStaleCount + $_.BigFunnelShouldNotBeIndexedCount
                        $totalBigFunnelSearchableItems = $totalBigFunnelItems - $_.BigFunnelShouldNotBeIndexedCount
                        $fullIndexPercentage = -1
                        $notPartIndexPercentage = -1

                        if ($totalBigFunnelSearchableItems -ne 0) {
                            $fullIndexPercentage = [Math]::Round((($_.BigFunnelIndexedCount / $totalBigFunnelSearchableItems) * 100), 2)
                            $divideBy = $totalBigFunnelSearchableItems - $_.BigFunnelPartiallyIndexedCount

                            if ($divideBy -ne 0) {
                                $notPartIndexPercentage = [Math]::Round((($_.BigFunnelIndexedCount / $divideBy) * 100), 2)
                            }
                        }

                        $mailboxStatisticsList.Add([PSCustomObject]@{
                                MailboxGuid                      = $_.MailboxGuid.ToString()
                                DisplayName                      = $_.DisplayName
                                MailboxType                      = $_.MailboxType.ToString()
                                MailboxTypeDetail                = $_.MailboxTypeDetail.ToString()
                                IsArchiveMailbox                 = $_.IsArchiveMailbox
                                DatabaseName                     = $_.DatabaseName
                                ServerName                       = $_.ServerName
                                AssociatedItemCount              = $_.AssociatedItemCount
                                DeletedItemCount                 = $_.DeletedItemCount
                                ItemCount                        = $_.ItemCount
                                SystemMessageCount               = $_.SystemMessageCount
                                BigFunnelMessageCount            = $_.BigFunnelMessageCount
                                BigFunnelIndexedCount            = $_.BigFunnelIndexedCount
                                BigFunnelPartiallyIndexedCount   = $_.BigFunnelPartiallyIndexedCount
                                BigFunnelNotIndexedCount         = $_.BigFunnelNotIndexedCount
                                BigFunnelCorruptedCount          = $_.BigFunnelCorruptedCount
                                BigFunnelStaleCount              = $_.BigFunnelStaleCount
                                BigFunnelShouldNotBeIndexedCount = $_.BigFunnelShouldNotBeIndexedCount
                                TotalMailboxItems                = $totalMailboxItems
                                TotalBigFunnelItems              = $totalBigFunnelItems
                                TotalBigFunnelSearchableItems    = $totalBigFunnelSearchableItems
                                FullyIndexPercentage             = $fullIndexPercentage
                                IndexPercentage                  = $notPartIndexPercentage
                            })
                    }
                }
        }
    }
    end {
        return $mailboxStatisticsList
    }
}
