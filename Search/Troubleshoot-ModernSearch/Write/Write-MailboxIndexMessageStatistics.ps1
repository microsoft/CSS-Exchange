# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\StoreQuery\Get-StoreQueryMailboxMessagesByCategory.ps1
. $PSScriptRoot\WriteHelpers.ps1
function Write-MailboxIndexMessageStatistics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$BasicMailboxQueryContext,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$MailboxStatistics,

        [Parameter(Mandatory = $true)]
        [ValidateSet("All", "Indexed", "PartiallyIndexed", "NotIndexed", "Corrupted", "Stale", "ShouldNotBeIndexed")]
        [string[]]$Category,

        [bool]$GroupMessages

    )

    process {
        $totalIndexableItems = ($MailboxStatistics.AssociatedItemCount + $MailboxStatistics.ItemCount + $MailboxStatistics.DeletedItemCount) - $MailboxStatistics.BigFunnelShouldNotBeIndexedCount

        Write-Host ""
        Write-Host "All Indexable Items Count: $totalIndexableItems"
        Write-Host ""

        foreach ($categoryType in $Category) {

            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            [array]$messages = Get-StoreQueryMailboxMessagesByCategory -BasicMailboxQueryContext $BasicMailboxQueryContext -Category $categoryType
            Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to get the mailbox index message stats for $($messages.count) messages"

            if ($messages.Count -gt 0) {

                if (-not $GroupMessages) {

                    foreach ($message in $messages) {
                        Write-Host "---------------------"
                        Write-DisplayObjectInformation -DisplayObject $message -PropertyToDisplay @(
                            "FolderId",
                            "MessageId",
                            "InternetMessageId",
                            "MessageSubject",
                            "MessageClass",
                            "BigFunnelPOISize",
                            "BigFunnelPOIIsUpToDate",
                            "IndexingErrorCode",
                            "IndexingErrorMessage",
                            "CondensedErrorMessage",
                            "ErrorTags",
                            "ErrorProperties",
                            "LastIndexingAttemptTime",
                            "IsPermanentFailure",
                            "IndexStatus",
                            "DateCreated"
                        )
                    }
                    continue
                }

                $groupedStatus = $messages | Group-Object IndexStatus, MessageClass

                foreach ($statusGrouping in $groupedStatus) {
                    Write-Host "---------------------"
                    Write-Host "Message Index Status: $($statusGrouping.Name)"
                    Write-Host "---------------------"
                    $groupedResults = $statusGrouping.Group |
                        Group-Object CondensedErrorMessage, IsPermanentFailure |
                        Sort-Object Count -Descending
                    foreach ($result in $groupedResults) {

                        $earliestLastIndexingAttemptTime = [DateTime]::MaxValue
                        $lastIndexingAttemptTime = [DateTime]::MinValue

                        foreach ($groupEntry in $groupedResults.Group) {

                            if ($groupEntry.LastIndexingAttemptTime -ne "NULL" -and
                                $groupEntry.LastIndexingAttemptTime -gt $lastIndexingAttemptTime) {
                                $lastIndexingAttemptTime = $groupEntry.LastIndexingAttemptTime
                            }

                            if ($groupEntry.LastIndexingAttemptTime -ne "NULL" -and
                                $groupEntry.LastIndexingAttemptTime -lt $earliestLastIndexingAttemptTime) {
                                $earliestLastIndexingAttemptTime = $groupEntry.LastIndexingAttemptTime
                            }
                        }

                        # Set to NULL if we are set to the default times.
                        # If NULL is set, that means all items in the group don't have a value set.
                        if ($lastIndexingAttemptTime -eq [DateTime]::MinValue) {
                            $lastIndexingAttemptTime = "NULL"
                        }

                        if ($earliestLastIndexingAttemptTime -eq [DateTime]::MaxValue) {
                            $earliestLastIndexingAttemptTime = "NULL"
                        }

                        $obj = [PSCustomObject]@{
                            TotalItems                      = $result.Count
                            ErrorMessage                    = $result.Values[0]
                            IsPermanentFailure              = $result.Values[1]
                            EarliestLastIndexingAttemptTime = $earliestLastIndexingAttemptTime
                            LastIndexingAttemptTime         = $lastIndexingAttemptTime
                        }

                        Write-DisplayObjectInformation -DisplayObject $obj -PropertyToDisplay @(
                            "TotalItems",
                            "ErrorMessage",
                            "IsPermanentFailure",
                            "EarliestLastIndexingAttemptTime",
                            "LastIndexingAttemptTime")
                        Write-Host ""
                    }
                }
            } else {
                Write-Host "Failed to find any results when doing a search on the category $categoryType"
            }
        }
    }
}
