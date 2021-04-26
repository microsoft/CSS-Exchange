Function Write-MailboxIndexMessageStatistics {
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
        [string[]]$Category

    )

    process {
        $totalIndexableItems = ($MailboxStatistics.AssociatedItemCount + $MailboxStatistics.ItemCount) - $MailboxStatistics.BigFunnelShouldNotBeIndexedCount

        Receive-Output ""
        Receive-Output "All Indexable Items Count: $totalIndexableItems"
        Receive-Output ""

        foreach ($categoryType in $Category) {

            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            [array]$messages = Get-MailboxIndexMessageStatistics -BasicMailboxQueryContext $BasicMailboxQueryContext -Category $categoryType
            Receive-Output "Took $($stopWatch.Elapsed.TotalSeconds) seconds to get the mailbox index message stats for $($messages.count) messages" -Diagnostic

            if ($messages.Count -gt 0) {

                $groupedStatus = $messages | Group-Object MessageStatus

                foreach ($statusGrouping in $groupedStatus) {
                    Receive-Output "---------------------"
                    Receive-Output "Message Index Status: $($statusGrouping.Name)"
                    Receive-Output "---------------------"
                    $groupedResults = $statusGrouping.Group | Group-Object IndexingErrorMessage, IsPermanentFailure
                    foreach ($result in $groupedResults) {

                        $earliestLastIndexingAttemptTime = [DateTime]::MaxValue
                        $lastIndexingAttemptTime = [DateTime]::MinValue

                        foreach ($groupEntry in $groupedResults.Group) {

                            if ($groupEntry.LastIndexingAttemptTime -gt $lastIndexingAttemptTime) {
                                $lastIndexingAttemptTime = $groupEntry.LastIndexingAttemptTime
                            }

                            if ($groupEntry.LastIndexingAttemptTime -lt $earliestLastIndexingAttemptTime) {
                                $earliestLastIndexingAttemptTime = $groupEntry.LastIndexingAttemptTime
                            }
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
                        Receive-Output ""
                    }
                }
            } else {
                Receive-Output "Failed to find any results when doing a search on the category $categoryType"
            }
        }
    }
}
