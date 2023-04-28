# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-StoreQueryMailboxMessagesByCategory.ps1
. $PSScriptRoot\..\..\Write\Write-BasicMailboxInformation.ps1
. $PSScriptRoot\..\..\Write\WriteHelpers.ps1

<#
    Used to collect the messages from a single mailbox based off the category type
    Will proceed to collect the messages based off each category type
    Then will display that information after each category collection to make it less of a day for the display
    At the end, return all the messages to the caller that was found for this user.
#>
function Invoke-MailboxMessagesForCategory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$MailboxInformation,

        [Parameter(Mandatory = $true)]
        [ValidateSet("All", "Indexed", "PartiallyIndexed", "NotIndexed", "Corrupted", "Stale", "ShouldNotBeIndexed")]
        [string[]]$Category,

        [bool]$GroupMessages
    )
    begin {
        $messagesForMailbox = New-Object 'System.Collections.Generic.List[object]'
        $basicMailboxQueryContext = Get-StoreQueryBasicMailboxQueryContext -StoreQueryHandler (Get-StoreQueryObject -MailboxInformation $MailboxInformation)
    }
    process {
        foreach ($categoryType in $Category) {
            [array]$messages = Get-StoreQueryMailboxMessagesByCategory -BasicMailboxQueryContext $basicMailboxQueryContext -Category $categoryType

            if ($messages.Count -eq 0) {
                Write-Host "Failed to find any results when doing a search on the category $categoryType"
                continue
            }

            if (-not $GroupMessages) {
                foreach ($message in $messages) {
                    #TODO: Add a break line somewhere
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
            } else {
                # Group the messages to make a simplified view
                $groupedStatus = $messages | Group-Object IndexStatus, MessageClass

                foreach ($statusGrouping in $groupedStatus) {
                    Write-DashLineBox "Message Index Status: $($statusGrouping.Name)"
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
            }
            $messagesForMailbox.AddRange($messages)
        }
    }
    end {
        return $messagesForMailbox
    }
}
