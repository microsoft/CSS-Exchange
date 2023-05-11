# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\WriteHelpers.ps1

<#
    Take the object from Get-MailboxInformation and
    quickly display some information about the object to the
    screen that is useful.
#>
function Write-BasicMailboxInformation {
    [CmdletBinding()]
    param(
        [object]$MailboxInformation
    )
    process {
        Write-Host ""

        $display = @(
            "Basic Mailbox Information:",
            "Mailbox GUID = $($MailboxInformation.MailboxGuid)",
            "Mailbox Database: $($MailboxInformation.Database)",
            "Active Server: $($MailboxInformation.PrimaryServer)",
            "Exchange Server Version: $($MailboxInformation.ExchangeServer.AdminDisplayVersion)",
            "Max Send Size: $($MailboxInformation.MailboxInfo.MaxSendSize.ToString())",
            "Max Receive Size: $($MailboxInformation.MailboxInfo.MaxReceiveSize.ToString())",
            "Use Database Quotas: $($MailboxInformation.MailboxInfo.UseDatabaseQuotaDefaults.ToString())",
            "Database Send Quota: $($MailboxInformation.MailboxStatistics.DatabaseProhibitSendQuota.ToString())"
            "Database Send & Receive Quota: $($MailboxInformation.MailboxStatistics.DatabaseProhibitSendReceiveQuota.ToString())"
            "Total Item Size: $($MailboxInformation.MailboxStatistics.TotalItemSize.ToString())",
            "Total Deleted Item Size: $($MailboxInformation.MailboxStatistics.TotalDeletedItemSize.ToString())"

        )
        Write-DashLineBox $display

        if ($MailboxInformation.MailboxInfo.MaxReceiveSize.ToString() -eq "0 B (0 bytes)") {
            Write-Warning "The Max Receive Size is set to 0 Bytes, all messages greater than 1MB will fail to be indexed."
        }

        try {
            # Just in case the objects for size and quotas are not in comparable formats
            if ((-not ($MailboxInformation.MailboxInfo.MaxReceiveSize.ToString() -eq "0 B (0 bytes)")) -and
                (($MailboxInformation.MailboxInfo.UseDatabaseQuotaDefaults -eq $true -and
                    $MailboxInformation.MailboxStatistics.TotalItemSize.Value -ge $MailboxInformation.MailboxStatistics.DatabaseProhibitSendReceiveQuota) -or
                    ($MailboxInformation.MailboxInfo.UseDatabaseQuotaDefaults -eq $false -and
                $MailboxInformation.MailboxStatistics.TotalItemSize.Value -ge $MailboxInformation.MailboxInfo.MaxReceiveSize))) {
                Write-Warning "The mailbox is full, all messages greater than 1MB will fail to be indexed."
            } else {
                Write-Verbose "Mailbox is not full. Indexing should work."
            }
        } catch {
            Write-Verbose "Failed to properly test to see if the mailbox is full causing indexing issues. Must look over this manually."
        }

        Write-Host ""
        Write-Host "Big Funnel Count Information Based Off Get-MailboxStatistics"
        Write-DisplayObjectInformation -DisplayObject $MailboxInformation.MailboxStatistics -PropertyToDisplay @(
            "AssociatedItemCount",
            "ItemCount",
            "DeletedItemCount",
            "BigFunnelMessageCount",
            "BigFunnelIndexedCount",
            "BigFunnelPartiallyIndexedCount",
            "BigFunnelNotIndexedCount",
            "BigFunnelCorruptedCount",
            "BigFunnelStaleCount",
            "BigFunnelShouldNotBeIndexedCount"
        )
        $mailboxStatistics = $MailboxInformation.MailboxStatistics
        $totalIndexableItems = ($mailboxStatistics.AssociatedItemCount + $mailboxStatistics.ItemCount + $mailboxStatistics.DeletedItemCount) - $mailboxStatistics.BigFunnelShouldNotBeIndexedCount
        Write-Host "All Indexable Items Count: $totalIndexableItems"

        Write-Host ""
        $MailboxInformation.MailboxStatistics | Format-List | Out-String | Write-Verbose
        Write-Verbose ""
        $MailboxInformation.DatabaseStatus | Format-List | Out-String | Write-Verbose
        Write-Verbose ""
        $MailboxInformation.DatabaseCopyStatus | Format-List | Out-String | Write-Verbose
        Write-Verbose ""
        $MailboxInformation.MailboxInfo | Format-List | Out-String | Write-Verbose
        Write-Verbose ""
    }
}
