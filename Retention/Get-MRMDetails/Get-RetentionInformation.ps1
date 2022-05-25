# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function GetByteQuantifiedSize {
    param(
        [object]$Object
    )

    if ($null -eq $Object) { Write-Debug "testing" -Debug }

    if ($null -ne $Object.Value -and
        $Object.Value.GetType().ToString() -eq "Microsoft.Exchange.Data.ByteQuantifiedSize") {
        return $Object.Value.ToBytes()
    } else {
        $Object = $Object.ToString()

        if ($Object -eq "Unlimited") { return -1 }

        $startIndex = $Object.IndexOf("(")
        [uint64]$bytes = $Object.Substring($startIndex, ($Object.IndexOf(" bytes") - $startIndex) ).Replace(",", "")
        return $bytes
    }
}

function Get-RetentionInformation {
    param(
        [object]$Mailbox
    )
    $retentionPolicies = Get-RetentionPolicy
    [array]$environmentTags = Get-RetentionPolicyTag

    $environmentTags |
        ForEach-Object {
            $_ | Add-Member -MemberType NoteProperty -Name "OctetRetentionIDAsSeenInMFCMAPI" -Value ([System.String]::Join("", ($_.RetentionId.ToByteArray() | ForEach-Object { $_.ToString(‘x2’) })).ToUpper())
        }

    # Mailbox Stats
    $mailboxStatistics = Get-MailboxStatistics $Mailbox.ExchangeGuid.ToString()
    $mailboxFolderStatistics = Get-MailboxFolderStatistics $Mailbox.ExchangeGuid.ToString()
    $totalItemSizeBytes = GetByteQuantifiedSize $mailboxStatistics.TotalItemSize
    $totalDeletedItemSizeBytes = GetByteQuantifiedSize $mailboxStatistics.TotalDeletedItemSize
    $recoverableItemsQuotaBytes = GetByteQuantifiedSize $Mailbox.RecoverableItemsQuota
    [int]$primaryRecoveryItemFillQuotaPercentage = $totalDeletedItemSizeBytes / $recoverableItemsQuotaBytes * 100

    # get archive information
    if ($null -ne $Mailbox.ArchiveDatabase -and
        $Mailbox.ArchiveGuid.ToString() -ne "00000000-0000-0000-0000-000000000000") {
        $archiveMailboxStatistics = Get-MailboxStatistics $Mailbox.ExchangeGuid.ToString() -Archive
        $archiveMailboxFolderStatistics = Get-MailboxFolderStatistics $Mailbox.ExchangeGuid.ToString() -Archive
        $archiveQuotaBytes = GetByteQuantifiedSize $Mailbox.ArchiveQuota

        # TODO: Test this out
        #Archive Mailbox Recoverable Items quota does not appear to be visible to admins in PowerShell.  However, recoverable Items quota can be inferred from 3 properties
        #Those properties are the RecoverableItemsQuota of the primary mailbox, Litigation Hold and In-Place Hold.  https://technet.microsoft.com/en-us/library/mt668450.aspx
        $archiveRecoverableItemsQuotaBytes = $recoverableItemsQuotaBytes
        $archiveTotalItemSizeBytes = GetByteQuantifiedSize $archiveMailboxStatistics.TotalItemSize
        $archiveTotalDeletedItemSizeBytes = GetByteQuantifiedSize $archiveMailboxStatistics.TotalDeletedItemSize
        [int]$archiveTotalFillPercentage = $archiveTotalItemSizeBytes / $archiveQuotaBytes * 100
        [int]$archiveRecoveryItemFillQuotaPercentage = $archiveTotalDeletedItemSizeBytes / $archiveRecoverableItemsQuotaBytes * 100
    }

    $mailboxRetentionPolicy = $retentionPolicies | Where-Object { $_.Name -eq $Mailbox.RetentionPolicy }
    $mailboxRetentionTags = $mailboxRetentionPolicy.RetentionPolicyTagLinks |
        ForEach-Object {
            $tagId = $_.ObjectGuid
            $environmentTags | Where-Object { $_.RetentionId -eq $tagId }
        }

    return [PSCustomObject]@{
        MailboxStatistics                      = $mailboxStatistics
        MailboxFolderStatistics                = $mailboxFolderStatistics
        TotalItemSize                          = $totalItemSizeBytes
        TotalDeletedItemSize                   = $totalDeletedItemSizeBytes
        RecoverableItemsQuota                  = $recoverableItemsQuotaBytes
        RecoveryItemFillQuotaPercentage        = $primaryRecoveryItemFillQuotaPercentage
        ArchiveMailboxStatistics               = $archiveMailboxStatistics
        ArchiveMailboxFolderStatistics         = $archiveMailboxFolderStatistics
        ArchiveQuota                           = $archiveQuotaBytes
        ArchiveRecoverableItemsQuota           = $archiveRecoverableItemsQuotaBytes
        ArchiveTotalItemSize                   = $archiveTotalItemSizeBytes
        ArchiveTotalDeletedItemSize            = $archiveTotalDeletedItemSizeBytes
        ArchiveTotalFillPercentage             = $archiveTotalFillPercentage
        ArchiveRecoveryItemFillQuotaPercentage = $archiveRecoveryItemFillQuotaPercentage
        RetentionPolicies                      = $retentionPolicies
        RetentionTags                          = $environmentTags
        MailboxRetentionPolicy                 = $mailboxRetentionPolicy
        MailboxRetentionTags                   = $mailboxRetentionTags
    }
}
