# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-BasicMailboxInformation {
    [CmdletBinding()]
    param(
        [object]$MailboxInformation
    )
    process {
        Write-Host ""
        Write-Host "----------------------------------------"
        Write-Host "Basic Mailbox Information:"
        Write-Host "Mailbox GUID = $($MailboxInformation.MailboxGuid)"
        Write-Host "Mailbox Database: $($MailboxInformation.Database)"
        Write-Host "Active Server: $($MailboxInformation.PrimaryServer)"
        Write-Host "Exchange Server Version: $($MailboxInformation.ExchangeServer.AdminDisplayVersion)"
        Write-Host "----------------------------------------"
        Write-Host ""
        Write-Host "Big Funnel Count Information Based Off Get-MailboxStatistics"
        Write-DisplayObjectInformation -DisplayObject $MailboxInformation.MailboxStatistics -PropertyToDisplay @(
            "BigFunnelMessageCount",
            "BigFunnelIndexedCount",
            "BigFunnelPartiallyIndexedCount",
            "BigFunnelNotIndexedCount",
            "BigFunnelCorruptedCount",
            "BigFunnelStaleCount",
            "BigFunnelShouldNotBeIndexedCount"
        )
        Write-Host "----------------------------------------"
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
