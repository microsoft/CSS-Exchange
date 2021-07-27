# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Write-ScriptOutput.ps1
Function Write-BasicMailboxInformation {
    [CmdletBinding()]
    param(
        [object]$MailboxInformation
    )
    process {
        Write-ScriptOutput ""
        Write-ScriptOutput "----------------------------------------"
        Write-ScriptOutput "Basic Mailbox Information:"
        Write-ScriptOutput "Mailbox GUID = $($MailboxInformation.MailboxGuid)"
        Write-ScriptOutput "Mailbox Database: $($MailboxInformation.Database)"
        Write-ScriptOutput "Active Server: $($MailboxInformation.PrimaryServer)"
        Write-ScriptOutput "Exchange Server Version: $($MailboxInformation.ExchangeServer.AdminDisplayVersion)"
        Write-ScriptOutput "----------------------------------------"
        Write-ScriptOutput ""
        Write-ScriptOutput "Big Funnel Count Information Based Off Get-MailboxStatistics"
        Write-DisplayObjectInformation -DisplayObject $MailboxInformation.MailboxStatistics -PropertyToDisplay @(
            "BigFunnelMessageCount",
            "BigFunnelIndexedCount",
            "BigFunnelPartiallyIndexedCount",
            "BigFunnelNotIndexedCount",
            "BigFunnelCorruptedCount",
            "BigFunnelStaleCount",
            "BigFunnelShouldNotBeIndexedCount"
        )
        Write-ScriptOutput "----------------------------------------"
        Write-ScriptOutput ""
        Write-ScriptOutput ($MailboxInformation.MailboxStatistics | Format-List) -Diagnostic
        Write-ScriptOutput "" -Diagnostic
        Write-ScriptOutput ($MailboxInformation.DatabaseStatus | Format-List) -Diagnostic
        Write-ScriptOutput "" -Diagnostic
        Write-ScriptOutput ($MailboxInformation.DatabaseCopyStatus | Format-List) -Diagnostic
        Write-ScriptOutput "" -Diagnostic
        Write-ScriptOutput ($MailboxInformation.MailboxInfo | Format-List) -Diagnostic
        Write-ScriptOutput "" -Diagnostic
    }
}
