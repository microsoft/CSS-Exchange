. $PSScriptRoot\..\Exchange\Get-ActiveDatabasesOnServer.ps1
. $PSScriptRoot\..\Exchange\Get-MailboxInformation.ps1
. $PSScriptRoot\..\Exchange\Get-MailboxStatisticsOnDatabase.ps1
. $PSScriptRoot\..\Exchange\Get-SearchProcessState.ps1
. $PSScriptRoot\Write-ScriptOutput.ps1
Function Write-MailboxStatisticsOnServer {
    [CmdletBinding()]
    param(
        [string[]]$Server
    )
    process {
        $activeDatabase = Get-ActiveDatabasesOnServer -Server $Server

        #Check to see the services health on those servers
        $activeDatabase | Group-Object Server |
            ForEach-Object { Write-CheckSearchProcessState -ActiveServer $_.Name }

        Write-ScriptOutput "Getting the mailbox statistics of all these databases"
        $activeDatabase | Format-Table |
            Out-String |
            ForEach-Object { Write-ScriptOutput $_ }
        Write-ScriptOutput "This may take some time..."

        $mailboxStats = Get-MailboxStatisticsOnDatabase -MailboxDatabase $activeDatabase.DBName
        $problemMailboxes = $mailboxStats |
            Where-Object { $_.BigFunnelNotIndexedCount -ne 0 } |
            Select-Object MailboxGuid, DisplayName, ServerName, ItemCount, BigFunnelMessageCount, BigFunnelIndexedCount, BigFunnelNotIndexedCount |
            Sort-Object BigFunnelNotIndexedCount -Descending

        $problemMailboxes | Format-Table |
            Out-String |
            ForEach-Object { Write-ScriptOutput $_ }

        #Get the top 10 mailboxes and their Category information
        Write-ScriptOutput "Getting the top 10 mailboxes category information"
        $problemMailboxes |
            Select-Object -First 10 |
            ForEach-Object {
                Write-ScriptOutput "----------------------------------------"
                $guid = $_.MailboxGuid
                Write-ScriptOutput "Getting user mailbox information for $guid"
                try {
                    $mailboxInformation = Get-MailboxInformation -Identity $guid
                } catch {
                    Write-ScriptOutput "Failed to find mailbox $guid. could be an Archive, Public Folder, or Arbitration Mailbox"
                    return
                }
                Write-BasicMailboxInformation -MailboxInformation $mailboxInformation

                Write-MailboxIndexMessageStatistics -BasicMailboxQueryContext (
                    Get-BasicMailboxQueryContext -StoreQueryHandler (
                        Get-StoreQueryHandler -MailboxInformation $mailboxInformation)) `
                    -MailboxStatistics $mailboxInformation.MailboxStatistics `
                    -Category "NotIndexed"
            }
    }
}
