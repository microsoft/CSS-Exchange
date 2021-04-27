. $PSScriptRoot\..\Exchange\Get-ActiveDatabasesOnServer.ps1
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
            Select-Object DisplayName, ServerName, ItemCount, BigFunnelMessageCount, BigFunnelIndexedCount, BigFunnelNotIndexedCount |
            Sort-Object BigFunnelNotIndexedCount -Descending

        $problemMailboxes | Format-Table |
            Out-String |
            ForEach-Object { Write-ScriptOutput $_ }
    }
}
