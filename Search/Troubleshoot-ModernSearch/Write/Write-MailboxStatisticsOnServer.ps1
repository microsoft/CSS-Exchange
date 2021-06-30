# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Exchange\Get-ActiveDatabasesOnServer.ps1
. $PSScriptRoot\..\Exchange\Get-MailboxInformation.ps1
. $PSScriptRoot\..\Exchange\Get-MailboxStatisticsOnDatabase.ps1
. $PSScriptRoot\..\Exchange\Get-SearchProcessState.ps1
. $PSScriptRoot\Write-ScriptOutput.ps1
Function Write-MailboxStatisticsOnServer {
    [CmdletBinding()]
    param(
        [string[]]$Server,
        [string]$SortByProperty,
        [bool]$ExcludeFullyIndexedMailboxes,
        [bool]$ExportData
    )
    begin {

        switch ($SortByProperty) {
            "TotalSearchableItems" { $SortByProperty = "TotalBigFunnelSearchableItems" }
            "IndexedCount" { $SortByProperty = "BigFunnelIndexedCount" }
            "NotIndexedCount" { $SortByProperty = "BigFunnelNotIndexedCount" }
            "PartIndexedCount" { $SortByProperty = "BigFunnelPartiallyIndexedCount" }
            "CorruptedCount" { $SortByProperty = "BigFunnelCorruptedCount" }
            "StaleCount" { $SortByProperty = "BigFunnelStaleCount" }
            "ShouldNotIndexCount" { $SortByProperty = "BigFunnelShouldNotBeIndexedCount" }
        }

        $sortObjectDescending = $true

        if ($SortByProperty -eq "FullyIndexPercentage") {
            $sortObjectDescending = $false
        }
    }
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
            Where-Object {
                if ($ExcludeFullyIndexedMailboxes -and
                    $_.FullyIndexPercentage -eq 100) {
                } else {
                    return $_
                }
            } |
            Sort-Object $SortByProperty -Descending:$sortObjectDescending

        $problemMailboxes |
            Select-Object MailboxGuid, `
            @{Name = "TotalSearchableItems"; Expression = { $_.TotalBigFunnelSearchableItems } },
            @{Name = "IndexedCount"; Expression = { $_.BigFunnelIndexedCount } },
            @{Name = "NotIndexedCount"; Expression = { $_.BigFunnelNotIndexedCount } },
            @{Name = "PartIndexedCount"; Expression = { $_.BigFunnelPartiallyIndexedCount } } ,
            @{Name = "CorruptedCount"; Expression = { $_.BigFunnelCorruptedCount } },
            @{Name = "StaleCount"; Expression = { $_.BigFunnelStaleCount } },
            @{Name = "ShouldNotIndexCount"; Expression = { $_.BigFunnelShouldNotBeIndexedCount } },
            FullyIndexPercentage,
            IndexPercentage |
            Format-Table |
            Out-String |
            ForEach-Object { Write-ScriptOutput $_ }

        if ($ExportData) {
            $filePath = "$PSScriptRoot\MailboxStatistics_$(([DateTime]::Now).ToString('yyyyMMddhhmmss')).csv"
            Write-ScriptOutput "Exporting Full Mailbox Stats out to: $filePath"
            $mailboxStats | Export-Csv -Path $filePath
        }

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
                $category = Get-CategoryOffStatistics -MailboxStatistics $mailboxInformation.MailboxStatistics

                Write-MailboxIndexMessageStatistics -BasicMailboxQueryContext (
                    Get-BasicMailboxQueryContext -StoreQueryHandler (
                        Get-StoreQueryObject -MailboxInformation $mailboxInformation)) `
                    -MailboxStatistics $mailboxInformation.MailboxStatistics `
                    -Category $category `
                    -GroupMessages $true
            }
    }
}
