Function Get-MailboxStatisticsOnDatabase {
    [CmdletBinding()]
    param(
        [string[]]$MailboxDatabase
    )
    begin {
        $mailboxStatisticsList = New-Object 'System.Collections.Generic.List[object]'
    }
    process {

        foreach ($database in $MailboxDatabase) {
            Get-MailboxStatistics -Database $database |
                ForEach-Object {

                    if ($_.DisplayName -notlike "SystemMailbox*" -and
                        $_.DisplayName -notlike "*HealthMailbox-*") {
                        $mailboxStatisticsList.Add([PSCustomObject]@{
                                DisplayName                      = $_.DisplayName
                                DatabaseName                     = $_.DatabaseName
                                ServerName                       = $_.ServerName
                                AssociatedItemCount              = $_.AssociatedItemCount
                                DeletedItemCount                 = $_.DeletedItemCount
                                ItemCount                        = $_.ItemCount
                                SystemMessageCount               = $_.SystemMessageCount
                                BigFunnelMessageCount            = $_.BigFunnelMessageCount
                                BigFunnelIndexedCount            = $_.BigFunnelIndexedCount
                                BigFunnelPartiallyIndexedCount   = $_.BigFunnelPartiallyIndexedCount
                                BigFunnelNotIndexedCount         = $_.BigFunnelNotIndexedCount
                                BigFunnelCorruptedCount          = $_.BigFunnelCorruptedCount
                                BigFunnelStaleCount              = $_.BigFunnelStaleCount
                                BigFunnelShouldNotBeIndexedCount = $_.BigFunnelShouldNotBeIndexedCount
                            })
                    }
                }
        }
    }
    end {
        return $mailboxStatisticsList
    }
}
