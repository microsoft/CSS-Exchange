# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function funcUltArchive {
    param(
        [string]$mbx
    )
    $m = get-mailbox $mbx
    $mbxLocations = Get-MailboxLocation -User $m.Identity
    Write-Host ""
    Write-Host ""
    Write-Host "There is a total of $($mbxLocations.Count-2) auxiliary archive mailboxes for [$strMailbox]."
    Write-Host ""
    Write-Host ""
    Write-Host "Archive mailbox statistics:"
    Write-Host ""
    Write-Host "Mailbox Type`tMailbox GUID`t`t`t`t`t`t`tMailbox Size(MB)"
    Write-Host "-------------------------------------------------------------------------------"
    $totalArchiveSize = 0
    foreach ($x in $mbxLocations) {
        if ($x.MailboxLocationType -ne "Primary") {
            $stats = Get-MailboxStatistics -Identity ($x.MailboxGuid).Guid | Select-Object @{name = "TotalItemSize"; expression = { [math]::Round(($_.TotalItemSize.ToString().Split("(")[1].Split(" ")[0].Replace(",", "") / 1MB), 2) } }
            Write-Host "$($x.MailboxLocationType)`t`t$($x.MailboxGUID)`t$($stats.TotalItemSize)"
            if ($stats) {
                $totalArchiveSize = $totalArchiveSize + $stats.TotalItemSize
            }
        }
    }
    Write-Host "-------------------------------------------------------------------------------"
    Write-Host "Total archive size:`t`t`t`t$totalArchiveSize MB"
    Write-Host ""
    Write-Host ""
    Write-Host ""
}
