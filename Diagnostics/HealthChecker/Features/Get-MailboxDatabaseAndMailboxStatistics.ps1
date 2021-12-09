# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-MailboxDatabaseAndMailboxStatistics {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $AllDBs = Get-MailboxDatabaseCopyStatus -server $Script:Server -ErrorAction SilentlyContinue
    $MountedDBs = $AllDBs | Where-Object { $_.ActiveCopy -eq $true }

    if ($MountedDBs.Count -gt 0) {
        Write-Grey("`tActive Database:")
        foreach ($db in $MountedDBs) {
            Write-Grey("`t`t" + $db.Name)
        }
        $MountedDBs.DatabaseName | ForEach-Object { Write-Verbose "Calculating User Mailbox Total for Active Database: $_"; $TotalActiveUserMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited).Count }
        Write-Grey("`tTotal Active User Mailboxes on server: " + $TotalActiveUserMailboxCount)
        $MountedDBs.DatabaseName | ForEach-Object { Write-Verbose "Calculating Public Mailbox Total for Active Database: $_"; $TotalActivePublicFolderMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited -PublicFolder).Count }
        Write-Grey("`tTotal Active Public Folder Mailboxes on server: " + $TotalActivePublicFolderMailboxCount)
        Write-Grey("`tTotal Active Mailboxes on server " + $Script:Server + ": " + ($TotalActiveUserMailboxCount + $TotalActivePublicFolderMailboxCount).ToString())
    } else {
        Write-Grey("`tNo Active Mailbox Databases found on server " + $Script:Server + ".")
    }

    $HealthyDbs = $AllDBs | Where-Object { $_.Status -match 'Healthy' }

    if ($HealthyDbs.count -gt 0) {
        Write-Grey("`r`n`tPassive Databases:")
        foreach ($db in $HealthyDbs) {
            Write-Grey("`t`t" + $db.Name)
        }
        $HealthyDbs.DatabaseName | ForEach-Object { Write-Verbose "`tCalculating User Mailbox Total for Passive Healthy Databases: $_"; $TotalPassiveUserMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited).Count }
        Write-Grey("`tTotal Passive user Mailboxes on Server: " + $TotalPassiveUserMailboxCount)
        $HealthyDbs.DatabaseName | ForEach-Object { Write-Verbose "`tCalculating Passive Mailbox Total for Passive Healthy Databases: $_"; $TotalPassivePublicFolderMailboxCount += (Get-Mailbox -Database $_ -ResultSize Unlimited -PublicFolder).Count }
        Write-Grey("`tTotal Passive Public Mailboxes on server: " + $TotalPassivePublicFolderMailboxCount)
        Write-Grey("`tTotal Passive Mailboxes on server: " + ($TotalPassiveUserMailboxCount + $TotalPassivePublicFolderMailboxCount).ToString())
    } else {
        Write-Grey("`tNo Passive Mailboxes found on server " + $Script:Server + ".")
    }
}
