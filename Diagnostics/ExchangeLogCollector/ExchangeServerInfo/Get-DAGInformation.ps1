# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-DAGInformation {
    param(
        [Parameter(Mandatory = $true)][string]$DAGName
    )

    try {
        $dag = Get-DatabaseAvailabilityGroup $DAGName -Status -ErrorAction Stop
    } catch {
        Write-ScriptDebug("Failed to run Get-DatabaseAvailabilityGroup on $DAGName")
        Invoke-CatchBlockActions
    }

    try {
        $dagNetwork = Get-DatabaseAvailabilityGroupNetwork $DAGName -ErrorAction Stop
    } catch {
        Write-ScriptDebug("Failed to run Get-DatabaseAvailabilityGroupNetwork on $DAGName")
        Invoke-CatchBlockActions
    }

    #Now to get the Mailbox Database Information for each server in the DAG.
    $cacheDBCopyStatus = @{}
    $mailboxDatabaseInformationPerServer = @{}

    foreach ($server in $dag.Servers) {
        $serverName = $server.ToString()
        $getMailboxDatabases = Get-MailboxDatabase -Server $serverName -Status

        #Foreach of the mailbox databases on this server, we want to know the copy status
        #but we don't want to duplicate this work a lot, so we have a cache feature.
        $getMailboxDatabaseCopyStatusPerDB = @{}
        $getMailboxDatabases |
            ForEach-Object {
                $dbName = $_.Name

                if (!($cacheDBCopyStatus.ContainsKey($dbName))) {
                    $copyStatusForDB = Get-MailboxDatabaseCopyStatus $dbName\* -ErrorAction SilentlyContinue
                    $cacheDBCopyStatus.Add($dbName, $copyStatusForDB)
                } else {
                    $copyStatusForDB = $cacheDBCopyStatus[$dbName]
                }

                $getMailboxDatabaseCopyStatusPerDB.Add($dbName, $copyStatusForDB)
            }

        $serverDatabaseInformation = [PSCustomObject]@{
            MailboxDatabases                = $getMailboxDatabases
            MailboxDatabaseCopyStatusPerDB  = $getMailboxDatabaseCopyStatusPerDB
            MailboxDatabaseCopyStatusServer = (Get-MailboxDatabaseCopyStatus *\$serverName -ErrorAction SilentlyContinue)
        }

        $mailboxDatabaseInformationPerServer.Add($serverName, $serverDatabaseInformation)
    }

    return [PSCustomObject]@{
        DAGInfo             = $dag
        DAGNetworkInfo      = $dagNetwork
        MailboxDatabaseInfo = $mailboxDatabaseInformationPerServer
    }
}
