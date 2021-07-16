# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Dependencies are based off EMS cmdlets.
Function Get-ActiveDatabasesOnServer {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string[]]$Server
    )
    begin {
        $activeDatabasesOnServerList = New-Object 'System.Collections.Generic.List[object]'
    }
    process {

        foreach ($srv in $Server) {

            Get-MailboxDatabaseCopyStatus *\$srv |
                Where-Object {
                    $_.Status -like "*Mounted*"
                } |
                ForEach-Object {
                    $activeDatabasesOnServerList.Add([PSCustomObject]@{
                            DBName = $_.DatabaseName
                            Server = $srv
                        })
                }
        }
    }
    end {
        return $activeDatabasesOnServerList
    }
}
