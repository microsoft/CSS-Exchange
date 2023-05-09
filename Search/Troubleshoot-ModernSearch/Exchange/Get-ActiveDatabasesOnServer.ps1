# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Dependencies are based off EMS cmdlets.
function Get-ActiveDatabasesOnServer {
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

            Get-MailboxDatabaseCopyStatus -Server $srv -Active |
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
