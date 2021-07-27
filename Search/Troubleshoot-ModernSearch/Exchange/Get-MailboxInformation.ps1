# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Dependencies are based off EMS cmdlets.
Function Get-MailboxInformation {
    [CmdletBinding()]
    param(
        [string]
        $Identity,

        [bool]
        $IsArchive,

        [bool]
        $IsPublicFolder
    )

    begin {
        $diagnosticContext = New-Object 'System.Collections.Generic.List[string]'
        $breadCrumb = 0
    }

    process {

        try {
            $diagnosticContext.Add("Get-MailboxInformation $($breadCrumb; $breadCrumb++)")
            $mailboxInfo = Get-Mailbox -Identity $Identity -PublicFolder:$IsPublicFolder -Archive:$IsArchive -ErrorAction Stop

            if ($IsArchive) {
                $mbxGuid = $mailboxInfo.ArchiveGuid.ToString()
                $databaseName = $mailboxInfo.ArchiveDatabase.ToString()
            } else {
                $mbxGuid = $mailboxInfo.ExchangeGuid.ToString()
                $databaseName = $mailboxInfo.Database.ToString()
            }

            $diagnosticContext.Add("Get-MailboxInformation $($breadCrumb; $breadCrumb++)")
            $mailboxStats = Get-MailboxStatistics -Identity $Identity -Archive:$IsArchive

            $diagnosticContext.Add("Get-MailboxInformation $($breadCrumb; $breadCrumb++)")
            $dbCopyStatus = Get-MailboxDatabaseCopyStatus $databaseName\* |
                Where-Object {
                    $_.Status -like "*Mounted*"
                }
            $primaryServer = $dbCopyStatus.Name.Substring($dbCopyStatus.Name.IndexOf("\") + 1)

            $diagnosticContext.Add("Get-MailboxInformation $($breadCrumb; $breadCrumb++)")
            $primaryServerInfo = Get-ExchangeServer -Identity $primaryServer

            if ($primaryServerInfo.AdminDisplayVersion.ToString() -notlike "Version 15.2*") {
                throw "User isn't on an Exchange 2019 server"
            }

            $diagnosticContext.Add("Get-MailboxInformation $($breadCrumb; $breadCrumb++)")
            $dbStatus = Get-MailboxDatabase -Identity $databaseName -Status

            $diagnosticContext.Add("Get-MailboxInformation $($breadCrumb; $breadCrumb++)")
        } catch {
            throw "Failed to find '$Identity' information. InnerException: $($Error[0].Exception)"
        }
    }
    end {
        return [PSCustomObject]@{
            Identity           = $Identity
            MailboxGuid        = $mbxGuid
            PrimaryServer      = $primaryServer
            DBWorkerID         = $dbStatus.WorkerProcessId
            Database           = $databaseName
            ExchangeServer     = $primaryServerInfo
            DatabaseStatus     = $dbStatus
            DatabaseCopyStatus = $dbCopyStatus
            MailboxInfo        = $mailboxInfo
            MailboxStatistics  = $mailboxStats
            DiagnosticContext  = $diagnosticContext
        }
    }
}
