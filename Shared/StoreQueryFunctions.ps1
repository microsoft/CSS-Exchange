# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Write-ErrorInformation.ps1
function ResetQueryInstances {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [object]
        $Query
    )
    process {
        $Query.IsUnlimited = $false
        $Query.SelectPartQuery = [string]::Empty
        $Query.FromPartQuery = [string]::Empty
        $Query.WherePartQuery = [string]::Empty
        $Query
    }
}

function SetSelect {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [object]
        $Query,

        [Parameter(Mandatory = $true)]
        [string[]]$Value
    )
    process {
        [string]$temp = $Value |
            ForEach-Object { "$_," }
        $Query.SelectPartQuery = $temp.TrimEnd(",")
        $Query
    }
}

function AddToSelect {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [object]$Query,

        [Parameter(Mandatory = $true)]
        [string[]]$Value
    )
    process {
        [string]$temp = $Value |
            ForEach-Object { "$_," }
        $Query.SelectPartQuery = "$($Query.SelectPartQuery), $($temp.TrimEnd(","))"
        $Query
    }
}

function SetFrom {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [object]$Query,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )
    process {
        $Query.FromPartQuery = $Value
        $Query
    }
}

function SetWhere {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [object]$Query,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )
    process {
        $Query.WherePartQuery = $Value
        $Query
    }
}

function AddToWhere {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [object]$Query,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )
    process {
        $Query.WherePartQuery = "$($Query.WherePartQuery)$Value"
        $Query
    }
}

function InvokeGetStoreQuery {
    [CmdletBinding()]
    [OutputType("System.Object[]")]
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [object]$Query
    )
    process {
        if (-not([string]::IsNullOrEmpty($Query.WherePartQuery))) {
            $queryString = "SELECT $($Query.SelectPartQuery) FROM $($Query.FromPartQuery) WHERE $($Query.WherePartQuery)"
        } else {
            $queryString = "SELECT $($Query.SelectPartQuery) FROM $($Query.FromPartQuery)"
        }

        $myParams = @{
            Server    = $Query.Server
            ProcessId = $Query.ProcessId
            Query     = $queryString
            Unlimited = $Query.IsUnlimited
        }

        Write-Verbose "Running 'Get-StoreQuery -Server $($Query.Server) -ProcessId $($Query.ProcessId) -Unlimited:`$$($Query.IsUnlimited) -Query `"$queryString`"'"
        $result = @(Get-StoreQuery @myParams)

        if ($result.GetType().ToString() -ne "System.Object[]" -or
            $result.Count -le 1) {
            if ($null -ne ($result.DiagnosticQueryException)) {
                Write-Error "Get-StoreQuery DiagnosticQueryException : $($result.DiagnosticQueryException)"
            } elseif ($null -ne ($result.DiagnosticQueryTranslatorException)) {
                Write-Error "Get-StoreQuery DiagnosticQueryTranslatorException : $($result.DiagnosticQueryTranslatorException)"
            } elseif ($null -ne ($result.DiagnosticQueryParserException)) {
                Write-Error "Get-StoreQuery DiagnosticQueryParserException : $($result.DiagnosticQueryParserException)"
            }
        }

        return $result
    }
}

# the function used to get the mailbox information required for Get-StoreQueryObject
function Get-StoreQueryMailboxInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Identity,

        [bool]
        $IsArchive,

        [bool]
        $IsPublicFolder
    )
    process {
        try {
            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            Write-Verbose "Attempting to run Get-Mailbox"
            Write-Verbose "Identity: '$Identity' IsArchive: $IsArchive IsPublicFolder: $IsPublicFolder"
            $mailboxInfo = Get-Mailbox -Identity $Identity -PublicFolder:$IsPublicFolder -Archive:$IsArchive -ErrorAction Stop

            if ($IsArchive) {
                $mbxGuid = $mailboxInfo.ArchiveGuid.ToString()
                $databaseName = $mailboxInfo.ArchiveDatabase.ToString()
            } else {
                $mbxGuid = $mailboxInfo.ExchangeGuid.ToString()
                $databaseName = $mailboxInfo.Database.ToString()
            }

            Write-Verbose "Attempting to run Get-MailboxStatistics"
            $mailboxStatistics = Get-MailboxStatistics -Identity $Identity -Archive:$IsArchive

            Write-Verbose "Attempting to run Get-MailboxDatabaseCopyStatus"
            $dbCopyStatus = Get-MailboxDatabaseCopyStatus $databaseName\* |
                Where-Object { $_.Status -like "*Mounted*" }
            $primaryServer = $dbCopyStatus.MailboxServer

            Write-Verbose "Running Get-ExchangeServer for primary server: $primaryServer"
            $primaryServerInfo = Get-ExchangeServer -Identity $primaryServer

            Write-Verbose "Running Get-MailboxDatabase"
            $databaseStatus = Get-MailboxDatabase -Identity $databaseName -Status
        } catch {
            Write-HostErrorInformation $_
            throw "Failed to find '$Identity' information."
        }
    }
    end {
        return [PSCustomObject]@{
            Identity           = $Identity
            MailboxGuid        = $mbxGuid
            PrimaryServer      = $primaryServer
            DBWorkerID         = $dbCopyStatus.WorkerProcessId
            Database           = $databaseName
            ExchangeServer     = $primaryServerInfo
            DatabaseStatus     = $databaseStatus
            DatabaseCopyStatus = $dbCopyStatus
            MailboxInfo        = $mailboxInfo
            MailboxStatistics  = $mailboxStatistics
        }
    }
}

function Get-StoreQueryObject {
    [CmdletBinding()]
    param(
        [object]$MailboxInformation
    )
    $ProcessId = $MailboxInformation.DBWorkerID
    $Server = $MailboxInformation.PrimaryServer
    $MailboxGuid = $MailboxInformation.MailboxGuid
    [PSCustomObject]@{
        Server          = $Server
        ProcessId       = $ProcessId
        IsUnlimited     = $false
        SelectPartQuery = [string]::Empty
        FromPartQuery   = [string]::Empty
        WherePartQuery  = [string]::Empty
        MailboxGuid     = $MailboxGuid
    }
}

# Needs to be executed in main part of script, otherwise, Get-StoreQuery will not load and be able to be called from other functions.
try {
    $installPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    $scriptPath = "$installPath\Scripts\ManagedStoreDiagnosticFunctions.ps1"

    if ((Test-Path $scriptPath)) {
        . $scriptPath
    } else {
        throw "Failed to find $scriptPath"
    }
} catch {
    Write-HostErrorInformation $_
    exit
}
