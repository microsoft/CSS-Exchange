# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function ResetQueryInstances {
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

Function SetSelect {
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

Function AddToSelect {
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

Function SetFrom {
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

Function SetWhere {
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

Function AddToWhere {
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

Function InvokeGetStoreQuery {
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

Function Get-StoreQueryObject {
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
