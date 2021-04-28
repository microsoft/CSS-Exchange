Function Get-StoreQueryHandler {
    [CmdletBinding()]
    param(
        [object]$MailboxInformation
    )
    begin {
        $Server = [string]::Empty
        $ProcessId = $null

        Function ResetQueryInstances {
            $this.IsUnlimited = $false
            $this.SelectPartQuery = [string]::Empty
            $this.FromPartQuery = [string]::Empty
            $this.WherePartQuery = [string]::Empty
        }

        Function SetSelect {
            param(
                [string[]]$Value
            )

            [string]$temp = $Value |
                ForEach-Object { "$_," }
            $this.SelectPartQuery = $temp.TrimEnd(",")
        }

        Function AddToSelect {
            param(
                [string[]]$Value
            )

            [string]$temp = $Value |
                ForEach-Object { "$_," }
            $this.SelectPartQuery = "$($this.SelectPartQuery), $($temp.TrimEnd(","))"
        }

        Function SetFrom {
            param(
                [string]$Value
            )

            $this.FromPartQuery = $Value
        }

        Function SetWhere {
            param(
                [string]$Value
            )

            $this.WherePartQuery = $Value
        }

        Function AddToWhere {
            param(
                [string]$Value
            )

            $this.WherePartQuery = "$($this.WherePartQuery)$Value"
        }

        Function InvokeGetStoreQuery {

            if (-not([string]::IsNullOrEmpty($this.WherePartQuery))) {
                $query = "SELECT $($this.SelectPartQuery) FROM $($this.FromPartQuery) WHERE $($this.WherePartQuery)"
            } else {
                $query = "SELECT $($this.SelectPartQuery) FROM $($this.FromPartQuery)"
            }

            $myParams = @{
                Server    = $this.Server
                ProcessId = $this.ProcessId
                Query     = $query
                Unlimited = $this.IsUnlimited
            }

            Write-Verbose "Running 'Get-StoreQuery -Server $($this.Server) -ProcessId $($this.ProcessId) -Unlimited:$($this.IsUnlimited) -Query `"$query`"'"
            $result = @(Get-StoreQuery @myParams)

            if ($result.DiagnosticQueryException.Count -gt 0) {
                Write-Verbose "Get-StoreQuery DiagnosticQueryException : $($result.DiagnosticQueryException)"
                Write-Error "Get-StoreQuery DiagnosticQueryException : $($result.DiagnosticQueryException)"
            } elseif ($result.DiagnosticQueryTranslatorException.Count -gt 0) {
                Write-Verbose "Get-StoreQuery DiagnosticQueryTranslatorException : $($result.DiagnosticQueryTranslatorException)"
                Write-Error "Get-StoreQuery DiagnosticQueryTranslatorException : $($result.DiagnosticQueryTranslatorException)"
            }

            return $result
        }
    }
    process {

        $ProcessId = $MailboxInformation.DBWorkerID
        $Server = $MailboxInformation.PrimaryServer
        $MailboxGuid = $MailboxInformation.MailboxGuid
    }
    end {
        $obj = [PSCustomObject]@{
            Server          = $Server
            ProcessId       = $ProcessId
            IsUnlimited     = $false
            SelectPartQuery = [string]::Empty
            FromPartQuery   = [string]::Empty
            WherePartQuery  = [string]::Empty
            MailboxGuid     = $MailboxGuid
        }

        $obj | Add-Member -MemberType ScriptMethod -Name "ResetQueryInstances" -Value ${Function:ResetQueryInstances}
        $obj | Add-Member -MemberType ScriptMethod -Name "SetSelect" -Value ${Function:SetSelect}
        $obj | Add-Member -MemberType ScriptMethod -Name "AddToSelect" -Value ${Function:AddToSelect}
        $obj | Add-Member -MemberType ScriptMethod -Name "SetFrom" -Value ${Function:SetFrom}
        $obj | Add-Member -MemberType ScriptMethod -Name "SetWhere" -Value ${Function:SetWhere}
        $obj | Add-Member -MemberType ScriptMethod -Name "AddToWhere" -Value ${Function:AddToWhere}
        $obj | Add-Member -MemberType ScriptMethod -Name "InvokeGetStoreQuery" -Value ${Function:InvokeGetStoreQuery}

        return $obj
    }
}
