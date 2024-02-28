# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
function Get-ProcessedServerList {
    [CmdletBinding()]
    param(
        [string[]]$ExchangeServerNames,

        [string[]]$SkipExchangeServerNames,

        [bool]$CheckOnline,

        [bool]$DisableGetExchangeServerFullList
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $getExchangeServer = New-Object System.Collections.Generic.List[object]
        $validExchangeServer = New-Object System.Collections.Generic.List[object]
        $validExchangeServerFqdn = New-Object System.Collections.Generic.List[string]
        $onlineExchangeServer = New-Object System.Collections.Generic.List[object]
        $onlineExchangeServerFqdn = New-Object System.Collections.Generic.List[string]
    }
    process {
        if ($DisableGetExchangeServerFullList) {
            # If we don't want to get all the Exchange Servers, then we need to make sure the list of Servers are Exchange Server
            if ($null -eq $ExchangeServerNames -or
                $ExchangeServerNames.Count -eq 0) {
                throw "Must provide servers to process when DisableGetExchangeServerFullList is set."
            }

            Write-Verbose "Getting the result of the Exchange Servers individually"
            foreach ($server in $ExchangeServerNames) {
                try {
                    $result = Get-ExchangeServer $server -ErrorAction Stop
                    $getExchangeServer.Add($result)
                } catch {
                    Write-Verbose "Failed to run Get-ExchangeServer for server '$server'. Inner Exception $_"
                    throw
                }
            }
        } else {
            Write-Verbose "Getting all the Exchange Servers in the organization"
            $result = @(Get-ExchangeServer)
            $getExchangeServer.AddRange($result)
        }

        if ($null -ne $ExchangeServerNames -and $ExchangeServerNames.Count -gt 0) {
            $getExchangeServer |
                Where-Object { ($_.Name -in $ExchangeServerNames) -or ($_.FQDN -in $ExchangeServerNames) } |
                ForEach-Object {
                    if ($null -ne $SkipExchangeServerNames -and $SkipExchangeServerNames.Count -gt 0) {
                        if (($_.Name -notin $SkipExchangeServerNames) -and ($_.FQDN -notin $SkipExchangeServerNames)) {
                            Write-Verbose "Adding Server $($_.Name) to the valid server list"
                            $validExchangeServer.Add($_)
                        }
                    } else {
                        Write-Verbose "Adding Server $($_.Name) to the valid server list"
                        $validExchangeServer.Add($_)
                    }
                }
        } else {
            if ($null -ne $SkipExchangeServerNames -and $SkipExchangeServerNames.Count -gt 0) {
                $getExchangeServer |
                    Where-Object { ($_.Name -notin $SkipExchangeServerNames) -and ($_.FQDN -notin $SkipExchangeServerNames) } |
                    ForEach-Object {
                        Write-Verbose "Adding Server $($_.Name) to the valid server list"
                        $validExchangeServer.Add($_)
                    }
            } else {
                Write-Verbose "Adding Server $($_.Name) to the valid server list"
                $validExchangeServer.AddRange($getExchangeServer)
            }
        }

        $validExchangeServer | ForEach-Object { $validExchangeServerFqdn.Add($_.FQDN ) }

        if ($CheckOnline) {
            Write-Verbose "Will check to see if the servers are online"
            foreach ($server in $validExchangeServer) {
                $result = Invoke-ScriptBlockHandler -ComputerName $server -ScriptBlock { return $env:COMPUTERNAME }

                if ($null -ne $result) {
                    $onlineExchangeServer.Add($server)
                    $onlineExchangeServerFqdn.Add($Server.FQDN)
                } else {
                    Write-Verbose "Server $($server.Name) not online"
                }
            }
        }
    }
    end {
        return [PSCustomObject]@{
            ValidExchangeServer      = $validExchangeServer
            ValidExchangeServerFqdn  = $validExchangeServerFqdn
            GetExchangeServer        = $getExchangeServer
            OnlineExchangeServer     = $onlineExchangeServer
            OnlineExchangeServerFqdn = $onlineExchangeServerFqdn
        }
    }
}
