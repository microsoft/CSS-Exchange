# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
Collection of function to help manage Exchange sessions.
Within a true EMS launch (on an Exchange Server Launch EMS) there is a function called Connect-ExchangeServer.
When Connect-ExchangeServer is used, we set the $global:remoteSession to be the current session that we are using.
This can be used to determine the Primary Session to be able to restore to it afterwards if need be.
NOTE: When using these functions, EMS will need to be required and Connect-ExchangeServer will need to be a valid cmdlet.
When on a Tools box where we load EMS, Connect-ExchangeServer needs to be loaded again by the following:
. $global:exBin"CommonConnectFunctions.ps1"
. $global:exBin"ConnectFunctions.ps1"
#>

. $PSScriptRoot\Invoke-CatchActionError.ps1
function Switch-ExchangeConnectedServer {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerFqdn,
        [ScriptBlock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        if ($null -eq $Script:CachedExchangePsSession) {
            $Script:CachedExchangePsSession = [PSCustomObject]@{
                PrimarySession   = $remoteSession
                ActiveSessionKey = $remoteSession.ComputerName
                Sessions         = @{
                    $remoteSession.ComputerName = $remoteSession
                }
            }
        }
        $result = $false
    }
    process {
        try {
            if (-not ($Script:CachedExchangePsSession.Sessions.ContainsKey($ServerFqdn))) {
                Write-Verbose "Calling Connect-ExchangeServer to connect to $ServerFqdn"
                Connect-ExchangeServer $ServerFqdn -AllowClobber
                $Script:CachedExchangePsSession.ActiveSessionKey = $ServerFqdn
                $Script:CachedExchangePsSession.Sessions.Add(($remoteSession.ComputerName), $remoteSession)
            } elseif ($Script:CachedExchangePsSession.ActiveSessionKey -ne $ServerFqdn) {
                Write-Verbose "Calling Import-Module as we already have it cached."
                $switchToSession = $Script:CachedExchangePsSession.Sessions[$ServerFqdn]
                $serverName = $switchToSession.ComputerName
                $modulePath = "$env:APPDATA\Microsoft\Exchange\RemotePowerShell\$serverName"
                Import-Module -Name $modulePath -ArgumentList $switchToSession -DisableNameChecking
                $Script:CachedExchangePsSession.ActiveSessionKey = $ServerFqdn
            } else {
                Write-Verbose "Already on active session for this server"
            }
            $result = $true
        } catch {
            Write-Verbose "Failed to Connect-ExchangeServer"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        return $result
    }
}

# Use this function at the end of the script to revert back to the primary server
function Invoke-RevertExchangeConnectServerToPrimary {
    [CmdletBinding()]
    param(
        [ScriptBlock]$CatchActionFunction
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        try {
            if ($null -ne $Script:CachedExchangePsSession) {
                $primarySession = $Script:CachedExchangePsSession.PrimarySession

                if ($Script:CachedExchangePsSession.ActiveSessionKey -ne $Script:CachedExchangePsSession.PrimarySession.ComputerName) {
                    Write-Verbose "Calling Connect-ExchangeServer to primary session"
                    Connect-ExchangeServer $primarySession.ComputerName -AllowClobber
                    Remove-PSSession $remoteSession
                }

                foreach ($key in $Script:CachedExchangePsSession.Sessions.Keys) {
                    $session = $Script:CachedExchangePsSession.Sessions[$key]

                    if ($session -ne $primarySession) {
                        Write-Verbose "Removing session for $key"
                        Remove-PSSession $session
                    }
                }

                $Script:CachedExchangePsSession = $null
            }
        } catch {
            Invoke-CatchActionError $CatchActionFunction
        }
    }
}
