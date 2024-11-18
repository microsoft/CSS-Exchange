# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\ModuleHandle.ps1

function Connect-EXOAdvanced {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'SingleSession')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AllowMultipleSessions')]
        [switch]$DoNotShowConnectionDetails,
        [Parameter(Mandatory = $true, ParameterSetName = 'AllowMultipleSessions')]
        [switch]$AllowMultipleSessions,
        [Parameter(Mandatory = $false, ParameterSetName = 'AllowMultipleSessions')]
        [string]$Prefix = $null
    )

    #Validate EXO 3.0 is installed and loaded
    $requestModule = Request-Module -Modules "ExchangeOnlineManagement" -MinModuleVersion 3.0.0

    if (-not $requestModule) {
        Write-Host "We cannot continue without ExchangeOnlineManagement Powershell module" -ForegroundColor Red
        return $null
    }

    #Validate EXO is connected or try to connect
    $connections = $null
    $newConnection = $null
    try {
        $connections = Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_.State -eq 'Connected' }
    } catch {
        Write-Host "We cannot check connections. Error:`n$_" -ForegroundColor Red
        return $null
    }

    if ($null -eq $connections -or $AllowMultipleSessions) {
        if ($connections.ModulePrefix -contains $Prefix) {
            Write-Host "You already have a session" -ForegroundColor Yellow -NoNewline
            if ($Prefix) {
                Write-Host " with the prefix $Prefix." -ForegroundColor Yellow
            } else {
                Write-Host " without prefix." -ForegroundColor Yellow
            }
            $newConnection = $connections | Where-Object { $_.ModulePrefix -eq $Prefix }
        } else {
            $prefixString = "."
            if ($Prefix) { $prefixString = " with Prefix $Prefix." }
            Write-Host "Not connected to Exchange Online$prefixString" -ForegroundColor Yellow

            if ($PSCmdlet.ShouldProcess("Do you want to add it?", "Adding an Exchange Online Session")) {
                Write-Verbose "Connecting to Exchange Online session"
                try {
                    Connect-ExchangeOnline -ShowBanner:$false -Prefix $Prefix -ErrorAction Stop
                } catch {
                    Write-Host "We cannot connect to Exchange Online. Error:`n$_" -ForegroundColor Red
                    return $null
                }
                try {
                    $newConnections = Get-ConnectionInformation -ErrorAction Stop
                } catch {
                    Write-Host "We cannot check connections. Error:`n$_" -ForegroundColor Red
                    return $null
                }
                foreach ($testConnection in $newConnections) {
                    if ($connections -notcontains $testConnection) {
                        $newConnection = $testConnection
                    }
                }
            }
        }
        if ($newConnection.count -gt 1) {
            Write-Host "You have more than one Exchange Online sessions with Prefix $Prefix." -ForegroundColor Red
            return $null
        }
    } else {
        Write-Verbose "You already have an Exchange Online session"
        if ($connections.count -gt 1) {
            Write-Host "You have more than one Exchange Online sessions please use just one session. You are not using AllowMultipleSessions" -ForegroundColor Red
            return $null
        }
        $newConnection = $connections
    }

    Write-Verbose "Connected session to Exchange Online"
    $newConnection.PSObject.Properties | ForEach-Object { Write-Verbose "$($_.Name): $($_.Value)" }
    if (-not $DoNotShowConnectionDetails) {
        Show-EXOConnection -Connection $newConnection
    }
    return $newConnection
}

function Show-EXOConnection {
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.Exchange.Management.ExoPowershellSnapin.ConnectionInformation]$Connection
    )
    Write-Host "`nConnected to Exchange Online"
    Write-Host "Session details"
    Write-Host "Tenant Id: $($Connection.TenantId)"
    Write-Host "User: $($Connection.UserPrincipalName)"
    if ($($Connection.ModulePrefix)) {
        Write-Host "Prefix: $($Connection.ModulePrefix)"
    }
}
