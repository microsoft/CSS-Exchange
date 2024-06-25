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
        [Parameter(Mandatory = $true, ParameterSetName = 'AllowMultipleSessions')]
        [string]$Prefix = $null
    )

    #Validate EXO 3.0 is installed and loaded
    $requestModule = $false
    $requestModule = Request-Module -Modules "ExchangeOnlineManagement" -MinModuleVersion 3.0.0

    if (-not $requestModule) {
        Write-Host "We cannot continue without ExchangeOnlineManagement Powershell module" -ForegroundColor Red
        return $null
    }

    #Validate EXO is connected or try to connect
    $connections = $null
    $newConnection = $null
    $connections = Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' }

    if ($null -eq $connections -or $AllowMultipleSessions) {
        if ($connections.ModulePrefix -contains $Prefix) {
            Write-Host "You already have a session with the prefix $Prefix" -ForegroundColor Red
            return $null
        } else {
            Write-Host "Not connected to Exchange Online" -ForegroundColor Yellow -NoNewline
            if ($Prefix) { Write-Host "with Prefix $Prefix" }
            if ($PSCmdlet.ShouldProcess("Do you want to add it?", "Adding an Exchange Online Session")) {
                Write-Verbose "Connecting to Exchange Online session"
                Connect-ExchangeOnline -ShowBanner:$false -ErrorAction SilentlyContinue -Prefix $Prefix
                $newConnections = Get-ConnectionInformation -ErrorAction SilentlyContinue
                foreach ($testConnection in $newConnections) {
                    if ($connections -notcontains $testConnection) {
                        $newConnection = $testConnection
                    }
                }
            }
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
