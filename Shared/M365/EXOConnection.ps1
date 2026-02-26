# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
This script defines a function `Connect-EXOAdvanced` that establishes a connection to Exchange Online.
It ensures that the required ExchangeOnlineManagement module (version 3.0.0 or higher by default) is installed and loaded.
The function supports single and multiple session connections, with optional parameters to control the connection details display and session prefix.
If the required module is not found, the script attempts to install it.
The function returns the connection information or null if the connection fails.

.PARAMETER DoNotShowConnectionDetails
 Optional switch to hide connection details.
.PARAMETER AllowMultipleSessions
 Optional switch to allow multiple sessions.
.PARAMETER Prefix
 Optional string to specify a prefix for the session.
.PARAMETER MinModuleVersion
 Optional parameter to specify the minimum version of the ExchangeOnlineManagement module (default and minimum supported version is 3.0.0).

.OUTPUTS
Microsoft.Exchange.Management.ExoPowershellSnapin.ConnectionInformation. The connection information object for the Exchange Online session.

.EXAMPLE
$exoConnection = Connect-EXOAdvanced
This example establishes a connection to Exchange Online using the default settings.

.EXAMPLE
$exoConnection = Connect-EXOAdvanced -AllowMultipleSessions
This example establishes a connection to Exchange Online and allows multiple sessions.

.EXAMPLE
$exoConnection = Connect-EXOAdvanced -AllowMultipleSessions -Prefix Con2
This example establishes a connection to Exchange Online, allows multiple sessions, and specifies a prefix "Con2" for the session.

.EXAMPLE
$exoConnection2 = Connect-EXOAdvanced -MinModuleVersion 3.5.0
This example establishes a connection to Exchange Online and specifies a minimum module version of 3.5.0.
#>

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
        [string]$Prefix = $null,
        [ValidateScript({
                if ($_ -lt [System.Version]'3.0.0.0') {
                    throw "Minimum supported version: 3.0.0.0"
                }
                $true
            })]
        [Parameter(Mandatory = $false, ParameterSetName = 'SingleSession')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AllowMultipleSessions')]
        [System.Version]$MinModuleVersion = '3.0.0.0'
    )

    #Validate EXO 3.0 is installed and loaded
    $requestModule = Request-Module -Module "ExchangeOnlineManagement" -MinModuleVersion $MinModuleVersion

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
        if ($connections | Where-Object { $_.ModulePrefix -eq $Prefix }) {
            Write-Host "You already have a session" -ForegroundColor Yellow -NoNewline
            if ($Prefix) {
                Write-Host " with the prefix $Prefix." -ForegroundColor Yellow
            } else {
                Write-Host " without prefix." -ForegroundColor Yellow
            }
            $newConnection = $connections | Where-Object { $_.ModulePrefix -eq $Prefix } | Select-Object -First 1
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
        if (@($newConnection).Count -gt 1) {
            Write-Host "You have more than one Exchange Online sessions with Prefix $Prefix.`nPlease use just one session with same Prefix." -ForegroundColor Red
            return $null
        }
    } else {
        Write-Verbose "You already have an Exchange Online session"
        if (@($connections).Count -gt 1) {
            Write-Host "You have more than one Exchange Online sessions.`nPlease use just one session as you are not using AllowMultipleSessions" -ForegroundColor Red
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
