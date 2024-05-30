# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\M365Modules.ps1

function Test-EXOConnection {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [System.Version]$ModuleVersion = $null,
        [Parameter(Mandatory = $false)]
        [switch]$DoNotShowConnectionDetails
    )

    #Validate EXO is installed and loaded
    $loadModule = $false
    if ($ModuleVersion) {
        $loadModule = Request-M365Module -ModuleName "ExchangeOnlineManagement" -MinModuleVersion $ModuleVersion
    } else {
        $loadModule = Request-M365Module -ModuleName "ExchangeOnlineManagement"
    }

    if (-not $loadModule) {
        Write-Host "We cannot continue without ExchangeOnlineManagement Powershell module" -ForegroundColor Red
        return $false
    }

    #Validate EXO is connected or try to connect
    $connection = $null
    $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($null -eq $connection) {
        if ($PSCmdlet.ShouldContinue("Do you want to connect?", "No connection found. We need a ExchangeOnlineManagement connection with Global administrator")) {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction SilentlyContinue
            $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue
            if ($null -eq $connection) {
                Write-Host "Connection could not be established" -ForegroundColor Red
            } else {
                if (-not $DoNotShowConnectionDetails) {
                    Show-EXOConnection -Connection $connection
                }
                return $true
            }
        }
        Write-Host "We cannot continue without ExchangeOnlineManagement Powershell session" -ForegroundColor Red
        return $false
    } elseif ($connection.count -eq 1) {
        if (-not $DoNotShowConnectionDetails) {
            Show-EXOConnection -Connection $connection
        }
        return $true
    } else {
        Write-Host "You have more than one Exchange Online sessions please use just one session" -ForegroundColor Red
        return $false
    }
}

function Show-EXOConnection {
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.Exchange.Management.ExoPowershellSnapin.ConnectionInformation]$Connection
    )
    Write-Host "Connected to Exchange Online"
    Write-Host "Session details"
    Write-Host "Tenant Id: $($Connection.TenantId)"
    Write-Host "User: $($Connection.UserPrincipalName)"
}
