# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\M365Modules.ps1

function Test-EXOConnection {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [System.Version]$ModuleVersion = $null
    )

    #Validate EXO is installed and loaded
    $loadedInstalled = $false
    if ($MinModuleVersion) {
        $loadedInstalled = Test-M365ModuleLoaded -ModuleName "ExchangeOnlineManagement" -MinModuleVersion $ModuleVersion
    } else {
        $loadedInstalled = Test-M365ModuleLoaded -ModuleName "ExchangeOnlineManagement"
    }
    if (-not $loadedInstalled) {
        if ($MinModuleVersion) {
            $loadedInstalled = Test-M365ModuleInstalled -ModuleName "ExchangeOnlineManagement" -MinModuleVersion $ModuleVersion
        } else {
            $loadedInstalled = Test-M365ModuleInstalled -ModuleName "ExchangeOnlineManagement"
        }
        if (-not $loadedInstalled) {
            if ($MinModuleVersion) {
                $loadedInstalled = Install-M365Module -ModuleName "ExchangeOnlineManagement" -MinModuleVersion $ModuleVersion
            } else {
                $loadedInstalled = Install-M365Module -ModuleName "ExchangeOnlineManagement"
            }
        }
        if ($loadedInstalled) {
            if ($MinModuleVersion) {
                $loadedInstalled = Import-M365Module ExchangeOnlineManagement -ErrorAction SilentlyContinue -MinModuleVersion $ModuleVersion
            } else {
                $loadedInstalled = Import-M365Module ExchangeOnlineManagement -ErrorAction SilentlyContinue
            }
            if (-not $loadedInstalled) {
                Write-Host "We cannot continue without ExchangeOnlineManagement Powershell module Loaded" -ForegroundColor Red
                break
            }
        } else {
            Write-Host "We cannot continue without ExchangeOnlineManagement Powershell module Installed" -ForegroundColor Red
            break
        }
    }

    #Validate EXO is connected or try to connect
    $connection = $null
    $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($null -eq $connection) {
        if ($PSCmdlet.ShouldContinue("Do you want to connect?", "No connection found. We need a ExchangeOnlineManagement connection with Global administrator")) {
            Connect-ExchangeOnline -ErrorAction SilentlyContinue
            $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue
            if ($null -eq $connection) {
                Write-Host "Connection could not be established" -ForegroundColor Red
            } else {
                Show-EXOConnection -Connection $connection
                return $true
            }
        }
        Write-Host "We cannot continue without ExchangeOnlineManagement Powershell session" -ForegroundColor Red
        return $false
    } elseif ($connection.count -eq 1) {
        Show-EXOConnection -Connection $connection
        return $true
    } else {
        Write-Host "You have more than one Exchange Online sessions please use just one session" -ForegroundColor Red
        return $false
    }
}

function Show-EXOConnection {
    param (
        [Parameter(Mandatory = $true)]
        #Microsoft.Exchange.Management.ExoPowershellSnapin.ConnectionInformation
        [ConnectionInformation]$Connection
    )
    Write-Host "Connected to Exchange Online"
    Write-Host "Session details"
    Write-Host "Tenant Id: $($Connection.TenantId)"
    Write-Host "User: $($Connection.UserPrincipalName)"
}
