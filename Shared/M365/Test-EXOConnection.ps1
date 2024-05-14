# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\M365Modules.ps1

function Test-EXOConnection {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    #Validate EXO is installed and loaded
    $loadedInstalled = $false
    $loadedInstalled = Test-M365ModuleLoaded -ModuleName "ExchangeOnlineManagement" -MinModuleVersion 3.2.0
    if (-not $loadedInstalled) {
        $loadedInstalled = Test-M365ModuleInstalled -ModuleName "ExchangeOnlineManagement" -MinModuleVersion 3.2.0
        if (-not $loadedInstalled) {
            $loadedInstalled = Install-M365Module -ModuleName "ExchangeOnlineManagement" -MinModuleVersion 3.2.0
        }
        if ($loadedInstalled) {
            $loadedInstalled = Import-M365Module ExchangeOnlineManagement -ErrorAction SilentlyContinue -Force -MinModuleVersion 3.2.0
            if (-not $loadedInstalled) {
                Write-Host "We cannot continue without ExchangeOnlineManagement Powershell module" -ForegroundColor Red
                break
            }
        } else {
            Write-Host "We cannot continue without ExchangeOnlineManagement Powershell module" -ForegroundColor Red
            break
        }
    }


    #Validate EXO is connected or try to connect
    $connection = $null
    $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($null -eq $connection) {
        Write-Host "Please use Global administrator credentials" -ForegroundColor Yellow

        if ($Force -or $PSCmdlet.ShouldContinue("Do you want to connect?", "We need a ExchangeOnlineManagement connection")) {
            Connect-ExchangeOnline -ErrorAction SilentlyContinue
            $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue
            if ($null -eq $connection) {
                Write-Host "Connection could not be established" -ForegroundColor Red
                Write-Host "We cannot continue without ExchangeOnlineManagement Powershell session" -ForegroundColor Red
                return $false
            } else {
                Write-Host "Connected to Exchange Online"
                Write-Host "Session details"
                Write-Host "Tenant Id: $($connection.TenantId)"
                Write-Host "User: $($connection.UserPrincipalName)"
                return $true
            }
        } else {
            Write-Host "We cannot continue without ExchangeOnlineManagement Powershell session" -ForegroundColor Red
            return $false
        }
    } elseif ($connection.count -eq 1) {
        Write-Host "Connected to Exchange Online"
        Write-Host "Session details"
        Write-Host "Tenant Id: $($connection.TenantId)"
        Write-Host "User: $($connection.UserPrincipalName)"
        return $true
    } else {
        Write-Host "You have more than one Exchange Online sessions please use just one session" -ForegroundColor Red
        return $false
    }
}
