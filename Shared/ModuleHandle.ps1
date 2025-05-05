# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
This script defines a function `Request-Module` that checks for the presence of specified PowerShell module.
If a module is not found, it attempts to install it on current user scope.
The function accepts a module names and an optional minimum version for the module.
It returns a boolean indicating whether a specified module was added successfully (installed if it is needed).

.PARAMETER Module
 Mandatory string specifying the names of the module to check and install if necessary.
.PARAMETER MinModuleVersion
 Optional parameter to specify the minimum version of the module (default is null).

.OUTPUTS
bool. A boolean indicating whether the specified module was added successfully (installed if it is needed).

.EXAMPLE
$requestModule = Request-Module -Module "ExchangeOnlineManagement"
This example checks if the "ExchangeOnlineManagement" module is installed. If it is not found, the script attempts to install it.

.EXAMPLE
$requestModule = Request-Module -Module "ExchangeOnlineManagement" -MinModuleVersion $MinModuleVersion
This example checks if the "ExchangeOnlineManagement" module with a specified minimum version is installed. If it is not found, the script attempts to install it.
#>

. $PSScriptRoot\..\Shared\Confirm-Administrator.ps1

function Request-Module {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Module,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null,
        [Parameter(Mandatory = $false)]
        [switch]$InstallAllUsersIfNotAvailable
    )

    $installedModule = $null
    $getParams = @{
        Name        = $Module
        ErrorAction = 'SilentlyContinue'
    }
    if ($MinModuleVersion) {
        $getParams["MinimumVersion"] = $MinModuleVersion
    }

    try {
        $installedModule = Get-InstalledModule @getParams
    } catch {
        Write-Host "Get-InstalledModule fails. Error: `n$_" -ForegroundColor Red
        return $false
    }

    if ($installedModule) {
        Write-Verbose "Module $Module is already installed."
        return $true
    } else {
        Write-Host "Module $Module is not installed."
    }

    if ($InstallAllUsersIfNotAvailable -and (-not (Confirm-Administrator))) {
        Write-Host "Module $Module is not available and cannot be installed for all users because this PowerShell is not running in elevated mode." -ForegroundColor Red
        return $false
    } else {
        Write-Verbose "Installing $Module"
        $installParams = @{
            Name  = $Module
            Scope = "CurrentUser"
        }
        if ($InstallAllUsersIfNotAvailable) {
            $installParams.Scope = "AllUsers"
            Write-Verbose "Scope: AllUsers"
        }
        if ($MinModuleVersion) {
            $installParams["MinimumVersion"] = $MinModuleVersion
            Write-Verbose "with minimum version $MinModuleVersion"
        } else {
            Write-Verbose "without minimum version"
        }
        try {
            Write-Host "Installing module $Module..."
            Install-Module @installParams -AllowClobber
        } catch {
            Write-Host "Installation process fails. Error: `n$_" -ForegroundColor Red
            return $false
        }
        $installedModule = $null
        try {
            $installedModule = Get-InstalledModule @getParams
        } catch {
            Write-Host "Get-InstalledModule fails. Error: `n$_" -ForegroundColor Red
            return $false
        }
        if ($null -eq $installedModule) {
            Write-Host "We could not install module: $Module" -ForegroundColor Red
            return $false
        } else {
            Write-Host "Module $Module correctly installed." -ForegroundColor Green
            return $true
        }
    }
}
