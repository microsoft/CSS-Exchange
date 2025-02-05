# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
This script defines a function `Request-Module` that checks for the presence of specified PowerShell modules.
If a module is not found, it attempts to install it on current user scope.
The function accepts a list of module names and an optional minimum version for the modules.
It returns a boolean indicating whether all specified modules are installed successfully.

.PARAMETER Modules
 Mandatory array of strings specifying the names of the modules to check and install if necessary.
.PARAMETER MinModuleVersion
 Optional parameter to specify the minimum version of the modules (default is null).

.OUTPUTS
bool. A boolean indicating whether all specified modules are installed successfully.

.EXAMPLE
$requestModule = Request-Module -Modules "ExchangeOnlineManagement"
This example checks if the "ExchangeOnlineManagement" module is installed. If it is not found, the script attempts to install it.

.EXAMPLE
$requestModule = Request-Module -Modules "ExchangeOnlineManagement" -MinModuleVersion $MinModuleVersion
This example checks if the "ExchangeOnlineManagement" module with a specified minimum version is installed. If it is not found, the script attempts to install it.
#>

. $PSScriptRoot\..\Shared\Confirm-Administrator.ps1

function Request-Module {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Module,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null,
        [Parameter(Mandatory = $false)]
        [switch]$InstallAllUsersIfNotAvailable
    )

    $noFoundError = $true

    foreach ($m in $Module) {
        Write-Verbose "Checking $m PowerShell Module"
        $getParams = @{
            Name        = $m
            ErrorAction = 'SilentlyContinue'
        }
        if ($MinModuleVersion) {
            $getParams["MinimumVersion"] = $MinModuleVersion
            Write-Verbose "with minimum version $minModuleVersion"
        } else {
            Write-Verbose "without minimum version"
        }
        $installed = Get-InstalledModule @getParams

        if ($null -eq $installed -or $installed.Name -notcontains $m) {
            Write-Host "The following module is missing: $m" -ForegroundColor Yellow
            if ($InstallAllUsersIfNotAvailable -and (-not (Confirm-Administrator))) {
                Write-Warning "Module $m is not available and cannot be installed for all users because this PowerShell is not running in elevated mode."
                $noFoundError = $false
            } else {
                $confirmed = $null
                try {
                    Write-Verbose "Installing $m"
                    $installParams = @{
                        Name        = $m
                        Scope       = "CurrentUser"
                        ErrorAction = 'Stop'
                    }
                    if ($InstallAllUsersIfNotAvailable) {
                        $installParams.Scope = "AllUsers"
                    }
                    if ($MinModuleVersion) {
                        $installParams["MinimumVersion"] = $MinModuleVersion
                        Write-Verbose "with minimum version $minModuleVersion"
                    } else {
                        Write-Verbose "without minimum version"
                    }
                    Install-Module @installParams -Force

                    Write-Verbose "Checking $m"
                    $confirmed = Get-InstalledModule @getParams
                    if (-not $confirmed) {
                        Write-Host "We could not install module: $m" -ForegroundColor Red
                        $noFoundError = $false
                    }
                } catch {
                    Write-Host "Installation process fails. Error: `n$_" -ForegroundColor Red
                    $noFoundError = $false
                }
            }
        } else {
            Write-Verbose "Found $m module installed"
        }
    }
    return $noFoundError
}
