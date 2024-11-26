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

function Request-Module {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Modules,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null
    )

    $noFoundError = $true
    foreach ($module in $Modules) {
        Write-Verbose "Checking $Modules PowerShell Module"
        $getParams = @{
            Name        = $module
            ErrorAction = 'SilentlyContinue'
        }
        Write-Verbose "Checking $module"
        if ($MinModuleVersion) {
            $getParams["MinimumVersion"] = $MinModuleVersion
            Write-Verbose "with minimum version $minModuleVersion"
        } else {
            Write-Verbose "without minimum version"
        }
        $installed = Get-InstalledModule @getParams

        if ($null -eq $installed -or $installed.Name -notcontains $module) {
            Write-Host "The following module is missing: $module" -ForegroundColor Yellow
            $confirmed = $null
            try {
                Write-Verbose "Installing $module"
                $installParams = @{
                    Name        = $module
                    Scope       = "CurrentUser"
                    ErrorAction = 'Stop'
                }
                if ($MinModuleVersion) {
                    $installParams["MinimumVersion"] = $MinModuleVersion
                    Write-Verbose "with minimum version $minModuleVersion"
                } else {
                    Write-Verbose "without minimum version"
                }
                Install-Module @installParams -Force

                Write-Verbose "Checking $module"
                $confirmed = Get-InstalledModule @getParams
                if (-not $confirmed) {
                    Write-Host "We could not install module: $module" -ForegroundColor Red
                    $noFoundError = $false
                }
            } catch {
                Write-Host "Installation process fails. Error: `n$_" -ForegroundColor Red
                $noFoundError = $false
            }
        }
    }
    return $noFoundError
}
