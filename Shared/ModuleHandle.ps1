# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
This script defines a function `Request-Module` that checks for the presence of specified PowerShell module.
If a module is not found, it attempts to install it on current user scope.
Modules are first detected with PowerShellGet, with Get-Module -ListAvailable as a fallback.
If another version is installed but none matches the requested version range, confirmation is required before installing with Force and AllowClobber.
The function accepts a module names and an optional minimum version for the module.
It returns a boolean indicating whether a specified module was added successfully (installed if it is needed).

.PARAMETER Module
 Mandatory string specifying the names of the module to check and install if necessary.
.PARAMETER MinModuleVersion
 Optional parameter to specify the minimum version of the module (default is null).
.PARAMETER MaximumVersion
 Optional parameter to specify the maximum version of the module (default is null).
.PARAMETER AllowClobber
 Optional switch to allow installation when the module exports commands with names that already exist. Requires confirmation.
 Also enabled when installation of a different module version is confirmed.

.OUTPUTS
bool. A boolean indicating whether the specified module was added successfully (installed if it is needed).

.EXAMPLE
$requestModule = Request-Module -Module "ExchangeOnlineManagement"
This example checks if the "ExchangeOnlineManagement" module is installed. If it is not found, the script attempts to install it.

.EXAMPLE
$requestModule = Request-Module -Module "ExchangeOnlineManagement" -MinModuleVersion $MinModuleVersion
This example checks if the "ExchangeOnlineManagement" module with a specified minimum version is installed. If it is not found, the script attempts to install it.

.EXAMPLE
$requestModule = Request-Module -Module "ExchangeOnlineManagement" -MinModuleVersion 3.0.0 -MaximumVersion 3.8.0
This example checks if an "ExchangeOnlineManagement" module version between 3.0.0 and 3.8.0 is installed. If it is not found, the script attempts to install a version in that range.
#>

. $PSScriptRoot\..\Shared\Confirm-Administrator.ps1

function Test-ModuleAvailable {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Module,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null,
        [Parameter(Mandatory = $false)]
        [System.Version]$MaximumVersion = $null
    )

    $getParams = @{
        Name        = $Module
        ErrorAction = 'SilentlyContinue'
    }
    if ($MinModuleVersion) {
        $getParams["MinimumVersion"] = $MinModuleVersion
    }
    if ($MaximumVersion) {
        $getParams["MaximumVersion"] = $MaximumVersion
    }

    try {
        $installedModule = Get-InstalledModule @getParams
    } catch {
        Write-Verbose "Get-InstalledModule fails. Error: `n$_"
        return $false
    }

    if (-not $installedModule) {
        try {
            $installedModule = Get-Module -ListAvailable -Name $Module -ErrorAction Stop |
                Where-Object {
                    (-not $MinModuleVersion -or $_.Version -ge $MinModuleVersion) -and
                    (-not $MaximumVersion -or $_.Version -le $MaximumVersion)
                }
        } catch {
            Write-Host "Get-Module fails. Error: `n$_" -ForegroundColor Red
            return $false
        }
    }

    return [bool]$installedModule
}

function Request-Module {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Module,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null,
        [Parameter(Mandatory = $false)]
        [System.Version]$MaximumVersion = $null,
        [Parameter(Mandatory = $false)]
        [switch]$InstallAllUsersIfNotAvailable,
        [Parameter(Mandatory = $false)]
        [switch]$AllowClobber
    )

    if ($MinModuleVersion -and $MaximumVersion -and $MaximumVersion -lt $MinModuleVersion) {
        Write-Host "MaximumVersion $MaximumVersion cannot be lower than MinModuleVersion $MinModuleVersion." -ForegroundColor Red
        return $false
    }

    $moduleAvailable = $false
    $moduleAvailable = Test-ModuleAvailable -Module $Module -MinModuleVersion $MinModuleVersion -MaximumVersion $MaximumVersion

    if ($moduleAvailable) {
        Write-Verbose "Module $Module is already installed."
        return $true
    } else {
        Write-Host "No installed version of module $Module matches the requested version requirements."
    }

    if ($InstallAllUsersIfNotAvailable -and (-not (Confirm-Administrator))) {
        Write-Host "Module $Module is not available and cannot be installed for all users because this PowerShell is not running in elevated mode." -ForegroundColor Red
        return $false
    } else {
        Write-Verbose "Installing $Module"
        $installParams = @{
            Name        = $Module
            Scope       = "CurrentUser"
            ErrorAction = "Stop"
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
        if ($MaximumVersion) {
            $installParams["MaximumVersion"] = $MaximumVersion
            Write-Verbose "with maximum version $MaximumVersion"
        } else {
            Write-Verbose "without maximum version"
        }
        if (Test-ModuleAvailable -Module $Module) {
            Write-Warning "Another version of $Module is already installed. Installation will use Force and AllowClobber, which may override existing commands. Modules currently in use may require a new PowerShell session."
            if (-not $PSCmdlet.ShouldProcess($Module, "Install a different module version with Force and AllowClobber")) {
                Write-Host "Installation of module $Module was not performed." -ForegroundColor Yellow
                return $false
            }
            $installParams["Force"] = $true
            $installParams["AllowClobber"] = $true
        }
        if ($AllowClobber -and -not $installParams.ContainsKey("AllowClobber")) {
            Write-Warning "AllowClobber is enabled. Installing $Module may introduce command name conflicts with other installed modules."
            if (-not $PSCmdlet.ShouldProcess($Module, "Install module with AllowClobber")) {
                return $false
            }
            $installParams["AllowClobber"] = $true
        }
        try {
            Write-Host "Installing module $Module..."
            Install-Module @installParams
        } catch {
            Write-Host "Installation process fails. Error: `n$_" -ForegroundColor Red
            return $false
        }
        $moduleAvailable = $false
        try {
            $moduleAvailable = Test-ModuleAvailable -Module $Module -MinModuleVersion $MinModuleVersion -MaximumVersion $MaximumVersion
        } catch {
            Write-Host "Verification of the installation process fails. Error: `n$_" -ForegroundColor Red
            return $false
        }
        if (-not $moduleAvailable) {
            Write-Host "We could not install module: $Module" -ForegroundColor Red
            return $false
        } else {
            Write-Host "Module $Module correctly installed." -ForegroundColor Green
            return $true
        }
    }
}
