# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Import-M365Module {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null
    )

    if ($MinModuleVersion) {
        Write-Verbose "Importing $ModuleName Powershell Module with minimum version $MinModuleVersion"
        if (Test-M365ModuleInstalled -ModuleName $ModuleName -MinModuleVersion $MinModuleVersion) {
            Import-Module $ModuleName -MinimumVersion $MinModuleVersion -ErrorAction SilentlyContinue -Force
        }
    } else {
        Write-Verbose "Importing $ModuleName Powershell Module"
        if (Test-M365ModuleInstalled -ModuleName $ModuleName) {
            Import-Module $ModuleName
        }
    }

    if ($MinModuleVersion) {
        return Test-M365ModuleLoaded -ModuleName $ModuleName -MinModuleVersion $MinModuleVersion
    } else {
        return Test-M365ModuleLoaded -ModuleName $ModuleName
    }
}

function Test-M365ModuleLoaded {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null
    )

    $modules = $null
    $modules = Get-Module | Where-Object { $_.Name -like $ModuleName } | Sort-Object Version -Descending

    if ($modules) {
        Write-Verbose "$ModuleName Powershell Module Loaded"
        $foundMinVersion = $false
        if ($MinModuleVersion) {
            foreach ($module in $modules) {
                if (Test-ModuleVersion -MinModuleVersion $MinModuleVersion -ModuleVersion $module.Version) {
                    Write-Verbose "$ModuleName Powershell Module version loaded with minimum version $MinModuleVersion': $($module.Version)"
                    $foundMinVersion = $true
                }
            }
            if ($foundMinVersion) {
                return $true
            } else {
                Write-Host "$ModuleName Powershell Module version loaded but do not reach minimum version: $MinModuleVersion" -ForegroundColor Red
                return $false
            }
        }
    } else {
        Write-Verbose "$ModuleName Powershell Module version loaded $MinModuleVersion. No minimum version specified"
        return $true
    }
}

function Test-M365ModuleInstalled {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null
    )

    $modules = $null
    $modules = Get-Module -ListAvailable | Where-Object { $_.Name -like $ModuleName } | Sort-Object Version -Descending
    if ($modules) {
        Write-Verbose "$ModuleName Powershell Module installed"
        $foundMinVersion = $false
        if ($MinModuleVersion) {
            foreach ($module in $module) {
                if (Test-ModuleVersion -MinModuleVersion $MinModuleVersion -ModuleVersion $module.Version) {
                    Write-Verbose "$ModuleName Powershell Module installed with minimum version $MinModuleVersion': $($module.Version)"
                    $foundMinVersion = $true
                }
            }
            if ($foundMinVersion) {
                return $true
            } else {
                Write-Host "$ModuleName Powershell Module installed but do not reach minimum version: $MinModuleVersion" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Verbose "$ModuleName Powershell Module version installed $MinModuleVersion. No minimum version specified"
            return $true
        }
    }
}

function Install-M365Module {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null,
        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    if ($MinModuleVersion) {
        $message = "Do you want to install min version $MinModuleVersion?"
    } else {
        $message = "Do you want to install?"
    }

    if ($Force -or $PSCmdlet.ShouldContinue($message, "Module $ModuleName")) {
        if ($MinModuleVersion) {
            Install-Module -Name $ModuleName -Force -ErrorAction SilentlyContinue -Scope CurrentUser -MinimumVersion $MinModuleVersion
            if (Test-M365ModuleInstalled -ModuleName $ModuleName -MinModuleVersion $MinModuleVersion) {
                Write-Verbose "$ModuleName Powershell Module installed"
                return $true
            } else {
                Write-Host "$ModuleName Powershell Module installation failed" -ForegroundColor Red
                return $false
            }
        } else {
            Install-Module -Name $ModuleName -Force -ErrorAction SilentlyContinue -Scope CurrentUser
            if (Test-M365ModuleInstalled -ModuleName $ModuleName) {
                Write-Verbose "$ModuleName Powershell Module installed"
                return $true
            } else {
                Write-Host "$ModuleName Powershell Module installation failed" -ForegroundColor Red
                return $false
            }
        }
    }
}

function Test-ModuleVersion {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Version]$MinModuleVersion,
        [Parameter(Mandatory = $true)]
        [System.Version]$ModuleVersion
    )
    return $ModuleVersion -lt $MinModuleVersion
}
