# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Request-Module {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Modules,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null
    )

    $installed = $null
    Write-Verbose "Checking $Modules PowerShell Module"
    if ($MinModuleVersion) {
        Write-Verbose "with minimum version $minModuleVersion"
        $installed = Get-InstalledModule -Name $Modules -MinimumVersion $MinModuleVersion -ErrorAction SilentlyContinue
    } else {
        Write-Verbose "without minimum version"
        $installed = Get-InstalledModule -Name $Modules -ErrorAction SilentlyContinue
    }

    $foundError = $false
    foreach ($module in $Modules) {
        if ($null -eq $installed -or $installed.Name -notcontains $module) {
            Write-Host "The following module is missing: $module" -ForegroundColor Yellow
            $confirmed = $null
            try {
                if ($MinModuleVersion) {
                    Write-Verbose "Installing $module with minimum version $minModuleVersion"
                    Install-Module -Name $module -Scope CurrentUser -MinimumVersion $MinModuleVersion
                    $confirmed = Get-InstalledModule -Name $module -MinimumVersion $MinModuleVersion -ErrorAction Stop
                    if (-not $confirmed) {
                        Write-Host "We could not install module: $module with minimum version $minModuleVersion" -ForegroundColor Red
                        $foundError = $true
                    }
                } else {
                    Write-Verbose "Installing $module"
                    Install-Module -Name $module -Scope CurrentUser
                    $confirmed = Get-InstalledModule -Name $module -ErrorAction Stop
                    if (-not $confirmed) {
                        Write-Host "We could not install module: $module" -ForegroundColor Red
                        $confirmed = $true
                    }
                }
            } catch {
                Write-Host "Installation process fails. Error: `n$_" -ForegroundColor Red
                return $false
            }
        }
    }
    if ($foundError) {
        return $false
    }
    return $true
}
