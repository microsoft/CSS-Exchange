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
                Install-Module @installParams

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
