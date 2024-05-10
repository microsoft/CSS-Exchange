# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.



function Test-M365ModuleLoaded {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null,
        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    $module = $null
    $module = (Get-Module | Where-Object { $_.Name -like "$ModuleName" } | Sort-Object Version -Descending | Select-Object -First 1)
    $needsUpdate = $false
    if ($module) {
        Write-Verbose "$ModuleName Powershell Module loaded"
        if ($MinModuleVersion) {
            $needsUpdate = CheckModuleVersion -MinModuleVersion $MinModuleVersion -ModuleVersion $module.Version
            if ($needsUpdate) {
                Write-Verbose "$ModuleName Powershell Module version loaded $MinModuleVersion is lower than expeced: $MinModuleVersion"
                #Update Module
            } else {
                Write-Verbose "$ModuleName Powershell Module version loaded $MinModuleVersion is expected or higher than required: $MinModuleVersion"
                return $true
            }
        } else {
            Write-Verbose "$ModuleName Powershell Module version loaded $MinModuleVersion. No minimum version specified"
            return $true
        }
    }

    $module = $null
    $module = Get-Module -ListAvailable | Where-Object { $_.Name -like $ModuleName } | Sort-Object Version -Descending | Select-Object -First 1
    if ($module) {
        Write-Verbose "$ModuleName Powershell Module installed"
        if ($MinModuleVersion) {
            $needsUpdate = CheckModuleVersion -MinModuleVersion $MinModuleVersion -ModuleVersion $module.Version
            if ($needsUpdate) {
                Write-Verbose "$ModuleName Powershell Module version installed $MinModuleVersion is lower than expeced: $MinModuleVersion"
            } else {
                Write-Verbose "$ModuleName Powershell Module version installed $MinModuleVersion is expected or higher than required: $MinModuleVersion"
                Import-Module $module -ErrorAction SilentlyContinue -Force
            }
        } else {
            Write-Verbose "$ModuleName Powershell Module version installed $MinModuleVersion. No minimum version specified"

        }


    } else {
    }
    #Validate EXO V2 is loaded
    Import-Module $ModuleName -ErrorAction SilentlyContinue -Force
    if ((Get-Module | Where-Object { $_.Name -like "$ModuleName" }).count -ge 1) {
        Write-Verbose "$ModuleName Powershell Module loaded"
        return $true
    } else {
        Write-Host "$ModuleName Powershell Module Import failed" -ForegroundColor Red
        return $false
    }
}

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
    return Test-M365ModuleLoaded -ModuleName $ModuleName
}

function Test-M365ModuleLoaded {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = $null
    )

    $module = $null
    $module = Get-Module | Where-Object { $_.Name -like $ModuleName } | Sort-Object Version -Descending | Select-Object -First 1
    if ($module) {
        Write-Verbose "$ModuleName Powershell Module Loaded"
        if ($MinModuleVersion) {
            if (Test-ModuleVersion -MinModuleVersion $MinModuleVersion -ModuleVersion $module.Version) {
                Write-Verbose "$ModuleName Powershell Module version loaded $MinModuleVersion. No minimum version specified"
                return $false
            } else {
                Write-Verbose "$ModuleName Powershell Module version loaded $MinModuleVersion. No minimum version specified"
                return $true
            }
        } else {
            Write-Verbose "$ModuleName Powershell Module version loaded $MinModuleVersion. No minimum version specified"
            return $true
        }
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

    $module = $null
    $module = Get-Module -ListAvailable | Where-Object { $_.Name -like $ModuleName } | Sort-Object Version -Descending | Select-Object -First 1
    if ($module) {
        Write-Verbose "$ModuleName Powershell Module installed"
        if ($MinModuleVersion) {
            if (Test-ModuleVersion -MinModuleVersion $MinModuleVersion -ModuleVersion $module.Version) {
                Write-Verbose "$ModuleName Powershell Module installed"
                return $true
            } else {
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
