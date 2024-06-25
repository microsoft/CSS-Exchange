# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-EXOConnection {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param (
        [Switch]$Force
    )
    #Validate EXO V2 is installed
    if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
        Write-Host "ExchangeOnlineManagement Powershell Module installed"
    } else {
        if ($Force -or $PSCmdlet.ShouldContinue("Do you want to install the module?", "ExchangeOnlineManagement Powershell Module not installed")) {
            Install-Module -Name ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue -Scope CurrentUser
            if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
                Write-Host "ExchangeOnlineManagement Powershell Module installed"
            } else {
                Write-Host "ExchangeOnlineManagement Powershell Module installation failed" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "We cannot continue without ExchangeOnlineManagement Powershell module" -ForegroundColor Red
            return $false
        }
    }

    #Validate EXO V2 is loaded
    if ((Get-Module | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
        Write-Host "ExchangeOnlineManagement Powershell Module loaded"
    } else {
        Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue -Force
        if ((Get-Module | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
            Write-Host "ExchangeOnlineManagement Powershell Module Imported"
        } else {
            Write-Host "ExchangeOnlineManagement Powershell Module Import failed" -ForegroundColor Red
            return $false
        }
    }

    #Validate EXO V2 is connected or try to connect
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
                Write-Host "Connected to EXO V2"
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
        Write-Host "Connected to EXO V2"
        Write-Host "Session details"
        Write-Host "Tenant Id: $($connection.TenantId)"
        Write-Host "User: $($connection.UserPrincipalName)"
        return $true
    } else {
        Write-Host "You have more than one EXO sessions please use just one session" -ForegroundColor Red
        return $false
    }
}

function Test-AADConnection {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param (
        [Switch]$Force
    )

    #Validate AzureAD is installed
    if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
        Write-Host "AzureAD Powershell Module installed"
    } else {
        if ($Force -or $PSCmdlet.ShouldContinue("Do you want to install the module?", "AzureAD Powershell Module not installed")) {
            Install-Module -Name AzureAD -Repository PSGallery -AllowClobber -Force -ErrorAction SilentlyContinue -Scope CurrentUser
            if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
                Write-Host "AzureAD Powershell Module installed"
            } else {
                Write-Host "AzureAD Powershell Module installation failed" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "We cannot continue without AzureAD Powershell module" -ForegroundColor Red
            return $false
        }
    }

    #Validate AzureAD is loaded
    if ((Get-Module | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
        Write-Host "AzureAD Powershell Module loaded"
    } else {
        Import-Module AzureAD -ErrorAction SilentlyContinue -Force
        if ((Get-Module | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
            Write-Host "AzureAD Powershell Module Imported"
        } else {
            Write-Host "AzureAD Powershell Module Import failed" -ForegroundColor Red
            return $false
        }
    }

    #Validate AzureAD is connected or try to connect
    try {
        $connection = $null
        $connection = Get-AzureADTenantDetail -ErrorAction SilentlyContinue
        if ($null -eq $connection) {
            Write-Host "Not connected to AzureAD" -ForegroundColor Red
            Write-Host "We cannot continue without AzureAD Powershell session" -ForegroundColor Red
            return $false
        } else {
            if ($connection.count -eq 1) {
                Write-Host "Connected to AzureAD"
                Write-Host "Session details"
                Write-Host "Tenant: $($connection.DisplayName)"
                return $true
            } else {
                Write-Host "You have more than one AzureAD sessions please use just one session" -ForegroundColor Red
                return $false
            }
        }
    } catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
        Write-Host "Please use Global administrator credentials" -ForegroundColor Yellow
        if ($Force -or $PSCmdlet.ShouldContinue("Do you want to connect?", "We need a AzureAD connection")) {
            Connect-AzureAD -ErrorAction SilentlyContinue
            try {
                $connection = Get-AzureADTenantDetail -ErrorAction SilentlyContinue
                if ($null -eq $connection) {
                    Write-Host "Connection could not be established" -ForegroundColor Red
                    Write-Host "We cannot continue without AzureAD Powershell session" -ForegroundColor Red
                    return $false
                } else {
                    Write-Host "Connected to AzureAD"
                    Write-Host "Session details"
                    Write-Host "Tenant: $($connection.DisplayName)"
                    return $true
                }
            } catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
                Write-Host "Connection could not be established" -ForegroundColor Red
                Write-Host "We cannot continue without AzureAD Powershell session" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "We cannot continue without AzureAD Powershell session" -ForegroundColor Red
            return $false
        }
    }
}
