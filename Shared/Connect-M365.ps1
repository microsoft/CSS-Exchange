# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-EXOConnection {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param ()
    #Validate EXO V2 is installed
    if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
        Write-Host "ExchangeOnlineManagement Powershell Module installed" -ForegroundColor Green
    } else {
        Write-Host "ExchangeOnlineManagement Powershell Module is missing `n Trying to install the module" -ForegroundColor Yellow
        Install-Module -Name ExchangeOnlineManagement -Force -ErrorAction Stop -Scope CurrentUser
        if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
            Write-Host "ExchangeOnlineManagement Powershell Module installed" -ForegroundColor Green
        } else {
            Write-Host "ExchangeOnlineManagement Powershell Module installation failed" -ForegroundColor Red
            break
        }
    }

    if ((Get-Module | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
        Write-Host "ExchangeOnlineManagement Powershell Module loaded" -ForegroundColor Green
    } else {
        Import-Module ExchangeOnlineManagement -ErrorAction stop -Force
        Write-Host "ExchangeOnlineManagement Powershell Module loading" -ForegroundColor Yellow
        if ((Get-Module | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
            Write-Host "ExchangeOnlineManagement Powershell Module Loaded" -ForegroundColor Green
        } else {
            Write-Host "ExchangeOnlineManagement Powershell Module load failed" -ForegroundColor Red
            break
        }
    }

    $connection = $null
    $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue

    if ($null -eq $connection) {
        Write-Host "Not connected to EXO V2" -ForegroundColor Red
        Write-Host "You need a connection To Exchange Online, you can use:" -ForegroundColor Yellow
        Write-Host "Connect-ExchangeOnline" -ForegroundColor Yellow
        Write-Host "Please use Global administrator credentials when prompted!" -ForegroundColor Yellow
        if ($PSCmdlet.ShouldProcess("Connection to Exchange Online", "Do you want to connect?")) {
            Connect-ExchangeOnline -ErrorAction Stop | Out-Null
            if ( Get-ConnectionInformation ) {
                Write-Host "Connected to EXO V2 successfully" -ForegroundColor Cyan
            } else {
                Write-Host "Failed to connect to EXO V2" -ForegroundColor Red
                break
            }
        } else {
            break
        }
    } elseif ($connection.count -eq 1) {
        Write-Host "Connected to EXO V2" -ForegroundColor Cyan
        Write-Host "Session details" -ForegroundColor Cyan
        Write-Host "Tenant Id: $($connection.TenantId)" -ForegroundColor Cyan
        Write-Host "User: $($connection.UserPrincipalName)" -ForegroundColor Cyan
    } else {
        Write-Host "You have more than one EXO sessions please use just one session" -ForegroundColor Red
        break
    }
}

function Test-AADConnection {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param ()

    #Validate AzureAD is installed
    if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
        Write-Host "AzureAD Powershell Module installed" -ForegroundColor Green
    } else {
        Write-Host "AzureAD Powershell Module is missing `n Trying to install the module" -ForegroundColor Red
        Install-Module -Name AzureAD -Repository PSGallery -AllowClobber -Force -ErrorAction Stop -Scope CurrentUser
        if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
            Write-Host "AzureAD Powershell Module installed" -ForegroundColor Green
        } else {
            Write-Host "AzureAD Powershell Module installation failed" -ForegroundColor Red
            break
        }
    }

    if ((Get-Module | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
        Write-Host "AzureAD Powershell Module loaded" -ForegroundColor Green
    } else {
        Import-Module AzureAD -ErrorAction stop -Force
        Write-Host "AzureAD Powershell Module loading" -ForegroundColor Yellow
        if ((Get-Module | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
            Write-Host "AzureAD Powershell Module Loaded" -ForegroundColor Green
        } else {
            Write-Host "AzureAD Powershell Module load failed" -ForegroundColor Red
            break
        }
    }

    try {
        $connection = $null
        $connection = Get-AzureADTenantDetail -ErrorAction SilentlyContinue
        if ($connection.count -eq 1) {
            Write-Host "Connected to AzureAD" -ForegroundColor Cyan
            Write-Host "Session details" -ForegroundColor Cyan
            Write-Host "Tenant: $($connection.DisplayName)" -ForegroundColor Cyan
        } else {
            Write-Host "You have more than one AzureAD sessions please use just one session" -ForegroundColor Red
            break
        }
    } catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
        Write-Host "Not connected to AzureAD" -ForegroundColor Red
        Write-Host "You need a connection to AzureAD, you can use:" -ForegroundColor Yellow
        Write-Host "Connect-AzureAD " -ForegroundColor Yellow
        Write-Host "Please use Global administrator credentials when prompted!" -ForegroundColor Yellow
        if ($PSCmdlet.ShouldProcess("Connection to Azure AD", "Do you want to connect?")) {
            Connect-AzureAD -ErrorAction Stop | Out-Null
            if ( Get-AzureADCurrentSessionInfo ) {
                Write-Host "Connected to AzureAD successfully" -ForegroundColor Cyan
            } else {
                Write-Host "Failed to connect to AzureAD" -ForegroundColor Red
                break
            }
        } else {
            break
        }
    }
}
