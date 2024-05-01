# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
function Connect-EXO {
    try {
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

        if ( Get-ConnectionInformation ) {
            Write-Host "Already connected to EXO V2" -ForegroundColor Cyan
        } else {
            Write-Host "Connecting to EXO V2, please enter Global administrator credentials when prompted!" -ForegroundColor Yellow
            Connect-ExchangeOnline -ErrorAction Stop | Out-Null
            if ( Get-ConnectionInformation ) {
                Write-Host "Connected to EXO V2 successfully" -ForegroundColor Cyan
            } else {
                Write-Host "Failed to connect to EXO V2" -ForegroundColor Red
                break
            }
        }
    } catch {
        Write-Host "Failure Connecting to EXO V2 please check if ExchangeOnlineManagement Powershell Module is installed & imported" -ForegroundColor Red
        break
    }
}

function Connect-AAD {
    try {
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
            $null = Get-AzureADTenantDetail
            Write-Host "Already connected to AzureAD" -ForegroundColor Cyan
        } catch {
            Write-Host "Connecting to AzureAD, please enter Global administrator credentials when prompted!" -ForegroundColor Yellow
            Connect-AzureAD -ErrorAction Stop | Out-Null
            if ( Get-AzureADCurrentSessionInfo ) {
                Write-Host "Connected to AzureAD successfully" -ForegroundColor Cyan
            } else {
                Write-Host "Failed to connect to AzureAD" -ForegroundColor Red
                break
            }
        }
    } catch {
        Write-Host "Failure Connecting to AzureAD please check if ExchangeOnlineManagement Powershell Module is installed & imported" -ForegroundColor Red
        break
    }
}
