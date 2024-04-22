# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Connect2EXO {
    try {
        #Validate EXO V2 is installed
        if ((Get-Module | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -eq 1) {
            Import-Module ExchangeOnlineManagement -ErrorAction stop -Force
            $CurrentDescription = "Importing EXO V2 Module"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Importing EXO V2 Module" -CurrentDescription $CurrentDescription
            Write-Warning "Connecting to EXO V2, please enter Global administrator credentials when prompted!"
            Connect-ExchangeOnline -ErrorAction Stop
            $CurrentDescription = "Connecting to EXO V2"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
            Write-Host "Connected to EXO V2 successfully" -ForegroundColor Cyan
        } else {
            #log failure and try to install EXO V2 module then Connect to EXO
            Write-Host "ExchangeOnlineManagement Powershell Module is missing `n Trying to install the module" -ForegroundColor Red
            Install-Module -Name ExchangeOnlineManagement -Force -ErrorAction Stop -Scope CurrentUser
            Import-Module ExchangeOnlineManagement -ErrorAction stop -Force
            $CurrentDescription = "Installing & Importing EXO V2 powershell module"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Installing & Importing EXO V2 powershell module" -CurrentDescription $CurrentDescription
            Write-Warning "Connecting to EXO V2, please enter Global administrator credentials when prompted!"
            Connect-ExchangeOnline -ErrorAction Stop
            $CurrentDescription = "Connecting to EXO V2"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
            Write-Host "Connected to EXO V2 successfully" -ForegroundColor Cyan
        }
    } catch {
        $CurrentDescription = "Connecting to EXO V2 please check if ExchangeOnlineManagement Powershell Module is installed & imported"
        $CurrentStatus = "Failure"
        log -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
        break
    }
}

function Connect2AzureAD {
    try {
        #Validate AzureAD is installed
        if ((Get-Module | Where-Object { $_.Name -like "AzureAD" }).count -eq 1) {
            Import-Module ExchangeOnlineManagement -ErrorAction stop -Force
            $CurrentDescription = "Importing AzureAD Module"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Importing AzureAD Module" -CurrentDescription $CurrentDescription
            Write-Warning "Connecting to AzureAD, please enter Global administrator credentials when prompted!"
            Connect-ExchangeOnline -ErrorAction Stop
            $CurrentDescription = "Connecting to AzureAD"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Connecting to AzureAD" -CurrentDescription $CurrentDescription
            Write-Host "Connected to AzureAD successfully" -ForegroundColor Cyan
        } else {
            #log failure and try to install AzureAD module then Connect to AzureAD
            Write-Host "AzureAD Powershell Module is missing `n Trying to install the module" -ForegroundColor Red
            Install-Module -Name AzureAD -Repository PSGallery -AllowClobber -Force -ErrorAction Stop -Scope CurrentUser
            Import-Module AzureAD -ErrorAction stop -Force
            $CurrentDescription = "Installing & Importing AzureAD powershell module"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Installing & Importing AzureAD powershell module" -CurrentDescription $CurrentDescription
            Write-Warning "Connecting to AzureAD, please enter Global administrator credentials when prompted!"
            Connect-ExchangeOnline -ErrorAction Stop
            $CurrentDescription = "Connecting to AzureAD"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Connecting to AzureAD" -CurrentDescription $CurrentDescription
            Write-Host "Connected to AzureAD successfully" -ForegroundColor Cyan
        }
    } catch {
        $CurrentDescription = "Connecting to AzureAD please check if ExchangeOnlineManagement Powershell Module is installed & imported"
        $CurrentStatus = "Failure"
        log -CurrentStatus $CurrentStatus -Function "Connecting to AzureAD" -CurrentDescription $CurrentDescription
        break
    }
}
