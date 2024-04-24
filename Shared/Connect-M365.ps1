# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
function log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentStatus,

        [Parameter(Mandatory = $true)]
        [string]$Function,

        [Parameter(Mandatory = $true)]
        [string]$CurrentDescription

    )

    $PSobject = New-Object PSObject
    $PSobject | Add-Member -NotePropertyName "Function" -NotePropertyValue $Function
    $PSobject | Add-Member -NotePropertyName "Description" -NotePropertyValue $CurrentDescription
    $PSobject | Add-Member -NotePropertyName "Status" -NotePropertyValue $CurrentStatus
    $PSobject | Export-Csv $ExportPath\DlToO365GroupUpgradeChecksLogging.csv -NoTypeInformation -Append
}

function Connect2EXO {
    try {
        #Validate EXO V2 is installed
        if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
            Write-Host "ExchangeOnlineManagement Powershell Module installed" -ForegroundColor Green
        } else {
            #log failure and try to install EXO V2 module then Connect to EXO
            Write-Host "ExchangeOnlineManagement Powershell Module is missing `n Trying to install the module" -ForegroundColor Red
            Install-Module -Name ExchangeOnlineManagement -Force -ErrorAction Stop -Scope CurrentUser
            if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
                Write-Host "ExchangeOnlineManagement Powershell Module installed" -ForegroundColor Green
            } else {
                Write-Host "ExchangeOnlineManagement Powershell Module installation failed" -ForegroundColor Red
                $CurrentDescription = "Installing EXO V2 Powershell Module"
                $CurrentStatus = "Failure"
                log -CurrentStatus $CurrentStatus -Function "Installing EXO V2 Powershell Module" -CurrentDescription $CurrentDescription
                break
            }
        }

        if ((Get-Module | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
            Write-Host "ExchangeOnlineManagement Powershell Module loaded" -ForegroundColor Green
        } else {
            Import-Module ExchangeOnlineManagement -ErrorAction stop -Force
            $CurrentDescription = "Loading EXO V2 Module"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Loading EXO V2 Module" -CurrentDescription $CurrentDescription
            if ((Get-Module | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -ge 1) {
                Write-Host "ExchangeOnlineManagement Powershell Module Loaded" -ForegroundColor Green
            } else {
                Write-Host "ExchangeOnlineManagement Powershell Module load failed" -ForegroundColor Red
                $CurrentDescription = "Loading EXO V2 Powershell Module"
                $CurrentStatus = "Failure"
                log -CurrentStatus $CurrentStatus -Function "Loading EXO V2 Powershell Module" -CurrentDescription $CurrentDescription
                break
            }
        }

        if ( Get-ConnectionInformation ) {
            Write-Host "Already connected to EXO V2" -ForegroundColor Cyan
        } else {
            Write-Warning "Connecting to EXO V2, please enter Global administrator credentials when prompted!"
            Connect-ExchangeOnline -ErrorAction Stop
            $CurrentDescription = "Connecting to EXO V2"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
            if ( Get-ConnectionInformation ) {
                Write-Host "Connected to EXO V2 successfully" -ForegroundColor Cyan
            } else {
                Write-Host "Failed to connect to EXO V2" -ForegroundColor Red
                $CurrentDescription = "Connecting to EXO V2"
                $CurrentStatus = "Failure"
                log -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
                break
            }
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
        if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
            Write-Host "AzureAD Powershell Module installed" -ForegroundColor Green
        } else {
            #log failure and try to install AzureAD
            Write-Host "AzureAD Powershell Module is missing `n Trying to install the module" -ForegroundColor Red
            Install-Module -Name AzureAD -Repository PSGallery -AllowClobber -Force -ErrorAction Stop -Scope CurrentUser
            if ((Get-Module -ListAvailable | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
                Write-Host "AzureAD Powershell Module installed" -ForegroundColor Green
            } else {
                Write-Host "AzureAD Powershell Module installation failed" -ForegroundColor Red
                $CurrentDescription = "Installing AzureAD Powershell Module"
                $CurrentStatus = "Failure"
                log -CurrentStatus $CurrentStatus -Function "Installing AzureAD Powershell Module" -CurrentDescription $CurrentDescription
                break
            }
        }

        if ((Get-Module | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
            Write-Host "AzureAD Powershell Module loaded" -ForegroundColor Green
        } else {
            Import-Module AzureAD -ErrorAction stop -Force
            $CurrentDescription = "Loading AzureAD Module"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Loading AzureAD Module" -CurrentDescription $CurrentDescription
            if ((Get-Module | Where-Object { $_.Name -like "AzureAD" }).count -ge 1) {
                Write-Host "AzureAD Powershell Module Loaded" -ForegroundColor Green
            } else {
                Write-Host "AzureAD Powershell Module load failed" -ForegroundColor Red
                $CurrentDescription = "Loading AzureAD Powershell Module"
                $CurrentStatus = "Failure"
                log -CurrentStatus $CurrentStatus -Function "Loading AzureAD Powershell Module" -CurrentDescription $CurrentDescription
                break
            }
        }

        if ( Get-AzureADCurrentSessionInfo ) {
            Write-Host "Already connected to AzureAD" -ForegroundColor Cyan
        } else {
            Write-Warning "Connecting to AzureAD, please enter Global administrator credentials when prompted!"
            Connect-AzureAD -ErrorAction Stop
            $CurrentDescription = "Connecting to AzureAD"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Connecting to AzureAD" -CurrentDescription $CurrentDescription
            if ( Get-AzureADCurrentSessionInfo ) {
                Write-Host "Connected to AzureAD successfully" -ForegroundColor Cyan
            } else {
                Write-Host "Failed to connect to AzureAD" -ForegroundColor Red
                $CurrentDescription = "Connecting to AzureAD"
                $CurrentStatus = "Failure"
                log -CurrentStatus $CurrentStatus -Function "Connecting to AzureAD" -CurrentDescription $CurrentDescription
                break
            }
        }
    } catch {
        $CurrentDescription = "Connecting to AzureAD please check if ExchangeOnlineManagement Powershell Module is installed & imported"
        $CurrentStatus = "Failure"
        log -CurrentStatus $CurrentStatus -Function "Connecting to AzureAD" -CurrentDescription $CurrentDescription
        break
    }
}
