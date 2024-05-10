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
