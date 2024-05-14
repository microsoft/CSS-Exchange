# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-AADConnection {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes,
        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    #Validate Graph is installed and loaded
    $loadedInstalled = $false
    $loadedInstalled = Test-M365ModuleLoaded -ModuleName "Microsoft.Graph" -MinModuleVersion 3.2.0
    if (-not $loadedInstalled) {
        $loadedInstalled = Test-M365ModuleInstalled -ModuleName "Microsoft.Graph" -MinModuleVersion 3.2.0
        if (-not $loadedInstalled) {
            $loadedInstalled = Install-M365Module -ModuleName "Microsoft.Graph" -MinModuleVersion 3.2.0
        }
        if ($loadedInstalled) {
            $loadedInstalled = Import-M365Module Microsoft.Graph -ErrorAction SilentlyContinue -Force -MinModuleVersion 3.2.0
            if (-not $loadedInstalled) {
                Write-Host "We cannot continue without Microsoft.Graph Powershell module" -ForegroundColor Red
                break
            }
        } else {
            Write-Host "We cannot continue without Microsoft.Graph Powershell module" -ForegroundColor Red
            break
        }
    }

    #Validate Graph is connected or try to connect
    $connection = $null
    $connection = Get-MgContext -ErrorAction SilentlyContinue
    if ($null -eq $connection) {
        Write-Host "Not connected to Graph" -ForegroundColor Red
        Write-Host "Please use Global administrator credentials" -ForegroundColor Yellow
        if ($Force -or $PSCmdlet.ShouldContinue("Do you want to connect?", "We need a AzureAD connection")) {
            Connect-MgGraph -Scopes $Scopes -ErrorAction SilentlyContinue
            $connection = Get-MgContext -ErrorAction SilentlyContinue
            if ($null -eq $connection) {
                Write-Host "Connection could not be established" -ForegroundColor Red
                Write-Host "We cannot continue without Graph Powershell session" -ForegroundColor Red
                return $false
            } else {
                if (Test-GraphContext -Scopes $connection.Scopes -ExpectedScopes $Scopes) {
                    Write-Host "Connected to Graph"
                    Write-Host "Session details"
                    Write-Host "Tenant: $((Get-MgOrganization).DisplayName)"
                    return $true
                } else {
                    Write-Host "We cannot continue without Graph Powershell session non Expeced Scopes found" -ForegroundColor Red
                    return $false
                }
            }
        } else {
            Write-Host "We cannot continue without Graph Powershell session" -ForegroundColor Red
            return $false
        }
    } elseif ($connection.count -eq 1) {
        if (Test-GraphContext -Scopes $connection.Scopes -ExpectedScopes $Scopes) {
            Write-Host "Connected to Graph"
            Write-Host "Session details"
            Write-Host "Tenant: $((Get-MgOrganization).DisplayName)"
            return $true
        } else {
            Write-Host "We cannot continue without Graph Powershell session non Expeced Scopes found" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "You have more than one Graph sessions please use just one session" -ForegroundColor Red
        return $false
    }
}

function Test-GraphContext {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes,
        [Parameter(Mandatory = $true)]
        [string[]]$ValidScopes
    )

    $missingScopes = Compare-Object -ReferenceObject $ExpectedScopes -DifferenceObject $Scopes

    if ($missingScopes) {
        Write-Host "The following scopes are missing: $($missingScopes | ForEach-Object { $_.InputObject })" -ForegroundColor Red
        return $false
    } else {
        Write-Verbose "All expected scopes are present." -ForegroundColor Green
        return $true
    }
}
