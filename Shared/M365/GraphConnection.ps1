# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\ModuleHandle.ps1

function Connect-GraphAdvanced {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes,
        [Parameter(Mandatory = $true)]
        [string[]]$Modules,
        [Parameter(Mandatory = $false)]
        [switch]$DoNotShowConnectionDetails
    )

    #Validate Graph is installed and loaded
    $requestModule = $false
    $requestModule = Request-Module -Modules $Modules
    if (-not $requestModule) {
        Write-Host "We cannot continue without $Modules Powershell module" -ForegroundColor Red
        return $null
    }

    #Validate Graph is connected or try to connect
    $connection = $null
    $connection = Get-MgContext -ErrorAction SilentlyContinue
    if ($null -eq $connection) {
        Write-Host "Not connected to Graph" -ForegroundColor Yellow
        $connection = Add-GraphConnection -Scopes $Scopes
    } else {
        Write-Verbose "You have a Graph sessions"
        Write-Verbose "Checking scopes"
        if (-not (Test-GraphContext -Scopes $connection.Scopes -ExpectedScopes $Scopes)) {
            Write-Host "Not connected to Graph with expected scopes" -ForegroundColor Yellow
            $connection = Add-GraphConnection -Scopes $Scopes
        }
    }
    if ($null -ne $connection -and -not $DoNotShowConnectionDetails) {
        $connection.PSObject.Properties | ForEach-Object { Write-Verbose "$($_.Name): $($_.Value)" }
        Show-GraphContext -Context $connection
    }
    return $connection
}

function Add-GraphConnection {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )

    if ($PSCmdlet.ShouldProcess("Do you want to connect?", "We need a Graph connection with scopes $Scopes")) {
        Write-Verbose "Connecting to Microsoft Graph API using scopes $Scopes"
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction SilentlyContinue
        $connection = $null
        $connection = Get-MgContext -ErrorAction SilentlyContinue
        Write-Verbose "Checking scopes"
        if (-not $connection) {
            Write-Host "We cannot continue without Graph Powershell session" -ForegroundColor Red
            return $null
        }
        if (-not (Test-GraphContext -Scopes $connection.Scopes -ExpectedScopes $Scopes)) {
            Write-Host "We cannot continue without Graph Powershell session without Expected Scopes" -ForegroundColor Red
            return $null
        }
        return $connection
    }
}

function Test-GraphContext {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedScopes,
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )

    $foundError = $false
    foreach ($expectedScope in $ExpectedScopes) {
        if ($Scopes -notcontains $expectedScope) {
            Write-Host "The following scope is missing: $expectedScope" -ForegroundColor Red
            $foundError = $true
        }
    }

    if ($foundError) {
        return $false
    } else {
        Write-Verbose "All expected scopes are present."
        return $true
    }
}

function Show-GraphContext {
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.Graph.PowerShell.Authentication.AuthContext]$Context
    )
    Write-Host "`nConnected to Graph"
    Write-Host "Session details"
    Write-Host "Tenant Id: $($Context.TenantId)"
    Write-Host "Account: $($Context.Account)"
}
