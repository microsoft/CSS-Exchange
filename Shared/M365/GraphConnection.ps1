# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
This script defines a function `Connect-GraphAdvanced` that establishes a connection to Microsoft Graph.
It ensures that the required modules are installed and loaded.
The function accepts a list of scopes and modules, with optional parameters for tenant ID and connection details display.
If the required modules are not found, the script attempts to install them.
The function returns the connection information or null if the connection fails.

.PARAMETER Scope
 Mandatory array of strings specifying the scopes for the connection.
.PARAMETER Module
 Mandatory array of strings specifying the modules required for the connection.
.PARAMETER TenantId
 Optional array of strings specifying the tenant ID(s) for the connection.
.PARAMETER Environment
 Optional Microsoft Graph environment. Valid values are Global, USGov, USGovDoD, and China. The default is Global.
.PARAMETER DoNotShowConnectionDetails
 Optional switch to hide connection details.
.PARAMETER MinModuleVersion
 Optional parameter to specify the minimum version of the Graph modules (default and minimum supported version 2.0.0).

.OUTPUTS
Microsoft.Graph.PowerShell.Authentication.AuthContext on success. The function returns $null on failure and does not throw operational errors.
Callers should verify the return value before continuing.

.EXAMPLE
$graphConnection = Connect-GraphAdvanced -Scope User.Read, Mail.Read -Module Microsoft.Graph
This example establishes a connection to Microsoft Graph with the scopes "User.Read" and "Mail.Read" using the "Microsoft.Graph" module.

.EXAMPLE
$graphConnection = Connect-GraphAdvanced -Scope Group.Read.All, User.Read.All -Module Microsoft.Graph.Users, Microsoft.Graph.Groups
This example establishes a connection to Microsoft Graph with the scopes "Group.Read.All" and "User.Read.All" using the "Microsoft.Graph.Users" and "Microsoft.Graph.Groups" modules.

.EXAMPLE
$graphConnection = Connect-GraphAdvanced -Scope Group.Read.All, User.Read.All -Module Microsoft.Graph.Users, Microsoft.Graph.Groups -MinModuleVersion 2.25.0
This example establishes a connection to Microsoft Graph with the scopes "Group.Read.All" and "User.Read.All" using the "Microsoft.Graph.Users" and "Microsoft.Graph.Groups" modules, and specifies a minimum module version of 2.25.0.

.EXAMPLE
$graphConnection = Connect-GraphAdvanced -Scope User.Read -Module Microsoft.Graph.Users -Environment USGov
This example establishes a connection to the Microsoft Graph US Government environment.

.EXAMPLE
$graph = Connect-GraphAdvanced -Scope User.Read -Module Microsoft.Graph.Users -Confirm:$false
if (-not $graph) {
    return
}
This example establishes a connection without confirmation prompts for unattended automation and stops the caller when the connection fails.

.NOTES
Connect-GraphAdvanced has ConfirmImpact set to High. Unattended callers must explicitly pass -Confirm:$false.
The function returns $null on failure instead of throwing. Always validate the returned connection before continuing.
#>

. $PSScriptRoot\..\ModuleHandle.ps1

$Script:graphAdvancedConnectionCreated = $false

function Connect-GraphAdvanced {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Scope,
        [Parameter(Mandatory = $true)]
        [string[]]$Module,
        [Parameter(Mandatory = $false)]
        [string]$TenantId = $null,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Global", "USGov", "USGovDoD", "China")]
        [string]$Environment = "Global",
        [Parameter(Mandatory = $false)]
        [switch]$DoNotShowConnectionDetails,
        [ValidateScript({
                if ($_ -lt [System.Version]'2.0.0.0') {
                    throw "Minimum supported version: 2.0.0.0"
                }
                $true
            })]
        [Parameter(Mandatory = $false)]
        [System.Version]$MinModuleVersion = '2.0.0.0'
    )

    #Validate Graph is installed and loaded
    foreach ($m in $Module) {
        $requestModule = $null
        $requestModule = Request-Module -Module $m -MinModuleVersion $MinModuleVersion
        if (-not $requestModule) {
            Write-Host "We cannot continue without $m Powershell module" -ForegroundColor Red
            return $null
        }
    }

    #Validate Graph is connected or try to connect
    $connection = $null
    try {
        $connection = Get-MgContext -ErrorAction Stop
    } catch {
        Write-Host "We cannot check context. Error:`n$_" -ForegroundColor Red
        return $null
    }

    $requiresConnection = $false
    $newConnection = $null
    if ($null -eq $connection) {
        Write-Host "Not connected to Graph" -ForegroundColor Yellow
        $requiresConnection = $true
    } elseif ($connection.Environment -ne $Environment) {
        Write-Host "Not connected to the expected Graph environment: $Environment" -ForegroundColor Yellow
        $requiresConnection = $true
    } else {
        Write-Verbose "You have a Graph sessions"
        Write-Verbose "Checking scopes"
        if (-not (Test-GraphScopeContext -Scope $connection.Scopes -ExpectedScope $Scope)) {
            Write-Host "Not connected to Graph with expected scopes" -ForegroundColor Yellow
            $requiresConnection = $true
        } else {
            Write-Verbose "All scopes are present"
            $newConnection = $connection
        }
    }

    if ($requiresConnection) {
        if ($PSCmdlet.ShouldProcess("Microsoft Graph session", "Connect with scopes $Scope in the $Environment environment")) {
            $newConnection = Add-GraphConnection -Scope $Scope -Environment $Environment -Confirm:$false
        }
    }

    if ($newConnection) {
        Write-Verbose "Checking TenantId"
        if ($TenantId) {
            if ($newConnection.TenantId -ne $TenantId) {
                Write-Host "Connected to $($newConnection.TenantId). Not expected tenant: $TenantId" -ForegroundColor Red
                return $null
            } else {
                Write-Verbose "TenantId is correct"
            }
        }

        $newConnection.PSObject.Properties | ForEach-Object { Write-Verbose "$($_.Name): $($_.Value)" }
        if (-not $DoNotShowConnectionDetails) {
            Show-GraphContext -Context $newConnection
        }
    }
    return $newConnection
}

function Add-GraphConnection {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Scope,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Global", "USGov", "USGovDoD", "China")]
        [string]$Environment = "Global"
    )

    if ($PSCmdlet.ShouldProcess("Do you want to connect?", "We need a Graph connection with scopes $Scope")) {
        $Script:graphAdvancedConnectionCreated = $false
        Write-Verbose "Connecting to the Microsoft Graph $Environment environment using scopes $Scope"
        try {
            Connect-MgGraph -Scope $Scope -Environment $Environment -NoWelcome -ErrorAction Stop
        } catch {
            Write-Host "We cannot connect to Graph. Error:`n$_" -ForegroundColor Red
            return $null
        }
        $connection = $null
        try {
            $connection = Get-MgContext -ErrorAction Stop
        } catch {
            Write-Host "We cannot check context. Error:`n$_" -ForegroundColor Red
            return $null
        }
        Write-Verbose "Checking scopes"
        if (-not $connection) {
            Write-Host "We cannot continue without Graph Powershell session" -ForegroundColor Red
            return $null
        }
        Write-Verbose "Checking environment"
        if ($connection.Environment -ne $Environment) {
            Write-Host "We cannot continue without the expected Graph environment: $Environment" -ForegroundColor Red
            return $null
        }
        if (-not (Test-GraphScopeContext -Scope $connection.Scopes -ExpectedScope $Scope)) {
            Write-Host "We cannot continue without Graph Powershell session without Expected Scopes" -ForegroundColor Red
            return $null
        }
        $Script:graphAdvancedConnectionCreated = $true
        return $connection
    }
}

<#
.SYNOPSIS
Disconnects the Microsoft Graph session created by the advanced Graph connection functions.

.DESCRIPTION
Disconnects only when Add-GraphConnection successfully created and validated a Microsoft Graph session.
Pre-existing connections are not disconnected.

.EXAMPLE
Disconnect-GraphAdvanced
Disconnects the Microsoft Graph session created by Add-GraphConnection.
#>
function Disconnect-GraphAdvanced {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param ()

    if (-not $Script:graphAdvancedConnectionCreated) {
        Write-Verbose "There is no Microsoft Graph session created by the advanced Graph connection functions."
        return
    }

    if ($PSCmdlet.ShouldProcess("Microsoft Graph session", "Disconnect the tracked session")) {
        try {
            Disconnect-MgGraph -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "We cannot disconnect from Graph. Error:`n$_" -ForegroundColor Red
            return
        }
        $Script:graphAdvancedConnectionCreated = $false
        Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Yellow
    }
}

function Test-GraphScopeContext {
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedScope,
        [Parameter(Mandatory = $true)]
        [string[]]$Scope
    )

    $foundError = $false
    foreach ($es in $ExpectedScope) {
        if ($Scope -notcontains $es) {
            Write-Host "The following scope is missing: $es" -ForegroundColor Red
            $foundError = $true
        }
    }

    Write-Verbose "All expected scopes are $(if($foundError){ "NOT "})present."
    return (-not $foundError)
}

function Show-GraphContext {
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.Graph.PowerShell.Authentication.AuthContext]$Context
    )
    Write-Host "`nConnected to Graph"
    Write-Host "Session details"
    Write-Host "Tenant Id: $($Context.TenantId)"
    if ($Context.AuthType) {
        Write-Host "AuthType: $($Context.AuthType)"
    }
    if ($Context.Account) {
        Write-Host "Account: $($Context.Account)"
    }
}
