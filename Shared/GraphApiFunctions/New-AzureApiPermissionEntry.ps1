# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Factory function that creates an API permission entry object.

.DESCRIPTION
    Creates a standardized PSCustomObject representing an API permission entry.
    Uses parameter sets to enforce correct input:

    - Pass -AppRoles to resolve an Application permission (from appRoles).
    - Pass -OAuth2PermissionScopes to resolve a Delegated permission (from oauth2PermissionScopes).

    Both collections are available on the service principal object returned by the Graph API.

.PARAMETER AppRoles
    The collection of app roles from the service principal's appRoles property.
    Each app role contains properties like id, value, displayName, description, allowedMemberTypes, etc.
    Passing this parameter selects the Application parameter set.

.PARAMETER OAuth2PermissionScopes
    The collection of delegated permission scopes from the service principal's oauth2PermissionScopes property.
    Each scope contains properties like id, value, adminConsentDisplayName, adminConsentDescription, type, etc.
    Passing this parameter selects the Delegated parameter set.

.PARAMETER PermissionName
    The name/value of the permission to search for (e.g., "Mail.Read", "User.Read.All").

.OUTPUTS
    PSCustomObject with the following properties:
    - AppRole: The matching permission definition object containing id, value, and other details, or $null if not found.
              For Application permissions this is an appRole object; for Delegated this is an oauth2PermissionScope object.
    - PermissionType: The resolved type of permission ("Application" or "Delegated")

.EXAMPLE
    $entry = New-AzureApiPermissionEntry -AppRoles $sp.appRoles -PermissionName "Mail.Read"

    Resolves an Application permission from appRoles.

.EXAMPLE
    $entry = New-AzureApiPermissionEntry -OAuth2PermissionScopes $sp.oauth2PermissionScopes -PermissionName "User.Read"

    Resolves a Delegated permission from oauth2PermissionScopes.
#>
function New-AzureApiPermissionEntry {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'This function only creates an in-memory object and does not change system state.')]
    [CmdletBinding(DefaultParameterSetName = "Application")]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "Application")]
        $AppRoles,

        [Parameter(Mandatory = $true, ParameterSetName = "Delegated")]
        $OAuth2PermissionScopes,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PermissionName
    )

    $permissionType = $PSCmdlet.ParameterSetName

    if ($permissionType -eq "Delegated") {
        # Delegated permissions are represented as oauth2PermissionScopes on the service principal
        # https://learn.microsoft.com/graph/api/resources/permissionscope?view=graph-rest-1.0
        $scopeResults = @($OAuth2PermissionScopes | Where-Object { $_.value -eq $PermissionName })

        if ($scopeResults.Count -gt 1) {
            Write-Error "Found $($scopeResults.Count) matching oauth2PermissionScopes for '$PermissionName'. Expected exactly one."
            return
        }

        return [PSCustomObject]@{
            AppRole        = ($scopeResults | Select-Object -First 1)
            PermissionType = $permissionType
        }
    }

    # Application permissions are represented as appRoles on the service principal
    # Filter by permission name (value) and ensure "Application" is in allowedMemberTypes
    # https://learn.microsoft.com/graph/api/resources/approle?view=graph-rest-1.0#properties
    $appRoleResults = @($AppRoles | Where-Object {
            $_.value -eq $PermissionName -and
            $_.allowedMemberTypes -contains "Application"
        })

    if ($appRoleResults.Count -gt 1) {
        Write-Error "Found $($appRoleResults.Count) matching app roles for '$PermissionName' (Application). Expected exactly one."
        return
    }

    return [PSCustomObject]@{
        AppRole        = ($appRoleResults | Select-Object -First 1)
        PermissionType = $permissionType
    }
}
