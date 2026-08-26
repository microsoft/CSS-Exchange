# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\New-AzureApiPermissionEntry.ps1
. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Retrieves app role definitions for specified API permissions from a service principal.

.DESCRIPTION
    This function queries an Azure AD service principal by its AppId and retrieves the permission
    definitions that match the specified permission names and types. For Application permissions,
    it searches appRoles; for Delegated permissions, it searches oauth2PermissionScopes.
    This is typically used to get the permission IDs needed when configuring API permissions
    on an Azure application.

    The function performs the following operations:
    1. Queries the service principal using the provided AppId via Graph API
    2. Retrieves the appRoles, oauth2PermissionScopes, and resourceSpecificApplicationPermissions
    3. For each requested permission, finds the matching definition by name and type
       (appRoles for Application, oauth2PermissionScopes for Delegated)
    4. Returns a result object containing all found permissions and whether all were found

    This function is commonly used in conjunction with Add-AzureApplicationRole to first
    discover the app role IDs, then add them to an application's requiredResourceAccess.

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context (AccessToken) for Graph API calls.

.PARAMETER AppId
    The Application ID (AppId/ClientId) of the service principal to query. This is typically
    a well-known Microsoft API AppId such as:
    - Microsoft Graph: 00000003-0000-0000-c000-000000000000
    - Office 365 Exchange Online: 00000002-0000-0ff1-ce00-000000000000

.PARAMETER Permissions
    A hashtable where keys are permission names (e.g., "Mail.Read", "full_access_as_app")
    and values are arrays of permission types (e.g., @("Application"), @("Application", "Delegated")).

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL to use for API requests (e.g., "https://graph.microsoft.com").

.OUTPUTS
    PSCustomObject with the following properties:
    - AllPermissionsFound: Boolean indicating whether all requested permissions were found
    - ApiPermissions: List of permission entry objects, each containing:
        - AppRole: The app role object with id, value, displayName, description, allowedMemberTypes, etc.
        - PermissionType: The type of permission ("Application" or "Delegated")

.EXAMPLE
    $permissions = @{
        "Mail.Read" = @("Application", "Delegated")
        "User.Read" = @("Delegated")
    }
    $result = Get-AzureApiPermission -AzAccountsObject $azContext -AppId "00000003-0000-0000-c000-000000000000" -Permissions $permissions -GraphApiUrl "https://graph.microsoft.com"

    if ($result.AllPermissionsFound) {
        Write-Host "Found all permissions"
        $result.ApiPermissions | ForEach-Object { Write-Host "- $($_.AppRole.value): $($_.AppRole.id)" }
    }

.NOTES
    Required Graph API permissions:
    - Application.Read.All (to read service principal information)

    API References:
    - List service principals: https://learn.microsoft.com/graph/api/serviceprincipal-list
    - App role resource: https://learn.microsoft.com/graph/api/resources/approle
    - Permissions reference: https://learn.microsoft.com/graph/permissions-reference
#>
function Get-AzureApiPermission {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AppId,

        [ValidateNotNullOrEmpty()]
        [hashtable]$Permissions,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Query Service Principal by using App Id: $AppId via Graph Api: $GraphApiUrl"

    $apiPermissionsList = New-Object System.Collections.Generic.List[object]
    $appRolesAddedIndex = 0
    $expectedPermissionsCount = ($Permissions.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum

    $queryServicePrincipalParams = @{
        Query       = "servicePrincipals(appId='$AppId')?`$select=id,appId,displayName,appRoles,oauth2PermissionScopes,resourceSpecificApplicationPermissions"
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $queryServicePrincipalResponse = Invoke-GraphApiRequest @queryServicePrincipalParams

    if ($queryServicePrincipalResponse.Successful -eq $false) {
        Write-Verbose "Something went wrong while querying the service principal using app id: $AppId"
        return
    }

    foreach ($permission in $Permissions.GetEnumerator()) {
        foreach ($permType in $permission.Value) {
            Write-Verbose "Searching for permission: $($permission.Key) with type: $permType"

            # Create the API permission entry object using the factory function
            # The parameter set determines whether appRoles or oauth2PermissionScopes is searched
            $newAzureApiPermissionEntryParams = @{
                PermissionName = $permission.Key
            }

            if ($permType -eq "Delegated") {
                $newAzureApiPermissionEntryParams["OAuth2PermissionScopes"] = $queryServicePrincipalResponse.Content.oauth2PermissionScopes
            } else {
                $newAzureApiPermissionEntryParams["AppRoles"] = $queryServicePrincipalResponse.Content.appRoles
            }

            $appRoleCustomObject = New-AzureApiPermissionEntry @newAzureApiPermissionEntryParams

            if ([System.String]::IsNullOrEmpty($appRoleCustomObject.AppRole.id)) {
                Write-Verbose "No permission definition found for: $($permission.Key) with type: $permType"
                continue
            }

            Write-Verbose "Found permission definition for: $($permission.Key) with type: $permType - Id: $($appRoleCustomObject.AppRole.id)"
            $apiPermissionsList.Add($appRoleCustomObject)
            $appRolesAddedIndex++
        }
    }

    Write-Verbose "Returning permissions for application with DisplayName: $($queryServicePrincipalResponse.Content.displayName)"

    return [PSCustomObject]@{
        AllPermissionsFound = ($appRolesAddedIndex -eq $expectedPermissionsCount)
        AppId               = $AppId
        ApiPermissions      = $apiPermissionsList
    }
}
