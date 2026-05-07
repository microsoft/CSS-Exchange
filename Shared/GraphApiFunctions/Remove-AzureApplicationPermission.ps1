# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AzureApiPermission.ps1
. $PSScriptRoot\Get-AzureApplication.ps1
. $PSScriptRoot\Get-AzureAppRoleAssignments.ps1
. $PSScriptRoot\Get-AzureServicePrincipal.ps1
. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Removes specified API permissions from an Azure AD application.

.DESCRIPTION
    This function fully removes API permissions from an application by performing two operations:
    1. Removes the app role assignments (admin consent grants) from all service principals associated with the application
    2. Updates the application's requiredResourceAccess to remove the permission entries from the manifest

    It accepts an array of API permission objects (created by New-ApiPermissionObject) and removes
    the matching permissions from all service principals and the application registration.

    The function performs the following operations:
    1. For each API permission object, looks up the app role IDs using Get-AzureApiPermission
    2. Retrieves all service principals for the application (handles multi-tenant scenarios where multiple may exist)
    3. For each service principal, gets all current app role assignments
    4. Deletes the matching app role assignments via Graph API (removes admin consent) from each service principal
    5. Retrieves the application object to get its requiredResourceAccess
    6. Updates the application's requiredResourceAccess to remove the permissions (updates manifest)

    This is useful for removing specific API permissions (e.g., EWS or Graph) from an application
    without affecting other permissions. The function ensures complete cleanup by processing all
    service principals associated with the application.

.PARAMETER AzAccountsObject
    An object containing the access token for authenticating to Microsoft Graph API.
    Must have the AccessToken property populated.

.PARAMETER AzureApplicationId
    The Application (client) ID of the Azure AD application from which to remove permissions.
    This is the AppId, not the object ID.

.PARAMETER ApiPermissions
    An array of API permission objects (created by New-ApiPermissionObject) specifying which
    permissions to remove. Each object contains:
    - ApiType: "Graph" or "EWS"
    - FirstPartyAppId: The resource application ID
    - Permissions: Hashtable of permission names and types

.PARAMETER GraphApiUrl
    The base URL for the Microsoft Graph API endpoint (e.g., https://graph.microsoft.com/v1.0).

.OUTPUTS
    System.Boolean
    Returns $true if all permissions were successfully removed, $false if any removal failed.

.EXAMPLE
    $ewsPermissions = New-ApiPermissionObject -ApiType "EWS" -Permissions "full_access_as_app" -PermissionType "Application"
    Remove-AzureApplicationPermission -AzAccountsObject $token -AzureApplicationId "12345678-..." -ApiPermissions @($ewsPermissions) -GraphApiUrl "https://graph.microsoft.com/v1.0"

    Removes EWS full_access_as_app permission from the specified application (both admin consent and manifest entry).

.LINK
    https://learn.microsoft.com/graph/api/serviceprincipal-delete-approleassignments
    https://learn.microsoft.com/graph/api/application-update
#>
function Remove-AzureApplicationPermission {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        [string]$AzureApplicationId,

        [ValidateNotNullOrEmpty()]
        [object[]]$ApiPermissions,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Removing API permissions from application: $AzureApplicationId via Graph API: $GraphApiUrl"

    # Common parameters used across all Graph API calls in this function
    $graphApiBaseParams = @{
        GraphApiUrl      = $GraphApiUrl
        AzAccountsObject = $AzAccountsObject
    }

    # Track overall success - will be set to $false if any individual removal fails
    $allRemovalsSuccessful = $true

    # ============================================================================
    # STEP 1: Resolve permission names to app role IDs
    # ============================================================================
    # Azure AD permissions are identified by GUIDs (app role IDs), not by their friendly names.
    # This section translates the human-readable permission names (e.g., "Mail.Read") into
    # their corresponding app role IDs by querying the resource application's service principal.
    #
    # We build a hashtable where:
    #   - Key: The resource application ID (e.g., Microsoft Graph's app ID)
    #   - Value: List of app role IDs to remove from that resource
    # ============================================================================
    $appRoleIdsToRemove = @{}

    foreach ($apiPermission in $ApiPermissions) {
        Write-Verbose "Looking up $($apiPermission.ApiType) permission definitions"

        # Query the resource application (e.g., Microsoft Graph) to get the app role definitions
        # This translates permission names like "Mail.Read" to their GUID app role IDs
        $getAzureApiPermissionsParams = $graphApiBaseParams + @{
            AppId       = $apiPermission.FirstPartyAppId
            Permissions = $apiPermission.Permissions
        }

        $apiPermissionsResponse = Get-AzureApiPermission @getAzureApiPermissionsParams

        if ($null -eq $apiPermissionsResponse -or $apiPermissionsResponse.AllPermissionsFound -eq $false) {
            # This is not necessarily an error - the permission might have already been removed
            # or the permission name might be invalid. We continue with whatever permissions we found.
            Write-Verbose "Could not find all requested permissions for $($apiPermission.ApiType) - some permissions may not exist"
        }

        # Add the found permission IDs to our removal list, grouped by resource application
        if ($null -ne $apiPermissionsResponse.ApiPermissions -and $apiPermissionsResponse.ApiPermissions.Count -gt 0) {
            if (-not $appRoleIdsToRemove.ContainsKey($apiPermission.FirstPartyAppId)) {
                $appRoleIdsToRemove[$apiPermission.FirstPartyAppId] = New-Object System.Collections.Generic.List[string]
            }

            foreach ($permissionEntry in $apiPermissionsResponse.ApiPermissions) {
                $appRoleIdsToRemove[$apiPermission.FirstPartyAppId].Add($permissionEntry.AppRole.id)
                Write-Verbose "Will remove appRoleId: $($permissionEntry.AppRole.id) ($($permissionEntry.AppRole.value)) from resource: $($apiPermission.FirstPartyAppId)"
            }
        }
    }

    # If no permissions were found to remove, we're done - this is considered a success
    # (the permissions are already not present)
    if ($appRoleIdsToRemove.Count -eq 0) {
        Write-Verbose "No matching permission definitions found to remove"
        return $true
    }

    #region Remove admin consent (appRoleAssignments) from service principal(s)
    # ============================================================================
    # STEP 2: Remove admin consent (app role assignments) from service principals
    # ============================================================================
    # TODO: This phase only removes Application permission consent via appRoleAssignments.
    # To support Delegated permissions, also query oauth2PermissionGrants for the service
    # principal, PATCH the grant to remove the target scopes from the space-delimited scope
    # string (or DELETE the grant entirely if no scopes remain).
    # ============================================================================
    # In Azure AD, there are TWO places where API permissions are stored:
    #   1. App Role Assignments on the Service Principal - These represent "admin consent"
    #      and grant the application actual access to the API. Stored per-tenant.
    #   2. Required Resource Access on the Application - This is the manifest declaration
    #      of what permissions the app requests. This is the "ask", not the "grant".
    #
    # This phase removes the app role assignments (the actual grants).
    #
    # IMPORTANT: An application can have multiple service principals in multi-tenant scenarios.
    # Each tenant that consents to the app gets its own service principal. We must process
    # ALL service principals to ensure complete cleanup of admin consent grants.
    # ============================================================================
    Write-Verbose "Phase 1: Removing admin consent (appRoleAssignments) from service principal(s)"

    # Retrieve ALL service principals for this application
    # Setting AllowReturnMultipleServicePrincipals to $true ensures we don't miss any
    $servicePrincipals = Get-AzureServicePrincipal @graphApiBaseParams -AzureApplicationId $AzureApplicationId -AllowReturnMultipleServicePrincipals $true

    if ($null -eq $servicePrincipals -or $servicePrincipals.Count -eq 0) {
        # No service principal means the app was never consented to in this tenant
        # This is fine - we'll still update the manifest in Phase 2
        Write-Verbose "Service principal not found for application: $AzureApplicationId - skipping admin consent removal"
    } else {
        Write-Verbose "Found $($servicePrincipals.Count) service principal(s) for application: $AzureApplicationId"

        # Process each service principal independently
        # Each one may have different app role assignments depending on what was consented
        foreach ($servicePrincipal in $servicePrincipals) {
            $servicePrincipalId = $servicePrincipal.SpnObjectId
            Write-Verbose "Processing service principal with ID: $servicePrincipalId (DisplayName: $($servicePrincipal.AppDisplayName))"

            # Get all current app role assignments for this service principal
            # These represent the permissions that have been admin-consented
            $currentAssignments = Get-AzureAppRoleAssignments @graphApiBaseParams -ServicePrincipalId $servicePrincipalId

            if ($null -eq $currentAssignments -or $currentAssignments.Count -eq 0) {
                # No assignments means nothing to remove for this service principal
                Write-Verbose "No app role assignments found for service principal: $servicePrincipalId"
                continue
            }

            Write-Verbose "Found $($currentAssignments.Count) app role assignment(s) on the service principal"

            # Iterate through each permission we want to remove and delete the matching assignment
            foreach ($resourceAppId in $appRoleIdsToRemove.Keys) {
                foreach ($appRoleId in $appRoleIdsToRemove[$resourceAppId]) {
                    # Find the assignment that matches this app role ID
                    $matchingAssignment = $currentAssignments | Where-Object { $_.AppRoleId -eq $appRoleId }

                    if ($null -eq $matchingAssignment) {
                        # The permission might be in the manifest but not actually consented
                        # This is normal and not an error
                        Write-Verbose "No app role assignment found for appRoleId: $appRoleId - it may not have admin consent"
                        continue
                    }

                    Write-Verbose "Removing app role assignment - Id: $($matchingAssignment.Id) ResourceDisplayName: $($matchingAssignment.ResourceDisplayName)"

                    # DELETE the app role assignment via Graph API
                    # This revokes the admin consent for this specific permission
                    # Expected response: HTTP 204 No Content on success
                    $removeParams = @{
                        Query              = "servicePrincipals/$servicePrincipalId/appRoleAssignments/$($matchingAssignment.Id)"
                        AccessToken        = $AzAccountsObject.AccessToken
                        Method             = "DELETE"
                        ExpectedStatusCode = 204
                        GraphApiUrl        = $GraphApiUrl
                    }

                    if ($PSCmdlet.ShouldProcess("Remove admin consent for appRoleId: $appRoleId from service principal: $servicePrincipalId", "DELETE appRoleAssignment")) {
                        $removeResponse = Invoke-GraphApiRequest @removeParams

                        if ($removeResponse.Successful -eq $false) {
                            Write-Verbose "Failed to remove admin consent for appRoleId: $appRoleId from service principal: $servicePrincipalId"
                            $allRemovalsSuccessful = $false
                        } else {
                            Write-Verbose "Successfully removed admin consent for appRoleId: $appRoleId from service principal: $servicePrincipalId"
                        }
                    }
                }
            }
        }
    }
    #endregion

    #region Remove permissions from application manifest (requiredResourceAccess)
    # ============================================================================
    # STEP 3: Remove permissions from the application manifest (requiredResourceAccess)
    # ============================================================================
    # The requiredResourceAccess property on the application object defines what permissions
    # the application declares it needs. This is visible in the Azure Portal under
    # "API Permissions" for the app registration.
    #
    # Even after removing admin consent (Phase 1), the permission entries remain in the
    # manifest. This phase cleans up those entries so the permissions no longer appear
    # in the Azure Portal and won't be re-consented accidentally.
    #
    # The structure of requiredResourceAccess is:
    #   [
    #     {
    #       "resourceAppId": "<resource-app-id>",      // e.g., Microsoft Graph
    #       "resourceAccess": [
    #         { "id": "<app-role-id>", "type": "Role" }  // Each permission
    #       ]
    #     }
    #   ]
    # ============================================================================
    Write-Verbose "Phase 2: Removing permissions from application manifest (requiredResourceAccess)"

    # Query the application to get its object ID and current requiredResourceAccess
    $applicationInfo = Get-AzureApplication @graphApiBaseParams -AzureApplicationId $AzureApplicationId

    if ($null -eq $applicationInfo -or $applicationInfo.ApplicationExists -eq $false) {
        Write-Verbose "Failed to query application or application not found: $AzureApplicationId"
        return $false
    }

    $applicationObjectId = $applicationInfo.Id
    $currentRequiredResourceAccess = @($applicationInfo.RequiredResourceAccess | Where-Object { $null -ne $_ })

    if ($currentRequiredResourceAccess.Count -eq 0) {
        Write-Verbose "No requiredResourceAccess entries found on the application - nothing to remove from manifest"
        return $allRemovalsSuccessful
    }

    Write-Verbose "Application object ID: $applicationObjectId"
    Write-Verbose "Current requiredResourceAccess entries: $($currentRequiredResourceAccess.Count)"

    # Build the updated requiredResourceAccess by filtering out the permissions we want to remove
    # We construct a new list rather than modifying in place to ensure clean JSON serialization
    $updatedRequiredResourceAccess = New-Object System.Collections.Generic.List[object]

    foreach ($resourceAccess in $currentRequiredResourceAccess) {
        $resourceAppId = $resourceAccess.resourceAppId

        if ($appRoleIdsToRemove.ContainsKey($resourceAppId)) {
            # This resource (e.g., Microsoft Graph) has some permissions we need to remove
            # Filter out the permissions that match our removal list
            $appRoleIdsToRemoveForResource = $appRoleIdsToRemove[$resourceAppId]

            $filteredResourceAccess = @($resourceAccess.resourceAccess | Where-Object {
                    $_.id -notin $appRoleIdsToRemoveForResource
                })

            if ($filteredResourceAccess.Count -gt 0) {
                # Some permissions remain for this resource - keep the entry with filtered permissions
                # Example: App had Mail.Read and Mail.Send, we're removing Mail.Read, keep Mail.Send
                $updatedRequiredResourceAccess.Add([PSCustomObject]@{
                        resourceAppId  = $resourceAppId
                        resourceAccess = $filteredResourceAccess
                    })
                Write-Verbose "Resource $resourceAppId Kept $($filteredResourceAccess.Count) permission(s), removed $($resourceAccess.resourceAccess.Count - $filteredResourceAccess.Count)"
            } else {
                # All permissions for this resource are being removed - omit the entire entry
                # This removes the resource completely from the manifest
                Write-Verbose "Resource $resourceAppId All permissions removed, entry will be deleted"
            }
        } else {
            # This resource is not in our removal list - preserve it unchanged
            # We only modify resources that have permissions we're explicitly removing
            $updatedRequiredResourceAccess.Add($resourceAccess)
            Write-Verbose "Resource $resourceAppId Not affected, keeping all $($resourceAccess.resourceAccess.Count) permission(s)"
        }
    }

    # Update the application with the new requiredResourceAccess
    # We use PATCH to update only this property, leaving other app settings unchanged
    # Depth 10 ensures nested objects are properly serialized
    $updateBody = @{
        requiredResourceAccess = $updatedRequiredResourceAccess
    } | ConvertTo-Json -Depth 10

    # PATCH the application object via Graph API
    # Expected response: HTTP 204 No Content on success
    $updateApplicationParams = @{
        Query              = "applications/$applicationObjectId"
        AccessToken        = $AzAccountsObject.AccessToken
        Method             = "PATCH"
        Body               = $updateBody
        ExpectedStatusCode = 204
        GraphApiUrl        = $GraphApiUrl
    }

    if ($PSCmdlet.ShouldProcess("Update application requiredResourceAccess", "PATCH applications/$applicationObjectId")) {
        $updateResponse = Invoke-GraphApiRequest @updateApplicationParams

        if ($updateResponse.Successful -eq $false) {
            Write-Verbose "Failed to update application requiredResourceAccess"
            $allRemovalsSuccessful = $false
        } else {
            Write-Verbose "Successfully updated application requiredResourceAccess"
        }
    }
    #endregion

    return $allRemovalsSuccessful
}
