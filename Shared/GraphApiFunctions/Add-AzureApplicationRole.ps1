# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Assigns API permissions to an Azure AD application.

.DESCRIPTION
    This function adds required resource access permissions to an Azure AD application using the Microsoft Graph API.
    It constructs a requiredResourceAccess object containing:
    - resourceAppId: The identifier of the resource application (e.g., Microsoft Graph) that the app needs access to.
    - resourceAccess: An array of permissions, where each entry includes:
        - id: The unique identifier of an app role or delegated permission exposed by the resource application.
        - type: Either "Role" (application permission) or "Scope" (delegated permission).

    The function supports two modes of operation:
    1. Merge mode (KeepExistingPermissions = $true, default):
       - Retrieves existing permissions from the application
       - Preserves permissions for other resource applications (e.g., EWS when adding Graph permissions)
       - Merges new permissions with existing ones for the same resource application, avoiding duplicates

    2. Overwrite mode (KeepExistingPermissions = $false):
       - Replaces all existing requiredResourceAccess entries with only the new permissions
       - Use with caution as this removes permissions for other resource applications

.PARAMETER AzAccountsObject
    An object containing Azure account information, including the AccessToken for authentication.

.PARAMETER ApplicationId
    The object ID of the Azure AD application to update (not the AppId/ClientId).

.PARAMETER ResourceId
    The AppId of the resource application providing the permissions (e.g., "00000003-0000-0000-c000-000000000000" for Microsoft Graph).

.PARAMETER ApiPermissions
    An array of permission objects, each containing:
    - AppRole: An object with an 'id' property representing the permission GUID
    - PermissionType: Either "Application" (for app-only permissions) or "Delegated" (for user-delegated permissions)

.PARAMETER KeepExistingPermissions
    When $true (default), preserves existing permissions and merges new ones.
    When $false, replaces all permissions with only the specified new permissions.

.PARAMETER GraphApiUrl
    The base URL for Microsoft Graph API calls (e.g., "https://graph.microsoft.com/v1.0").

.OUTPUTS
    System.Boolean - Returns $true if permissions were successfully added, $false otherwise.

.LINK
    https://learn.microsoft.com/graph/api/application-update
    https://learn.microsoft.com/graph/api/resources/requiredresourceaccess
    https://learn.microsoft.com/graph/api/resources/resourceaccess
#>
function Add-AzureApplicationRole {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $ApplicationId,

        [ValidateNotNullOrEmpty()]
        $ResourceId,

        [ValidateNotNullOrEmpty()]
        [System.Object[]]$ApiPermissions,

        $KeepExistingPermissions = $true,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Adding permission to Azure Application: $ApplicationId via Graph Api: $GraphApiUrl"
    Write-Verbose "ResourceId: $ResourceId - Permissions to be added: $($ApiPermissions | ConvertTo-Json -Depth 4)"

    # This list will hold all requiredResourceAccess entries for the final PATCH request
    # Each entry represents permissions for a specific resource application (e.g., Graph, EWS)
    $requiredResourceAccessList = New-Object System.Collections.Generic.List[object]

    # Transform the input ApiPermissions into the resourceAccess format expected by Graph API
    # Each entry maps to: { id: <permission GUID>, type: "Role" or "Scope" }
    # "Role" = Application permission (app-only), "Scope" = Delegated permission (user context)
    $newResourceAccessEntries = foreach ($entry in $ApiPermissions) {
        [PSCustomObject]@{
            id   = $entry.AppRole.id
            type = if ($entry.PermissionType -eq "Application") { "Role" } else { "Scope" }
        }
    }

    if ($KeepExistingPermissions) {
        Write-Verbose "Retrieving existing requiredResourceAccess from the application"
        $getApplicationParams = @{
            Query       = "applications/$ApplicationId" + '?$select=requiredResourceAccess'
            AccessToken = $AzAccountsObject.AccessToken
            GraphApiUrl = $GraphApiUrl
        }

        $getApplicationResponse = Invoke-GraphApiRequest @getApplicationParams

        if ($getApplicationResponse.Successful -eq $false) {
            Write-Verbose "Failed to retrieve existing application permissions"
            return $false
        }

        $existingRequiredResourceAccess = $getApplicationResponse.Content.requiredResourceAccess

        if ($null -ne $existingRequiredResourceAccess) {
            # Iterate through all existing resource access entries
            # We need to preserve permissions for other resources while merging permissions for our target resource
            foreach ($existingResource in $existingRequiredResourceAccess) {
                if ($existingResource.resourceAppId -eq $ResourceId) {
                    # Found the target resource - merge existing permissions with new ones
                    # Start with existing permissions and add new ones that don't already exist
                    $mergedResourceAccess = New-Object System.Collections.Generic.List[object]
                    $mergedResourceAccess.AddRange(@($existingResource.resourceAccess))

                    # Add each new permission only if it doesn't already exist (avoid duplicates)
                    # Comparing by id alone is sufficient because appRoles and oauth2PermissionScopes
                    # use independently assigned GUIDs - the same id never appears as both Role and Scope
                    foreach ($newEntry in $newResourceAccessEntries) {
                        $existingEntry = $mergedResourceAccess | Where-Object { $_.id -eq $newEntry.id }
                        if ($null -eq $existingEntry) {
                            $mergedResourceAccess.Add($newEntry)
                        }
                    }
                    $requiredResourceAccessList.Add([PSCustomObject]@{
                            resourceAppId  = $ResourceId
                            resourceAccess = $mergedResourceAccess.ToArray()
                        })
                } else {
                    # Keep existing resource access for other resourceAppIds
                    $requiredResourceAccessList.Add($existingResource)
                }
            }

            # If ResourceId was not found in existing permissions, add it as new
            $resourceIdExists = $existingRequiredResourceAccess | Where-Object { $_.resourceAppId -eq $ResourceId }
            if ($null -eq $resourceIdExists) {
                $requiredResourceAccessList.Add([PSCustomObject]@{
                        resourceAppId  = $ResourceId
                        resourceAccess = @($newResourceAccessEntries)
                    })
            }
        } else {
            # No existing permissions, add new ones
            $requiredResourceAccessList.Add([PSCustomObject]@{
                    resourceAppId  = $ResourceId
                    resourceAccess = @($newResourceAccessEntries)
                })
        }
    } else {
        # Overwrite mode - only include new permissions
        $requiredResourceAccessList.Add([PSCustomObject]@{
                resourceAppId  = $ResourceId
                resourceAccess = @($newResourceAccessEntries)
            })
    }

    # Use .ToArray() instead of @() to avoid "Argument types do not match" exception
    # when converting System.Collections.Generic.List[object] to an array
    $resourceAccessObject = [PSCustomObject]@{
        requiredResourceAccess = $requiredResourceAccessList.ToArray()
    }

    # Prepare the PATCH request to update the application's requiredResourceAccess property
    # Depth 4 is required for proper JSON serialization of nested resourceAccess arrays
    $updateApplicationParams = @{
        Query              = "applications/$ApplicationId"
        AccessToken        = $AzAccountsObject.AccessToken
        Body               = $resourceAccessObject | ConvertTo-Json -Depth 4
        Method             = "PATCH"
        ExpectedStatusCode = 204
        GraphApiUrl        = $GraphApiUrl
    }

    # Execute the Graph API PATCH request to update the application's permissions
    if ($PSCmdlet.ShouldProcess("PATCH $ResourceId", "Invoke-GraphApiRequest")) {
        $updateApplicationResponse = Invoke-GraphApiRequest @updateApplicationParams

        if ($updateApplicationResponse.Successful -eq $false) {
            Write-Verbose "Something went wrong while adding permissions to this Azure Application"
            return $false
        }

        return $true
    }

    return $false
}
