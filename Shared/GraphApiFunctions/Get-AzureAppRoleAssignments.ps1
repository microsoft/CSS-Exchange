# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Retrieves the app role assignments granted to a service principal.

.DESCRIPTION
    This function queries the Microsoft Graph API to retrieve all app role assignments
    that have been granted to a specified service principal. App role assignments represent
    the Admin Consent grants that allow a service principal to access APIs with specific
    permissions.

    The function performs the following operations:
    1. Queries the Graph API for all appRoleAssignments on the specified service principal
    2. Transforms each assignment into a structured PSCustomObject
    3. Returns a list of all assignments with relevant details

    This function is commonly used to verify which API permissions have been granted
    Admin Consent, or to audit the permissions assigned to an application.

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context (AccessToken) for Graph API calls.

.PARAMETER ServicePrincipalId
    The Object ID of the service principal to query for app role assignments.
    This is the service principal's unique identifier in Azure AD (not the AppId).

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL to use for API requests (e.g., "https://graph.microsoft.com").

.OUTPUTS
    System.Collections.Generic.List[object] containing PSCustomObjects with the following properties:
    - Id: Unique identifier of the app role assignment
    - AppRoleId: The ID of the app role (permission) that was assigned
    - PrincipalDisplayName: Display name of the service principal that received the assignment
    - PrincipalId: Object ID of the service principal that received the assignment
    - PrincipalType: Type of principal (typically "ServicePrincipal")
    - ResourceDisplayName: Display name of the resource API (e.g., "Microsoft Graph")
    - ResourceId: Object ID of the resource service principal providing the API

    Returns $null if the query fails.

.EXAMPLE
    $assignments = Get-AzureAppRoleAssignments -AzAccountsObject $azContext -ServicePrincipalId "12345678-1234-1234-1234-123456789012" -GraphApiUrl "https://graph.microsoft.com"

    if ($assignments) {
        Write-Host "Found $($assignments.Count) app role assignments:"
        $assignments | ForEach-Object { Write-Host "- $($_.ResourceDisplayName): $($_.AppRoleId)" }
    }

.NOTES
    Required Graph API permissions:
    - Application.Read.All (to read app role assignments)

    API Reference:
    - List appRoleAssignments: https://learn.microsoft.com/graph/api/serviceprincipal-list-approleassignments
#>
function Get-AzureAppRoleAssignments {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $ServicePrincipalId,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Searching for Service Principal with Id: $ServicePrincipalId via Graph Api: $GraphApiUrl"

    $assignmentsListObject = New-Object System.Collections.Generic.List[object]

    $queryAppRoleAssignmentsParams = @{
        Query       = "servicePrincipals/$ServicePrincipalId/appRoleAssignments"
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $queryAppRoleAssignmentsResponse = Invoke-GraphApiRequest @queryAppRoleAssignmentsParams

    if ($queryAppRoleAssignmentsResponse.Successful -eq $false) {
        Write-Verbose "Something went wrong while querying the appRoleAssignment"
        return
    }

    foreach ($assignment in $queryAppRoleAssignmentsResponse.Content.value) {
        $assignmentsListObject.Add([PSCustomObject]@{
                Id                   = $assignment.id
                AppRoleId            = $assignment.appRoleId
                PrincipalDisplayName = $assignment.principalDisplayName
                PrincipalId          = $assignment.principalId
                PrincipalType        = $assignment.principalType
                ResourceDisplayName  = $assignment.resourceDisplayName
                ResourceId           = $assignment.resourceId
            })
    }

    return $assignmentsListObject
}
