# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    Retrieve the list of appRoleAssignment that have been granted to a service principal.
    https://learn.microsoft.com/graph/api/serviceprincipal-list-approleassignments
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
