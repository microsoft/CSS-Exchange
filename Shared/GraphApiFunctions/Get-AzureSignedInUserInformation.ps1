# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Retrieves information about the currently signed-in user and determines admin consent eligibility.

.DESCRIPTION
    This function queries the Microsoft Graph API to retrieve properties of the currently
    signed-in user and their group/role memberships. It also determines whether the user
    has sufficient privileges to grant Admin Consent for Azure AD applications.

    The function performs the following operations:
    1. Queries the Graph API "me" endpoint to get the signed-in user's properties
    2. Queries the "me/memberOf" endpoint to get all group and role memberships
    3. Checks if the user is a member of roles eligible to grant Admin Consent:
       - Global Administrator (62e90394-69f5-4237-9190-012177145e10)
       - Privileged Role Administrator (9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3)
    4. Returns a result object with user info, memberships, and consent eligibility

    This function is typically used as a prerequisite check before attempting to grant
    Admin Consent on Azure AD applications.

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context (AccessToken) for Graph API calls.

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL to use for API requests (e.g., "https://graph.microsoft.com").

.OUTPUTS
    PSCustomObject with the following properties:
    - UserInformation: The full user object from Graph API (id, displayName, mail, userPrincipalName, etc.)
    - MemberOfInformation: List of groups and directory roles the user is a member of
    - EligibleToGrantAdminConsent: Boolean indicating whether the user can grant Admin Consent
      (true if member of Global Administrator or Privileged Role Administrator)

    Returns $null if either Graph API query fails.

.EXAMPLE
    $userInfo = Get-AzureSignedInUserInformation -AzAccountsObject $azContext -GraphApiUrl "https://graph.microsoft.com"

    if ($userInfo.EligibleToGrantAdminConsent) {
        Write-Host "User $($userInfo.UserInformation.displayName) can grant Admin Consent"
    } else {
        Write-Host "User does not have permission to grant Admin Consent"
    }

.NOTES
    Required Graph API permissions:
    - User.Read (to read signed-in user information)
    - Directory.Read.All (to read group/role memberships)

    API References:
    - Get signed-in user: https://learn.microsoft.com/graph/api/user-get
    - List memberOf: https://learn.microsoft.com/graph/api/user-list-memberof
    - Built-in roles: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
    - Admin consent overview: https://learn.microsoft.com/entra/identity/enterprise-apps/user-admin-consent-overview
#>
function Get-AzureSignedInUserInformation {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Getting information for the signed-in user via Graph Api: $GraphApiUrl"

    # Groups with permission to grant admin consent
    # Build-in roles: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
    # Admin consent overview: https://learn.microsoft.com/entra/identity/enterprise-apps/user-admin-consent-overview
    $groupsEligibleToGrantAdminConsent = @(
        "62e90394-69f5-4237-9190-012177145e10",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
    )

    $memberOfListObject = New-Object System.Collections.Generic.List[object]

    $getAzureSignedInUserBasicParams = @{
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    # Gets the properties and relationship of the signed-in user
    $getAzureSignedInUserResponse = Invoke-GraphApiRequest @getAzureSignedInUserBasicParams -Query "me"

    if ($getAzureSignedInUserResponse.Successful -eq $false) {
        Write-Verbose "Unable to query signed-in user information - please try again"
        return
    }

    # Gets the group membership of the signed-in user
    $getAzureSignedInUserMemberOfResponse = Invoke-GraphApiRequest @getAzureSignedInUserBasicParams -Query "me/memberOf"

    if ($getAzureSignedInUserMemberOfResponse.Successful -eq $false) {
        Write-Verbose "Unable to query signed-in user memberOf information - please try again"
        return
    }

    foreach ($group in $getAzureSignedInUserMemberOfResponse.Content.value) {
        Write-Verbose "Adding group: '$($group.displayName)' to list"
        $memberOfListObject.Add($group)
    }

    return [PSCustomObject]@{
        UserInformation             = $getAzureSignedInUserResponse.Content
        MemberOfInformation         = $memberOfListObject
        EligibleToGrantAdminConsent = ($groupsEligibleToGrantAdminConsent | Where-Object { $_ -in $memberOfListObject.roleTemplateId }).Count -ge 1
    }
}
