# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Convert-JsonWebTokenToObject.ps1

<#
.SYNOPSIS
    Retrieves information about the currently signed-in user and determines admin consent eligibility.

.DESCRIPTION
    This function reads properties of the currently signed-in user and their directory role
    assignments directly from the claims of the provided access token. It also determines whether
    the user has sufficient privileges to grant Admin Consent for Azure AD applications.

    The function performs the following operations:
    1. Decodes the access token to read the signed-in user's object id ('oid' claim)
    2. Reads the user's directory role assignments ('wids' claim)
    3. Checks if the user is a member of roles eligible to grant Admin Consent:
       - Global Administrator (62e90394-69f5-4237-9190-012177145e10)
       - Privileged Role Administrator (9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3)
    4. Returns a result object with user info, role memberships, and consent eligibility

    Reading the information from the token claims avoids the need for the Microsoft Graph
    "User.Read" and "Directory.Read.All" delegated permissions.

    This function is typically used as a prerequisite check before attempting to grant
    Admin Consent on Azure AD applications.

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context (AccessToken) whose claims are read.

.OUTPUTS
    PSCustomObject with the following properties:
    - UserInformation: User object built from the token claims (id, displayName, userPrincipalName)
    - MemberOfInformation: List of directory role template ids the user is assigned to ('wids' claim)
    - EligibleToGrantAdminConsent: Boolean indicating whether the user can grant Admin Consent
      (true if member of Global Administrator or Privileged Role Administrator)

    Returns $null if the access token cannot be decoded.

.EXAMPLE
    $userInfo = Get-AzureSignedInUserInformation -AzAccountsObject $azContext

    if ($userInfo.EligibleToGrantAdminConsent) {
        Write-Host "User $($userInfo.UserInformation.displayName) can grant Admin Consent"
    } else {
        Write-Host "User does not have permission to grant Admin Consent"
    }

.NOTES
    The required information is read from the access token claims, so no Microsoft Graph
    API permissions are required:
    - oid: object id of the signed-in user
    - wids: directory role template ids assigned to the signed-in user

    Note: The "wids" claim only contains directory role assignments (not security group
    memberships). In rare overage scenarios (a very large number of role assignments) the
    claim can be omitted; in that case the user is treated as not eligible to grant Admin
    Consent and the caller can fall back to -AllowCreationWithoutConsentPermission.

    References:
    - Access token claims reference: https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
    - Built-in roles: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
    - Admin consent overview: https://learn.microsoft.com/entra/identity/enterprise-apps/user-admin-consent-overview
#>
function Get-AzureSignedInUserInformation {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject
    )

    Write-Verbose "Getting information for the signed-in user from the access token claims"

    # Groups with permission to grant admin consent
    # Build-in roles: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
    # Admin consent overview: https://learn.microsoft.com/entra/identity/enterprise-apps/user-admin-consent-overview
    $groupsEligibleToGrantAdminConsent = @(
        "62e90394-69f5-4237-9190-012177145e10",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
    )

    $memberOfListObject = New-Object System.Collections.Generic.List[object]

    # Decode the access token to read the signed-in user information from its claims. This avoids the need
    # for the "User.Read" and "Directory.Read.All" Graph permissions
    $tokenObject = Convert-JsonWebTokenToObject -Token $AzAccountsObject.AccessToken

    if ($null -eq $tokenObject) {
        Write-Verbose "Unable to decode the access token - please try again"
        return
    }

    $tokenPayload = $tokenObject.Payload

    # The "oid" claim is the object id of the signed-in user
    if ([System.String]::IsNullOrEmpty($tokenPayload.oid)) {
        Write-Verbose "The access token does not contain an 'oid' claim - unable to determine the signed-in user"
        return
    }

    # The "wids" claim contains the directory role template ids assigned to the signed-in user. It may be
    # absent if the user has no directory roles or in rare overage scenarios.
    if ($null -ne $tokenPayload.wids) {
        foreach ($roleTemplateId in $tokenPayload.wids) {
            Write-Verbose "Adding directory role template id: '$roleTemplateId' to list"
            $memberOfListObject.Add($roleTemplateId)
        }
    } else {
        Write-Verbose "The access token does not contain a 'wids' claim - the user is treated as not eligible to grant Admin Consent"
    }

    $userInformation = [PSCustomObject]@{
        id                = $tokenPayload.oid
        displayName       = $tokenPayload.name
        userPrincipalName = $tokenPayload.upn
    }

    return [PSCustomObject]@{
        UserInformation             = $userInformation
        MemberOfInformation         = $memberOfListObject
        EligibleToGrantAdminConsent = ($groupsEligibleToGrantAdminConsent | Where-Object { $_ -in $memberOfListObject }).Count -ge 1
    }
}
