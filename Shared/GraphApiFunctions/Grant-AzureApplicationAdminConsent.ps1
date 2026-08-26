# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Grants Admin Consent for an app role assignment to a service principal.

.DESCRIPTION
    This function grants Admin Consent by creating an app role assignment between a service
    principal (your application) and a resource service principal (the API, such as Microsoft Graph).
    App role assignments are the mechanism by which application permissions are actually granted
    to an application at the tenant level.

    The function performs the following operations:
    1. Constructs the app role assignment request with principalId, resourceId, and appRoleId
    2. POSTs the assignment to the service principal's appRoleAssignments endpoint
    3. Returns a boolean indicating success or failure

    This function is typically called after adding API permissions to an application's
    requiredResourceAccess. Adding permissions declares what the app requests; granting
    Admin Consent actually authorizes those permissions tenant-wide.

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context (AccessToken) for Graph API calls.

.PARAMETER DisplayName
    The display name of the Azure AD application (used for logging purposes).

.PARAMETER ServicePrincipalId
    The Object ID of the service principal receiving the permission grant.
    This is your application's service principal in the tenant.

.PARAMETER ResourceId
    The Object ID of the resource service principal that provides the API.
    For example, the Microsoft Graph service principal's Object ID.
    Note: This is the Object ID, not the AppId (e.g., not "00000003-0000-0000-c000-000000000000").

.PARAMETER AppRoleId
    The GUID of the specific app role (permission) to grant.
    This ID comes from the appRoles collection of the resource service principal.

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL to use for API requests (e.g., "https://graph.microsoft.com").

.OUTPUTS
    System.Boolean
    - $true: Admin Consent was successfully granted
    - $false: Failed to grant Admin Consent or operation was skipped via -WhatIf

.EXAMPLE
    $result = Grant-AzureApplicationAdminConsent -AzAccountsObject $azContext `
        -DisplayName "MyExchangeApp" `
        -ServicePrincipalId "12345678-1234-1234-1234-123456789012" `
        -ResourceId "87654321-4321-4321-4321-210987654321" `
        -AppRoleId "e1fe6dd8-ba31-4d61-89e7-88639da4683d" `
        -GraphApiUrl "https://graph.microsoft.com"

    if ($result) {
        Write-Host "Admin Consent granted successfully"
    } else {
        Write-Host "Failed to grant Admin Consent"
    }

.NOTES
    Required Graph API permissions:
    - AppRoleAssignment.ReadWrite.All (to create app role assignments)

    The calling user must be a Global Administrator or Privileged Role Administrator
    to grant Admin Consent.

    This function supports -WhatIf and -Confirm through ShouldProcess.

    API Reference:
    - Grant appRoleAssignment: https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments
#>
# TODO: This function only grants Application permissions via appRoleAssignments.
# To support Delegated permissions, a separate function (e.g., Grant-AzureApplicationDelegatedConsent)
# is needed that uses POST /oauth2PermissionGrants with consentType=AllPrincipals and a
# space-delimited scope string. If a grant already exists for the client+resource pair,
# it must be PATCHed to add scopes rather than POSTing a new grant.
function Grant-AzureApplicationAdminConsent {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $DisplayName,

        [ValidateNotNullOrEmpty()]
        $ServicePrincipalId,

        [ValidateNotNullOrEmpty()]
        $ResourceId,

        [ValidateNotNullOrEmpty()]
        $AppRoleId,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Granting Admin Consent to Service Principal: $ServicePrincipalId via Graph Api: $GraphApiUrl"

    $grantAdminConsentParams = @{
        Query              = "servicePrincipals/$ServicePrincipalId/appRoleAssignments"
        AccessToken        = $AzAccountsObject.AccessToken
        Body               = @{ "principalId" = $ServicePrincipalId; "resourceId" = $ResourceId; "appRoleId" = $AppRoleId } | ConvertTo-Json
        Method             = "POST"
        ExpectedStatusCode = 201
        GraphApiUrl        = $GraphApiUrl
    }

    # Graph API call to grant admin consent to an Azure Application
    if ($PSCmdlet.ShouldProcess("POST servicePrincipals/$ServicePrincipalId/appRoleAssignments", "Invoke-GraphApiRequest")) {
        $adminConsentResponse = Invoke-GraphApiRequest @grantAdminConsentParams

        if ($adminConsentResponse.Successful -eq $false) {
            Write-Verbose "Something went wrong while granting Admin Consent"
            return $false
        }

        return $true
    }

    return $false
}
