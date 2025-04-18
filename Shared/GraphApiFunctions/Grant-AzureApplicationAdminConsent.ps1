# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    Grant an appRoleAssignment to a service principal also known as Admin Consent
    App roles that are assigned to service principals are also known as application permissions
    Application permissions can be granted directly with app role assignments, or through a consent experience
    https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments
#>
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
