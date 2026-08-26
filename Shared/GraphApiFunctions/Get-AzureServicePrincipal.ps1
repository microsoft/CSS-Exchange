# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Retrieves service principal information for an Azure AD application.

.DESCRIPTION
    This function queries Microsoft Graph API to find service principals associated with a given application ID.
    A service principal is the local representation of an application in a specific Azure AD tenant, created
    when an application is granted access to resources in the tenant.

    The function returns key information about the service principal including:
    - SpnObjectId: The unique object ID of the service principal (different from the application ID)
    - AppDisplayName: The display name of the associated application
    - KeyCredentials: Certificate credentials configured on the service principal

    By default, the function returns nothing if multiple service principals are found for the same application ID
    (which can occur in multi-tenant scenarios). Set AllowReturnMultipleServicePrincipals to $true to retrieve all matches.

.PARAMETER AzAccountsObject
    An object containing Azure account information, including the AccessToken for authentication.

.PARAMETER AzureApplicationId
    The Application (client) ID of the Azure AD application to look up. This is the AppId, not the object ID.

.PARAMETER GraphApiUrl
    The base URL for Microsoft Graph API calls (e.g., "https://graph.microsoft.com/v1.0").

.PARAMETER AllowReturnMultipleServicePrincipals
    When $false (default), the function returns nothing if multiple service principals are found.
    When $true, returns all matching service principals as a list.

.OUTPUTS
    System.Collections.Generic.List[object] - A list of PSCustomObjects containing SpnObjectId, AppDisplayName, and KeyCredentials.
    Returns $null if no service principal is found or if multiple are found and AllowReturnMultipleServicePrincipals is $false.

.LINK
    https://learn.microsoft.com/graph/api/serviceprincipal-get
    https://learn.microsoft.com/graph/api/serviceprincipal-list
#>
function Get-AzureServicePrincipal {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AzureApplicationId,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        $AllowReturnMultipleServicePrincipals = $false
    )

    Write-Verbose "Searching for Service Principal by using App Id: $AzureApplicationId via Graph Api: $GraphApiUrl"

    $servicePrincipalList = New-Object System.Collections.Generic.List[object]

    $queryServicePrincipalParams = @{
        Query       = "servicePrincipals?`$filter=appId eq '$AzureApplicationId'&`$select=id,appDisplayName,appRoles,keyCredentials"
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $queryServicePrincipalResponse = Invoke-GraphApiRequest @queryServicePrincipalParams

    if ($queryServicePrincipalResponse.Successful -eq $false) {
        Write-Verbose "Something went wrong while querying the service principal"
        return
    }

    if (($queryServicePrincipalResponse.Content.value).Count -gt 1 -and
        $AllowReturnMultipleServicePrincipals -eq $false) {
        Write-Verbose "Multiple Service Principals were returned for this application"
        Write-Verbose "Set 'AllowReturnMultipleServicePrincipals' to true if you want the function to return all of them"
        return
    }

    foreach ($value in $queryServicePrincipalResponse.Content.value) {
        Write-Verbose "Adding Service Principal - Id: $($value.id) DisplayName: $($value.appDisplayName)"

        # Add any additional property which we should return as part of the custom object
        $servicePrincipalList.Add([PSCustomObject]@{
                SpnObjectId    = $value.id
                AppDisplayName = $value.appDisplayName
                AppRoles       = $value.appRoles
                KeyCredentials = $value.keyCredentials
            })
    }

    return $servicePrincipalList
}
