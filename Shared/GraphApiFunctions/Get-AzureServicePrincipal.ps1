# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    Queries the service principal by using an app id and returns information such as the object id
    By default we query the Office 365 Exchange Online service principal
    https://learn.microsoft.com/graph/api/serviceprincipal-get
#>
function Get-AzureServicePrincipal {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        $AzureApplicationId = "00000002-0000-0ff1-ce00-000000000000",

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        $AllowReturnMultipleServicePrincipals = $false
    )

    Write-Verbose "Searching for Service Principal by using App Id: $AzureApplicationId via Graph Api: $GraphApiUrl"

    $servicePrincipalList = New-Object System.Collections.Generic.List[object]

    $queryServicePrincipalParams = @{
        Query       = "servicePrincipals?`$filter=appId eq '$AzureApplicationId'&`$select=id,appDisplayName,keyCredentials"
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
                KeyCredentials = $value.keyCredentials
            })
    }

    return $servicePrincipalList
}
