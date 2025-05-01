# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    Gets the Azure Application ID for the Azure Application name which was provided
    https://learn.microsoft.com/graph/api/application-list#request
#>
function Get-AzureApplication {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AzureApplicationName,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Processing Azure Application: $AzureApplicationName via Graph Api: $GraphApiUrl"

    $listAadApplicationParams = @{
        Query       = ("applications?`$filter=displayName eq '$AzureApplicationName'")
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $getAzureApplicationResponse = Invoke-GraphApiRequest @listAadApplicationParams

    if ($getAzureApplicationResponse.Successful -eq $false) {
        Write-Verbose "Something went wrong while the Azure Application was being queried"
        return
    }

    $azureApplicationExists = (-not([System.String]::IsNullOrEmpty($getAzureApplicationResponse.Content.value.appId)))

    Write-Verbose "Application: $AzureApplicationName exists? $azureApplicationExists"

    return [PSCustomObject]@{
        Id                     = $getAzureApplicationResponse.Content.value.id
        AppId                  = $getAzureApplicationResponse.Content.value.appId
        DisplayName            = $getAzureApplicationResponse.Content.value.displayName
        CreatedDateTime        = $getAzureApplicationResponse.Content.value.createdDateTime
        RequiredResourceAccess = $getAzureApplicationResponse.Content.value.requiredResourceAccess
        KeyCredentials         = $getAzureApplicationResponse.Content.value.keyCredentials
        PasswordCredentials    = $getAzureApplicationResponse.Content.value.passwordCredentials
        ApplicationExists      = $azureApplicationExists
    }
}
