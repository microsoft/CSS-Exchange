# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Retrieves an Azure AD application by its display name or application ID.

.DESCRIPTION
    This function queries Azure AD to find an application registration by its display name
    or application (client) ID using the Microsoft Graph API. It returns detailed information
    about the application including its identifiers, configured permissions, and credentials.

    The function performs the following operations:
    1. Queries the Graph API applications endpoint with a filter on displayName or appId
    2. Checks if an application with the specified identifier exists
    3. Returns a result object with the application's properties or null values if not found

    This function is typically used as a prerequisite step before modifying an application's
    permissions, credentials, or other configuration.

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context (AccessToken) for Graph API calls.

.PARAMETER AzureApplicationName
    The display name of the Azure AD application to retrieve.
    Either AzureApplicationName or AzureApplicationId must be provided.

.PARAMETER AzureApplicationId
    The Application (Client) ID of the Azure AD application to retrieve.
    Either AzureApplicationName or AzureApplicationId must be provided.

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL to use for API requests (e.g., "https://graph.microsoft.com").

.OUTPUTS
    PSCustomObject with the following properties:
    - Id: The Object ID of the application (unique identifier in Azure AD)
    - AppId: The Application (Client) ID used for authentication
    - DisplayName: The display name of the application
    - CreatedDateTime: When the application was created
    - RequiredResourceAccess: Array of API permissions configured on the application
    - KeyCredentials: Certificate credentials configured on the application
    - PasswordCredentials: Client secret credentials configured on the application
    - ApplicationExists: Boolean indicating whether the application was found

.EXAMPLE
    $app = Get-AzureApplication -AzAccountsObject $azContext -AzureApplicationName "MyExchangeApp" -GraphApiUrl "https://graph.microsoft.com"

    Retrieves the application by its display name.

.EXAMPLE
    $app = Get-AzureApplication -AzAccountsObject $azContext -AzureApplicationId "12345678-1234-1234-1234-123456789012" -GraphApiUrl "https://graph.microsoft.com"

    Retrieves the application by its application (client) ID.

.NOTES
    Required Graph API permissions:
    - Application.Read.All (to read application registrations)

    API Reference:
    - List applications: https://learn.microsoft.com/graph/api/application-list
#>
function Get-AzureApplication {
    [CmdletBinding(DefaultParameterSetName = "ByName")]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [Parameter(Mandatory = $true, ParameterSetName = "ByName")]
        [string]$AzureApplicationName,

        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [string]$AzureApplicationId,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    # Build the query filter based on the resolved parameter set
    if ($PSCmdlet.ParameterSetName -eq "ById") {
        Write-Verbose "Processing Azure Application by AppId: $AzureApplicationId via Graph API: $GraphApiUrl"
        $filterQuery = "appId eq '$AzureApplicationId'"
        $applicationIdentifier = $AzureApplicationId
    } else {
        Write-Verbose "Processing Azure Application by Name: $AzureApplicationName via Graph API: $GraphApiUrl"
        $filterQuery = "displayName eq '$AzureApplicationName'"
        $applicationIdentifier = $AzureApplicationName
    }

    $listAadApplicationParams = @{
        Query       = "applications?`$filter=$filterQuery"
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $getAzureApplicationResponse = Invoke-GraphApiRequest @listAadApplicationParams

    if ($getAzureApplicationResponse.Successful -eq $false) {
        Write-Verbose "Something went wrong while the Azure Application was being queried"
        return
    }

    $azureApplicationExists = (-not([System.String]::IsNullOrEmpty($getAzureApplicationResponse.Content.value.appId)))

    Write-Verbose "Application: $applicationIdentifier exists? $azureApplicationExists"

    return [PSCustomObject]@{
        Id                     = $getAzureApplicationResponse.Content.value.id
        AppId                  = $getAzureApplicationResponse.Content.value.appId
        DisplayName            = $getAzureApplicationResponse.Content.value.displayName
        CreatedDateTime        = $getAzureApplicationResponse.Content.value.createdDateTime
        RequiredResourceAccess = @($getAzureApplicationResponse.Content.value.requiredResourceAccess)
        KeyCredentials         = $getAzureApplicationResponse.Content.value.keyCredentials
        PasswordCredentials    = $getAzureApplicationResponse.Content.value.passwordCredentials
        ApplicationExists      = $azureApplicationExists
    }
}
