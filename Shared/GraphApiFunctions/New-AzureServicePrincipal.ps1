# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Creates a new service principal for an Azure AD application.

.DESCRIPTION
    This function creates a new service principal object in Azure AD for the specified application using the
    Microsoft Graph API. A service principal is the local representation of an application in an Azure AD tenant
    and is required before an application can access resources in that tenant.

    The function performs two Graph API operations:
    1. POST to create the service principal with the specified AppId, description, notes, and enabled status
    2. PATCH to add required tags for proper categorization:
       - "WindowsAzureActiveDirectoryIntegratedApp": Identifies this as an integrated Azure AD application
       - "HideApp": Hides the application from the standard app list in the Azure portal

    If no Notes parameter is provided, the function automatically generates a note containing the script name
    and a download link to the CSS-Exchange repository where this function is maintained.

.PARAMETER AzAccountsObject
    An object containing Azure account information, including the AccessToken for authentication.

.PARAMETER AppId
    The Application (client) ID of the Azure AD application to create a service principal for.

.PARAMETER Description
    A description for the service principal. Defaults to "Added by <script name>".

.PARAMETER Notes
    Optional notes to attach to the service principal. If not provided, auto-generates a note with the
    script name and a link to download the script from the CSS-Exchange GitHub releases.

.PARAMETER GraphApiUrl
    The base URL for Microsoft Graph API calls (e.g., "https://graph.microsoft.com/v1.0").

.OUTPUTS
    PSCustomObject with the following properties:
    - Id: The object ID of the newly created service principal
    - Enabled: Boolean indicating whether the service principal is enabled
    - AppDisplayName: The display name of the associated application

    Returns $null if the service principal creation or tag update fails.

.LINK
    https://learn.microsoft.com/graph/api/serviceprincipal-post-serviceprincipals
    https://learn.microsoft.com/graph/api/serviceprincipal-update
#>
function New-AzureServicePrincipal {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AppId,

        $Description = "Added by $($script:MyInvocation.MyCommand.Name)",

        $Notes,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Creating a new Service Principal for Azure Application with AppId: $AppId via Graph Api: $GraphApiUrl"

    if ([System.String]::IsNullOrWhiteSpace($Notes)) {
        Write-Verbose "No notes were provided when calling the function - default placeholder will be used"
        $scriptName = $($script:MyInvocation.MyCommand.Name)
        $Notes = "This Service Principal was automatically created by the $scriptName script. The script can be downloaded here: https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName"
    }

    $servicePrincipalBaseParams = @{
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    # Graph API call to create a service principal object
    if ($PSCmdlet.ShouldProcess("POST $AppId", "Invoke-GraphApiRequest")) {

        $newServicePrincipalParams = $servicePrincipalBaseParams + @{
            Query              = "servicePrincipals"
            Body               = @{ "appId" = $AppId; "description" = $Description; "notes" = $Notes; "accountEnabled" = $true } | ConvertTo-Json
            Method             = "POST"
            ExpectedStatusCode = 201
        }

        $newServicePrincipalResponse = Invoke-GraphApiRequest @newServicePrincipalParams

        if ($newServicePrincipalResponse.Successful -eq $false) {
            Write-Verbose "Something went wrong while creating the service principal"
            return
        }

        $updateServicePrincipalParams = $servicePrincipalBaseParams + @{
            Query              = "servicePrincipals/$($newServicePrincipalResponse.Content.id)"
            Body               = @{ "tags" = @("WindowsAzureActiveDirectoryIntegratedApp", "HideApp") } | ConvertTo-Json
            Method             = "PATCH"
            ExpectedStatusCode = 204
        }

        # Graph API call to update the service principal and add the required tags that can be used to categorize and identify the application
        if ($PSCmdlet.ShouldProcess("PATCH WindowsAzureActiveDirectoryIntegratedApp", "Invoke-GraphApiRequest")) {
            $updateServicePrincipalResponse = Invoke-GraphApiRequest @updateServicePrincipalParams

            if ($updateServicePrincipalResponse.Successful -eq $false) {
                Write-Verbose "Something went wrong while adding the required tags to the service principal"
                return
            }
        }

        return [PSCustomObject]@{
            Id             = $newServicePrincipalResponse.Content.id
            Enabled        = $newServicePrincipalResponse.Content.accountEnabled
            AppDisplayName = $newServicePrincipalResponse.Content.appDisplayName
        }
    }
}
