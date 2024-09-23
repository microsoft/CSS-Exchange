# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    Assigns permission to an Azure Application

    The resourceAccessObject which is passed in the body of the Graph API call
    It specifies the resources that the application needs to access
    resourceAppId specifies the resources that the application needs to access and also the set of delegated permissions and application roles that it needs for each of those resources
    resourceAccess id is the unique identifier of an app role or delegated permission exposed by the resource application
    resourceAccess type specifies  whether the id property references a delegated permission or an app role (application permission)

    See:
    https://learn.microsoft.com/graph/api/application-update
    https://learn.microsoft.com/graph/api/resources/requiredresourceaccess
    https://learn.microsoft.com/graph/api/resources/resourceaccess
#>
function Add-AzureApplicationRole {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $ApplicationId,

        [ValidateNotNullOrEmpty()]
        $ResourceId,

        [ValidateNotNullOrEmpty()]
        $AppRoleId,

        [ValidateSet("Scope", "Role")]
        $Type = "Role",

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Adding permission to Azure Application: $ApplicationId via Graph Api: $GraphApiUrl"
    Write-Verbose "ResourceId: $ResourceId - AppRoleId: $AppRoleId - Type: $Type"

    $resourceAccessObject = [PSCustomObject]@{
        requiredResourceAccess = @(
            [PSCustomObject]@{
                resourceAppId  = $ResourceId
                resourceAccess = @(
                    [PSCustomObject]@{
                        id   = $AppRoleId
                        type = $Type
                    }
                )
            }
        )
    }

    $updateApplicationParams = @{
        Query              = "applications/$ApplicationId"
        AccessToken        = $AzAccountsObject.AccessToken
        Body               = $resourceAccessObject | ConvertTo-Json -Depth 4
        Method             = "PATCH"
        ExpectedStatusCode = 204
        GraphApiUrl        = $GraphApiUrl
    }

    # Graph API call to add permissions to the Azure Application
    if ($PSCmdlet.ShouldProcess("PATCH $ResourceId", "Invoke-GraphApiRequest")) {
        $updateApplicationResponse = Invoke-GraphApiRequest @updateApplicationParams

        if ($updateApplicationResponse.Successful -eq $false) {
            Write-Verbose "Something went wrong while adding permissions this Azure Application"
            return $false
        }

        return $true
    }

    return $false
}
