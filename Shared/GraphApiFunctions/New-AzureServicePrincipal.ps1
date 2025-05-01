# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    Create a new servicePrincipal object which is assigned to the specified Azure Application
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
            AppDisplayName = $newServicePrincipalResponse.appDisplayName
        }
    }
}
