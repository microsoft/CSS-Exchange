# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AzureApplication.ps1
. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    This function will delete the specified Azure AD application
    https://docs.microsoft.com/graph/api/application-delete?view=graph-rest-1.0&tabs=http
#>
function Remove-AzureApplication {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AzureApplicationName,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Processing Azure Application: $AzureApplicationName via Graph Api: $GraphApiUrl"

    $getAzureApplicationParams = @{
        AzAccountsObject     = $AzAccountsObject
        AzureApplicationName = $AzureApplicationName
        GraphApiUrl          = $GraphApiUrl
    }
    $getAzureApplicationResponse = Get-AzureApplication @getAzureApplicationParams

    if ($null -eq $getAzureApplicationResponse -or
        [System.String]::IsNullOrEmpty($getAzureApplicationResponse.Id)) {
        Write-Verbose "Something went wrong while querying the Azure Application: $AzureApplicationName"
        Write-Verbose "It could mean that the application doesn't exist or we failed to execute the query"
        return $false
    }

    $deleteAadApplicationParams = @{
        Query              = "applications/$($getAzureApplicationResponse.Id)"
        AccessToken        = $AzAccountsObject.AccessToken
        Method             = "DELETE"
        ExpectedStatusCode = 204
        GraphApiUrl        = $GraphApiUrl
    }
    if ($PSCmdlet.ShouldProcess("DELETE $AzureApplicationName", "Invoke-GraphApiRequest")) {
        $deleteAzureApplicationResponse = Invoke-GraphApiRequest @deleteAadApplicationParams

        if ($deleteAzureApplicationResponse.Successful -eq $false) {
            Write-Verbose "Unable to delete the Azure Application"
            return $false
        }

        Write-Verbose "Deleted the Azure application: $AzureApplicationName successfully"
        return $true
    }

    return $false
}
