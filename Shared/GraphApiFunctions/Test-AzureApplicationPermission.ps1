# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AzureApplication.ps1
. $PSScriptRoot\Get-AzureAppRoleAssignments.ps1
. $PSScriptRoot\Get-AzureServicePrincipal.ps1

<#
    Validates whether an Azure application has the expected API permissions
    The function also checks if tenant-wide admin consent has been granted
#>
function Test-AzureApplicationPermission {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        $AzureApplicationObject,

        $AzureApplicationName,

        [ValidateNotNullOrEmpty()]
        $ResourceAppId,

        [ValidateNotNullOrEmpty()]
        $ResourceAccessId,

        [ValidateNotNullOrEmpty()]
        $Type
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $graphApiBaseParams = @{
            GraphApiUrl      = $GraphApiUrl
            AzAccountsObject = $AzAccountsObject
        }

        $apiPermissionsSetAsExpected = $false
        $adminConsentGranted = $false
    } process {
        if ([System.String]::IsNullOrWhiteSpace($AzureApplicationName) -and
            $null -eq $AzureApplicationObject) {
            Write-Verbose "No Application name or Azure Application object was provided - validation can't be performed"
            return
        }

        if (-not([System.String]::IsNullOrWhiteSpace($AzureApplicationName))) {
            $AzureApplicationObject = Get-AzureApplication @graphApiBaseParams -AzureApplicationName $azureApplicationName

            if ($null -eq $AzureApplicationObject.AppId) {
                Write-Verbose "We were unable to query the Azure application: $AzureApplicationName - this could be due to the application not existing or a failure in the Graph API call"
                return
            }
        }

        # If the application exists, we're checking if resourceAppId and resourceAccess is configured as expected, otherwise the app needs to be re-created
        $requiredResourceAccessInformation = $AzureApplicationObject.RequiredResourceAccess
        $azureApplicationId = $AzureApplicationObject.AppId

        $apiPermissionsSetAsExpected = (($requiredResourceAccessInformation.resourceAppId -eq $ResourceAppId) -and
            ($requiredResourceAccessInformation.resourceAccess.id -eq $ResourceAccessId -and
            $requiredResourceAccessInformation.resourceAccess.type -eq $Type))

        # We need to validate if admin consent has been granted - to do so, we need to query the service principal assigned to the application first
        $getAzureServicePrincipalInformation = Get-AzureServicePrincipal @graphApiBaseParams -AzureApplicationId $azureApplicationId

        # Next we need to validate the role assignments for that service principal - we must provide the servicePrincipalId here which we got by previous call
        if ($null -ne $getAzureServicePrincipalInformation) {
            $getAzureAppRoleAssignmentsInformation = Get-AzureAppRoleAssignments @graphApiBaseParams -ServicePrincipalId $getAzureServicePrincipalInformation.SpnObjectId

            if ($null -eq $getAzureAppRoleAssignmentsInformation) {
                Write-Verbose "No appRoleAssignments granted to the Service Principal: $($getAzureServicePrincipalInformation.SpnObjectId) were found"

                return
            }

            $adminConsentResult = $getAzureAppRoleAssignmentsInformation | Where-Object {
                $_.PrincipalId -eq $getAzureServicePrincipalInformation.SpnObjectId -and
                $_.AppRoleId -eq $ResourceAccessId
            }

            $adminConsentGranted = $null -ne $adminConsentResult.Id
        } else {
            Write-Verbose "Unable to query Service Principal - validation can't be performed"
        }
    } end {
        Write-Verbose "API Permissions as expected? $apiPermissionsSetAsExpected - Admin Consent granted? $adminConsentGranted"

        return [PSCustomObject]@{
            PermissionsAsExpected = $apiPermissionsSetAsExpected
            AdminConsentGranted   = $adminConsentGranted
        }
    }
}
