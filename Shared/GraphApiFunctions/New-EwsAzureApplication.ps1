# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AzureApplicationOwner.ps1
. $PSScriptRoot\Get-AzureApplication.ps1
. $PSScriptRoot\Add-AzureApplicationRole.ps1
. $PSScriptRoot\Grant-AzureApplicationAdminConsent.ps1
. $PSScriptRoot\Get-AzureServicePrincipal.ps1
. $PSScriptRoot\Get-AzureSignedInUserInformation.ps1
. $PSScriptRoot\New-AzureApplication.ps1
. $PSScriptRoot\New-AzureServicePrincipal.ps1
. $PSScriptRoot\..\AzureFunctions\Get-Consent.ps1
. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    This function creates an Azure Application (3P app) with full_access_as_app permission that allows you to run EWS calls against all mailboxes in the organization

    See:
    https://learn.microsoft.com/exchange/client-developer/exchange-web-services/how-to-authenticate-an-ews-application-by-using-oauth#configure-for-delegated-authentication
    https://learn.microsoft.com/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications
#>
function New-EwsAzureApplication {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess is used by the sub-functions which are used in this function')]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AzureApplicationName,

        $JpegByteArray,

        $Notes,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        $AskForConsent = $false,

        $AllowCreationWithoutConsentPermission = $false
    )

    begin {
        Write-Verbose "New application to be created: $AzureApplicationName via Graph Api: $GraphApiUrl"

        # Base parameters which we need to run any of the following Graph API calls
        $azureApplicationBaseParams = @{
            AzAccountsObject = $AzAccountsObject
            GraphApiUrl      = $GraphApiUrl
        }

        # Well-known ids of the Office 365 application and EWS resource
        $o365ExchangeOnlineApplicationId = "00000002-0000-0ff1-ce00-000000000000"
        $o365EwsResource = "dc890d15-9560-4a4c-9b7f-a736ec74ec40"

        $sufficientPermissionToGrantAdminConsent = $false
    } end {
        # Graph API call to check if an Azure Application with the name that was specified, already exists
        $getAzureApplication = Get-AzureApplication @azureApplicationBaseParams -AzureApplicationName $AzureApplicationName

        if ($null -eq $getAzureApplication) {
            Write-Verbose "We were not able to check if an Azure Application with the same name already exists"
            return
        }

        if (-not([System.String]::IsNullOrEmpty($getAzureApplication.Id))) {
            Write-Verbose "Azure Application: $AzureApplicationName with ClientId: $($getAzureApplication.AppId) already exists and can't be created again"
            return
        }

        # Graph API call to get the current logged in user - we need this information to run the following Graph API calls
        $loggedInUserResponse = Get-AzureSignedInUserInformation @azureApplicationBaseParams

        if ($null -eq $loggedInUserResponse) {
            Write-Verbose "We were not able to query the signed-in user information"
            return
        }

        $sufficientPermissionToGrantAdminConsent = $loggedInUserResponse.EligibleToGrantAdminConsent

        if ($sufficientPermissionToGrantAdminConsent -eq $false -and
            $AllowCreationWithoutConsentPermission -eq $false) {
            Write-Verbose "The account which was used has insufficient permission to grant Admin Consent"
            return
        }

        $currentUser = $loggedInUserResponse.UserInformation

        $createNewAzureApplicationParams = $azureApplicationBaseParams + @{
            DisplayName = $AzureApplicationName
            Notes       = $Notes
        }

        if ($null -ne $JpegByteArray) {
            Write-Verbose "Logo as jpeg byte array was provided"
            $createNewAzureApplicationParams.Add("JpegByteArray", $JpegByteArray)
        }

        # Graph API call to create a new Azure Application
        $azureApplication = New-AzureApplication @createNewAzureApplicationParams

        if ($null -eq $azureApplication) {
            Write-Verbose "We were not able to create a new Azure Application named: $AzureApplicationName"
            return
        }

        # Graph API call to add the user as new Azure Application owner
        $azureApplicationOwner = Add-AzureApplicationOwner @azureApplicationBaseParams -ApplicationId $azureApplication.Id -NewOwnerUserId $currentUser.id

        if ($azureApplicationOwner.IsOwner -eq $false) {
            Write-Verbose "We were not able to add the new Owner"
            return
        }

        Write-Verbose "User is an Owner of the Azure Application - Status: $($azureApplicationOwner.Reason)"

        # Graph API call to update the Azure AD Application and add the required permissions
        $azureApplicationRoleParams = $azureApplicationBaseParams + @{
            ApplicationId = $azureApplication.Id
            ResourceId    = $o365ExchangeOnlineApplicationId
            AppRoleId     = $o365EwsResource
        }
        $azureApplicationRole = Add-AzureApplicationRole @azureApplicationRoleParams

        if ($azureApplicationRole -eq $false) {
            Write-Verbose "We were not able to add the new permissions to the Azure Application: $AzureApplicationName"
            return
        }

        # Graph API call to create a new service principal for the Azure Application
        $servicePrincipal = New-AzureServicePrincipal @azureApplicationBaseParams -AppId $azureApplication.AppId -Notes $Notes

        if ($null -eq $servicePrincipal) {
            Write-Verbose "We were not able to create a new Service Principal"
            return
        }

        # Graph API call to query the Office 365 Exchange Online service principal (as we need the object id)
        $querySpnResponse = Get-AzureServicePrincipal @azureApplicationBaseParams -AzureApplicationId $o365ExchangeOnlineApplicationId

        if ($null -eq $querySpnResponse) {
            Write-Verbose "We were not able to query the Office 365 Exchange Online Service Principal"
            return
        }

        if ($sufficientPermissionToGrantAdminConsent -eq $false -and
            $AllowCreationWithoutConsentPermission) {
            Write-Verbose "User has no sufficient permission to grant Admin Consent - skipping Admin Consent call"
        } else {
            if ($AskForConsent) {
                $consentGiven = Get-Consent -Message "Do you want to grant EWS - full_access_as_app permission to all accounts in your tenant?`r`nThis action will update any existing admin consent records for this application."
            }

            if ($consentGiven -or
                $AskForConsent -eq $false) {
                # Graph API call to provide admin consent to the application
                $adminConsent = Grant-AzureApplicationAdminConsent @azureApplicationBaseParams -ServicePrincipalId $servicePrincipal.Id -ResourceId $querySpnResponse.SpnObjectId -AppRoleId $o365EwsResource

                if ($adminConsent -eq $false) {
                    Write-Verbose "We were not able to grant Admin Consent to Azure Application $($azureApplication.AppId)"
                    return
                }
            } else {
                Write-Verbose "Ask for consent: $AskForConsent - Consent given: $consentGiven"
            }
        }

        Write-Verbose "Application: $AzureApplicationName created with required permissions - Client Id: $($azureApplication.AppId)"

        return [PSCustomObject]@{
            ApplicationId          = $azureApplication.Id
            AppId                  = $azureApplication.AppId
            AdminConsent           = if ($null -eq $adminConsent) { $false } else { $adminConsent }
            AdminConsentPermission = $sufficientPermissionToGrantAdminConsent
        }
    }
}
