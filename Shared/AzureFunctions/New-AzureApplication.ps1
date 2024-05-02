. $PSScriptRoot\Invoke-GraphApiRequest.ps1

function New-AzureApplication {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        $AccessToken,
        $AzureApplicationName,
        $GraphApiUrl
    )

    <#
        This function will create an Azure AD Application by calling the Graph API
        https://docs.microsoft.com/graph/api/application-post-applications?view=graph-rest-1.0&tabs=http
    #>

    Write-Verbose "Calling $($MyInvocation.MyCommand)"

    $getAadApplicationParams = @{
        AccessToken          = $AccessToken
        AzureApplicationName = $AzureApplicationName
        GraphApiUrl          = $GraphApiUrl
    }
    $getAadApplicationResponse = Get-AzureApplication @getAadApplicationParams

    if ($null -eq $getAadApplicationResponse) {
        Write-Host "Something went wrong while querying the Azure AD Application" -ForegroundColor Red
        exit
    } elseif (-not([System.String]::IsNullOrEmpty($getAadApplicationResponse.Value.id))) {
        Write-Host "Application with name: $AzureApplicationName already exists..."
        Write-Host "Client ID: $($getAadApplicationResponse.Value.AppId)" -ForegroundColor Green
        exit
    }

    if ($PSCmdlet.ShouldProcess($AzureApplicationName, "Create application")) {
        # Graph API call to create a new Azure AD Application
        $newAzureAdApplicationParams = @{
            Query              = "applications"
            Body               = @{ "displayName" = $AzureApplicationName; "signInAudience" = "AzureADMyOrg" } | ConvertTo-Json
            AccessToken        = $AccessToken
            Method             = "Post"
            ExpectedStatusCode = 201
            GraphApiUrl        = $GraphApiUrl
        }
        $createAzureApplicationResponse = Invoke-GraphApiRequest @newAzureAdApplicationParams

        if ($createAzureApplicationResponse.Successful -eq $false) {
            Write-Host "Something went wrong while creating the Azure AD Application: $AzureApplicationName" -ForegroundColor Red
            exit
        }

        $aadApplication = $createAzureApplicationResponse.Content
    }

    # Graph API call to get the current logged in user
    $loggedInUserParams = @{
        Query       = "me"
        AccessToken = $AccessToken
        GraphApiUrl = $GraphApiUrl
    }
    $loggedInUserResponse = Invoke-GraphApiRequest @loggedInUserParams

    if ($loggedInUserResponse.Successful -eq $false) {
        Write-Host "Unable to query the logged in user. Please try again." -ForegroundColor Red
        exit
    }

    $currentUser = $loggedInUserResponse.Content

    # Graph API call to query the owners of the Azure AD Application
    $listOwnerParams = @{
        Query       = "applications/$($aadApplication.id)/owners"
        AccessToken = $AccessToken
        GraphApiUrl = $GraphApiUrl
    }
    $listOwnerResponse = Invoke-GraphApiRequest @listOwnerParams

    if ($listOwnerResponse.Successful -eq $false) {
        Write-Host "Something went wrong while querying the owners of the Azure application: $AzureApplicationName" -ForegroundColor Red
        exit
    }

    if ($null -ne $listOwnerResponse.Content.value.id -and $listOwnerResponse.Content.value.id.Contains($currentUser.id)) {
        Write-Host "User: $($currentUser.userPrincipalName) is already an owner of application: $AzureApplicationName"
    } else {
        Write-Host "User: $($currentUser.userPrincipalName) is not an owner of application: $AzureApplicationName"

        if ($PSCmdlet.ShouldProcess($AzureApplicationName, "Add $($currentUser.userPrincipalName) as owner")) {
            # Graph API call to add the current user as owner of the Azure AD Application
            $addUserAsOwnerParams = @{
                Query              = "applications/$($aadApplication.id)/owners/`$ref"
                AccessToken        = $AccessToken
                Body               = @{ "@odata.id" = "$GraphApiUrl/v1.0/directoryObjects/$($currentUser.id)" } | ConvertTo-Json
                Method             = "Post"
                ExpectedStatusCode = 204
                GraphApiUrl        = $GraphApiUrl
            }
            $addUserAsOwnerResponse = Invoke-GraphApiRequest @addUserAsOwnerParams

            if ($addUserAsOwnerResponse.Successful -eq $false) {
                Write-Host "Something went wrong while adding the user as owner of the Azure application: $AzureApplicationName" -ForegroundColor Red
                exit
            }
        }
    }

    if ($PSCmdlet.ShouldProcess($AzureApplicationName, "Add required permissions")) {
        # Graph API call to update the Azure AD Application and add the required permissions
        # https://learn.microsoft.com/exchange/client-developer/exchange-web-services/how-to-authenticate-an-ews-application-by-using-oauth#configure-for-delegated-authentication
        # https://learn.microsoft.com/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications
        $updateApplicationParams = @{
            Query              = "applications/$($aadApplication.id)"
            AccessToken        = $AccessToken
            Body               = '{ "requiredResourceAccess": [ { "resourceAppId": "00000002-0000-0ff1-ce00-000000000000", "resourceAccess": [ { "id": "dc890d15-9560-4a4c-9b7f-a736ec74ec40", "type": "Role" } ] } ] }'
            Method             = "Patch"
            ExpectedStatusCode = 204
            GraphApiUrl        = $GraphApiUrl
        }
        $updateApplicationResponse = Invoke-GraphApiRequest @updateApplicationParams

        if ($updateApplicationResponse.Successful -eq $false) {
            Write-Host "Something went wrong while adding the required permission to application: $AzureApplicationName" -ForegroundColor Red
            exit
        }
    }

    if ($PSCmdlet.ShouldProcess($AzureApplicationName, "Create service principal")) {
        # Graph API call to create a new service principal for the Azure AD Application
        $newServicePrincipalParams = @{
            Query              = "servicePrincipals"
            AccessToken        = $AccessToken
            Body               = @{ "appId" = $aadApplication.appId; "accountEnabled" = $true } | ConvertTo-Json
            Method             = "Post"
            ExpectedStatusCode = 201
            GraphApiUrl        = $GraphApiUrl
        }
        $newServicePrincipalResponse = Invoke-GraphApiRequest @newServicePrincipalParams

        if ($newServicePrincipalResponse.Successful -eq $false) {
            Write-Host "Something went wrong while creating the service principal." -ForegroundColor Red
            exit
        }

        $servicePrincipal = $newServicePrincipalResponse.Content

        # Graph API call to update the service principal and add the required tags
        $updateServicePrincipalParams = @{
            Query              = "servicePrincipals/$($servicePrincipal.id)"
            AccessToken        = $AccessToken
            Body               = @{ "tags" = @("WindowsAzureActiveDirectoryIntegratedApp") } | ConvertTo-Json
            Method             = "Patch"
            ExpectedStatusCode = 204
            GraphApiUrl        = $GraphApiUrl
        }
        $updateServicePrincipalResponse = Invoke-GraphApiRequest @updateServicePrincipalParams

        if ($updateServicePrincipalResponse.Successful -eq $false) {
            Write-Host "Something went wrong while updating the service principal." -ForegroundColor Red
            exit
        }

        # Graph API call to query the Office 365 Exchange Online service principal (as we need the object id)
        $o365ExchangeOnlineServicePrincipalParams = @{
            Query       = "servicePrincipals?`$filter=appId eq '00000002-0000-0ff1-ce00-000000000000'"
            AccessToken = $AccessToken
            GraphApiUrl = $GraphApiUrl
        }
        $o365ExchangeOnlineServicePrincipalResponse = Invoke-GraphApiRequest @o365ExchangeOnlineServicePrincipalParams

        if ($o365ExchangeOnlineServicePrincipalResponse.Successful -eq $false) {
            Write-Host "Something went wrong while querying the Office 365 Exchange Online service principal." -ForegroundColor Red
            exit
        }

        $o365ExchangeOnlineObjectId = $o365ExchangeOnlineServicePrincipalResponse.Content.value[0].id
    }

    if ($PSCmdlet.ShouldProcess($AzureApplicationName, "Provide admin consent")) {
        # Graph API call to provide admin consent to the application
        $adminConsentParams = @{
            Query              = "servicePrincipals/$($servicePrincipal.id)/appRoleAssignments"
            AccessToken        = $AccessToken
            Body               = @{ "principalId" = $servicePrincipal.id; "resourceId" = $o365ExchangeOnlineObjectId; "appRoleId" = "dc890d15-9560-4a4c-9b7f-a736ec74ec40" } | ConvertTo-Json
            Method             = "Post"
            ExpectedStatusCode = 201
            GraphApiUrl        = $GraphApiUrl
        }
        $adminConsentResponse = Invoke-GraphApiRequest @adminConsentParams

        if ($adminConsentResponse.Successful -eq $false) {
            Write-Host "Something went wrong while providing admin consent to application: $AzureApplicationName" -ForegroundColor Red
            exit
        }
    }

    Write-Host "Application: $AzureApplicationName created with required permissions. Client ID: $($aadApplication.appId)" -ForegroundColor Green
}
