# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AzureApiPermission.ps1
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
.SYNOPSIS
    Creates a fully configured Azure AD application registration for Exchange Online access.

.DESCRIPTION
    This function performs the complete setup workflow for an Azure AD application that can access
    Exchange Online via either EWS (Exchange Web Services) or Microsoft Graph API.

    The function uses a two-phase approach:
    - Phase 1: Collects all requested API permissions and prompts the user for consent intent
    - Phase 2: Applies the permissions to the application and grants admin consent based on user's intent

    The workflow includes:
    1. Validating that no application with the same name already exists
    2. Verifying the signed-in user has sufficient permissions to grant admin consent
    3. Creating a new Azure AD application registration with optional logo and notes
    4. Adding the current signed-in user as an application owner
    5. Creating an associated service principal for the application
    6. Configuring the required API permissions (application permissions/app roles)
    7. Optionally granting tenant-wide admin consent for the configured permissions

    The function supports first-party Microsoft APIs including:
    - Microsoft Graph API (AppId: 00000003-0000-0000-c000-000000000000)
    - Office 365 Exchange Online / EWS (AppId: 00000002-0000-0ff1-ce00-000000000000)

    Admin consent can be granted interactively (when AskForConsent is $true) or skipped entirely.
    If the signed-in user lacks admin privileges, the AllowCreationWithoutConsentPermission parameter
    allows the application to be created anyway, with consent to be granted later by an admin.

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context. This is typically obtained from
    the Az.Accounts module after connecting to Azure.

.PARAMETER AzureApplicationName
    The display name for the new Azure AD application registration. Must be unique within the tenant.

.PARAMETER PngByteArray
    Optional. A byte array containing a PNG image to use as the application logo.

.PARAMETER Notes
    Optional. Notes or description text to attach to the application and service principal.

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL (e.g., 'https://graph.microsoft.com/v1.0' or
    'https://graph.microsoft.com/beta').

.PARAMETER RequestedApiPermissions
    An array of API permission objects created by New-ApiPermissionObject. Each object specifies
    a first-party API (e.g., Graph, EWS) and the permissions to request.

.PARAMETER AskForConsent
    When $true, prompts the user interactively to confirm admin consent for each API type.
    When $false, admin consent is granted automatically without prompting.
    Default is $false.

.PARAMETER AllowCreationWithoutConsentPermission
    When $true, allows the application to be created even if the signed-in user lacks permission
    to grant admin consent. The application will be created without consent, which must be
    granted later by a user with sufficient privileges. Default is $false.

.OUTPUTS
    PSCustomObject with the following properties:
    - ApplicationId: The object ID of the created Azure AD application
    - AppId: The client/application ID (used for authentication)
    - AdminConsentResults: Array of objects tracking consent status per API type, each containing:
        - ApiType: The API type (e.g., 'Graph', 'EWS')
        - Granted: Boolean indicating if consent was successfully granted
        - Reason: Status reason ('Success', 'Failed', 'UserDeclined', 'InsufficientPermission',
                  'ServicePrincipalNotCreated', 'FirstPartyServicePrincipalNotFound')
    - AdminConsentPermission: Boolean indicating if the signed-in user has permission to grant consent
    - Warnings: Array of warning messages for non-fatal issues during setup
    - Success: Boolean indicating if the entire operation completed without warnings

    Returns $null if the operation fails due to:
    - Unable to query existing applications
    - Application with the same name already exists
    - Unable to get signed-in user information
    - User lacks consent permission and AllowCreationWithoutConsentPermission is $false
    - Unable to create the application

.EXAMPLE
    $permissions = New-ApiPermissionObject -ApiType "Graph" -Permissions "ProfilePhoto.Read.All", "Calendars.ReadBasic.All", "Mail.Read" -PermissionType "Application"
    $result = New-ExchangeAzureApplication -AzAccountsObject $azContext -AzureApplicationName 'MyExchangeApp' -GraphApiUrl 'https://graph.microsoft.com/v1.0' -RequestedApiPermissions $permissions -AskForConsent $true

.LINK
    https://learn.microsoft.com/exchange/client-developer/exchange-web-services/how-to-authenticate-an-ews-application-by-using-oauth

.LINK
    https://learn.microsoft.com/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications
#>
function New-ExchangeAzureApplication {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess is used by the sub-functions which are used in this function')]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AzureApplicationName,

        $PngByteArray,

        $Notes,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        [ValidateNotNullOrEmpty()]
        $RequestedApiPermissions,

        $AskForConsent = $false,

        $AllowCreationWithoutConsentPermission = $false
    )

    end {
        Write-Verbose "New application to be created: $AzureApplicationName via Graph Api: $GraphApiUrl"

        # Base parameters which we need to run any of the following Graph API calls
        $graphApiBaseParams = @{
            AzAccountsObject = $AzAccountsObject
            GraphApiUrl      = $GraphApiUrl
        }

        # This function uses a two-phase approach:
        # Phase 1: Collect all API permissions and gather user consent intent (stored in $permissionsList)
        # Phase 2: Apply the permissions to the application and grant admin consent based on user's intent

        # Collects API permission objects along with user's consent intent for each API type (e.g., Graph, EWS)
        $permissionsList = New-Object System.Collections.Generic.List[object]

        # Tracks the outcome of admin consent grants for each API type (success, failure, or skipped with reason)
        $adminConsentResults = New-Object System.Collections.Generic.List[object]

        # Collects non-fatal warnings that occur during application setup (e.g., failed to add owner)
        $warnings = New-Object System.Collections.Generic.List[string]

        # Variable to track if the signed-in user has sufficient permission to grant Admin Consent
        $sufficientPermissionToGrantAdminConsent = $false

        # Graph API call to check if an Azure Application with the name that was specified, already exists
        $getAzureApplication = Get-AzureApplication @graphApiBaseParams -AzureApplicationName $AzureApplicationName

        # Graph API call to check if an Azure Application already exists has errored
        if ($null -eq $getAzureApplication) {
            Write-Verbose "Unable to query existing Azure Applications"
            return
        }

        # Graph APi call to check if an Azure Application already exists was successful and an application with the specified name was found
        if (-not([System.String]::IsNullOrEmpty($getAzureApplication.Id))) {
            Write-Verbose "Azure Application: $AzureApplicationName with ClientId: $($getAzureApplication.AppId) already exists and can't be created again"
            return
        }

        # Graph API call to get the current logged in user - we need this information to run the following Graph API calls
        $getAzureSignedInUserInformation = Get-AzureSignedInUserInformation @graphApiBaseParams

        if ($null -eq $getAzureSignedInUserInformation) {
            Write-Verbose "Unable to query the signed-in user information"
            return
        }

        $sufficientPermissionToGrantAdminConsent = $getAzureSignedInUserInformation.EligibleToGrantAdminConsent

        if ($sufficientPermissionToGrantAdminConsent -eq $false -and
            -not ($AllowCreationWithoutConsentPermission)) {
            Write-Verbose "The signed-in user has no sufficient permission to grant Admin Consent"
            return
        }

        # Graph API call to create a new Azure Application
        $azureApplication = New-AzureApplication @graphApiBaseParams -DisplayName $AzureApplicationName -Notes $Notes -PngByteArray $PngByteArray

        if ($null -eq $azureApplication) {
            Write-Verbose "Unable to create a new Azure Application named: $AzureApplicationName"
            return
        }

        # Graph API call to add the user as new Azure Application owner
        $addAzureApplicationOwnerParams = $graphApiBaseParams + @{
            ApplicationId  = $azureApplication.Id
            NewOwnerUserId = $getAzureSignedInUserInformation.UserInformation.id
        }

        $azureApplicationOwner = Add-AzureApplicationOwner @addAzureApplicationOwnerParams

        if ($azureApplicationOwner.IsOwner -eq $false) {
            $warnings.Add("Unable to add the signed-in user as Owner of the Azure Application: $AzureApplicationName")
            Write-Verbose $warnings[-1]
        }

        # Graph API call to create a new service principal for the Azure Application
        $newAzureServicePrincipal = New-AzureServicePrincipal @graphApiBaseParams -AppId $azureApplication.AppId -Notes $Notes

        if ($null -eq $newAzureServicePrincipal) {
            $warnings.Add("Unable to create a new Service Principal for the Azure Application: $AzureApplicationName - Admin Consent cannot be granted")
            Write-Verbose $warnings[-1]
        }

        Write-Verbose "User with Id: $($getAzureSignedInUserInformation.UserInformation.id) is now an Owner of the Azure Application: $AzureApplicationName - Status: $($azureApplicationOwner.Reason)"

        # ==================== PHASE 1: Collect permissions and consent intent ====================
        # This phase queries the API permissions for each requested first party application (e.g., Graph, EWS)
        # and prompts the user for consent if AskForConsent is enabled. The results are stored in $permissionsList
        # with AdminConsentGiven indicating whether the user agreed to grant consent (not the actual grant status).
        foreach ($requestedApiPermissionObject in $RequestedApiPermissions) {
            $getAzureApiPermissions = Get-AzureApiPermission @graphApiBaseParams -AppId $requestedApiPermissionObject.FirstPartyAppId -Permissions $requestedApiPermissionObject.Permissions

            if ($getAzureApiPermissions.AllPermissionsFound -eq $false) {
                $warnings.Add("Unable to find all requested API permissions for the first party application with Id: $($requestedApiPermissionObject.FirstPartyAppId)")
                Write-Verbose $warnings[-1]
                continue
            }

            $consentGiven = $false
            if ($sufficientPermissionToGrantAdminConsent) {
                if ($AskForConsent) {
                    # Prompt the user to confirm admin consent
                    $permissionsString = ($requestedApiPermissionObject.Permissions.GetEnumerator() | ForEach-Object { "`r`n- $($_.Key) ($($_.Value -join ', '))" }) -join ''
                    Write-Verbose "Preparing string to ask for Admin Consent for API type: $($requestedApiPermissionObject.ApiType)"
                    $consentGiven = Get-Consent -Message "`r`nDo you want to grant the following $($requestedApiPermissionObject.ApiType) permission to all accounts in your tenant?$permissionsString`r`n`nThis action will update any existing admin consent records for this application."
                } else {
                    # If not prompting for consent, automatically grant consent
                    Write-Verbose "AskForConsent is disabled - automatically granting consent for API type: $($requestedApiPermissionObject.ApiType)"
                    $consentGiven = $true
                }
            }

            $permissionsList.Add([PSCustomObject]@{
                    ApiType               = $requestedApiPermissionObject.ApiType
                    PermissionInformation = $getAzureApiPermissions
                    AdminConsentGiven     = $consentGiven
                })
        }

        # ==================== PHASE 2: Apply permissions and grant admin consent ====================
        # This phase iterates through the collected permissions, adds them to the Azure application,
        # and grants admin consent based on the user's intent captured in Phase 1.
        foreach ($permissionsListObject in $permissionsList) {
            Write-Verbose "Adding $($permissionsListObject.ApiType) permissions to application: $AzureApplicationName"

            $addAzureApplicationRoleParams = $graphApiBaseParams + @{
                ApplicationId  = $azureApplication.Id
                ResourceId     = $permissionsListObject.PermissionInformation.AppId
                ApiPermissions = $permissionsListObject.PermissionInformation.ApiPermissions
            }

            $addAzureApplicationRole = Add-AzureApplicationRole @addAzureApplicationRoleParams

            if ($addAzureApplicationRole -eq $false) {
                $warnings.Add("Unable to add $($permissionsListObject.ApiType) permission to the Azure Application: $AzureApplicationName")
                Write-Verbose $warnings[-1]
                continue
            }

            # Skip admin consent if the service principal wasn't created
            # Reason: Without a service principal, we cannot assign app roles for admin consent
            if ($null -eq $newAzureServicePrincipal) {
                $adminConsentResults.Add([PSCustomObject]@{
                        ApiType = $permissionsListObject.ApiType
                        Granted = $false
                        Reason  = "ServicePrincipalNotCreated"
                    })
                continue
            }

            # Query the first party service principal (e.g., Microsoft Graph) to get its object ID
            # Reason: We need the resource service principal ID to create the app role assignment
            $firstPartyServicePrincipal = Get-AzureServicePrincipal @graphApiBaseParams -AzureApplicationId $permissionsListObject.PermissionInformation.AppId

            if ($null -eq $firstPartyServicePrincipal) {
                # Reason: Cannot grant consent without knowing the target resource's service principal
                $warnings.Add("Unable to query the first party Service Principal for API type: $($permissionsListObject.ApiType)")
                Write-Verbose $warnings[-1]
                $adminConsentResults.Add([PSCustomObject]@{
                        ApiType = $permissionsListObject.ApiType
                        Granted = $false
                        Reason  = "FirstPartyServicePrincipalNotFound"
                    })
                continue
            }

            if ($sufficientPermissionToGrantAdminConsent -eq $false -and
                $AllowCreationWithoutConsentPermission) {
                # Reason: User lacks admin privileges but opted to create the app anyway; consent must be granted later by an admin via Azure Portal or PowerShell
                Write-Verbose "User has no sufficient permission to grant Admin Consent but AllowCreationWithoutConsentPermission is enabled - skipping Admin Consent call"
                $adminConsentResults.Add([PSCustomObject]@{
                        ApiType = $permissionsListObject.ApiType
                        Granted = $false
                        Reason  = "InsufficientPermission"
                    })
            } else {
                # Check if user agreed to grant consent in Phase 1 (AdminConsentGiven tracks intent, not actual grant)
                if ($permissionsListObject.AdminConsentGiven -eq $false) {
                    # Reason: User explicitly chose not to grant admin consent when prompted
                    Write-Verbose "User has declined to grant Admin Consent for API type: $($permissionsListObject.ApiType)"
                    $adminConsentResults.Add([PSCustomObject]@{
                            ApiType = $permissionsListObject.ApiType
                            Granted = $false
                            Reason  = "UserDeclined"
                        })
                    continue
                }

                Write-Verbose "User has granted Admin Consent for API type: $($permissionsListObject.ApiType)"

                # TODO: This loop grants consent for all permissions via appRoleAssignments, which is only
                # correct for Application permissions. To support Delegated permissions, partition
                # ApiPermissions by PermissionType: call Grant-AzureApplicationAdminConsent for Application
                # permissions, and a new Grant-AzureApplicationDelegatedConsent for Delegated permissions
                # (using POST/PATCH oauth2PermissionGrants with combined scope string per resource).
                $consentFailed = $false
                foreach ($apiPermissionEntry in $permissionsListObject.PermissionInformation.ApiPermissions) {
                    $apiPermission = $apiPermissionEntry.AppRole
                    Write-Verbose "Granting Admin Consent for Permission - Id: $($apiPermission.id) DisplayName: $($apiPermission.displayName) PermissionType: $($apiPermissionEntry.PermissionType)"

                    $grantAdminConsentParams = $graphApiBaseParams + @{
                        ServicePrincipalId = $newAzureServicePrincipal.Id
                        ResourceId         = $firstPartyServicePrincipal.SpnObjectId
                        AppRoleId          = $apiPermission.id
                    }

                    $adminConsent = Grant-AzureApplicationAdminConsent @grantAdminConsentParams

                    if ($adminConsent -eq $false) {
                        $warnings.Add("Unable to grant Admin Consent for $($permissionsListObject.ApiType) API permission: $($apiPermission.value) to Azure Application $($azureApplication.AppId)")
                        Write-Verbose $warnings[-1]
                        $consentFailed = $true
                        break
                    }
                }

                $adminConsentResults.Add([PSCustomObject]@{
                        ApiType = $permissionsListObject.ApiType
                        Granted = (-not $consentFailed)
                        Reason  = if ($consentFailed) { "Failed" } else { "Success" }
                    })
            }
        }

        Write-Verbose "Application: $AzureApplicationName created with required permissions - Client Id: $($azureApplication.AppId)"

        return [PSCustomObject]@{
            ApplicationId          = $azureApplication.Id
            AppId                  = $azureApplication.AppId
            AdminConsentResults    = $adminConsentResults.ToArray()
            AdminConsentPermission = $sufficientPermissionToGrantAdminConsent
            Warnings               = $warnings.ToArray()
            Success                = ($warnings.Count -eq 0)
        }
    }
}
