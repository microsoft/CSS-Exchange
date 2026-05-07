# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AzureApplicationRole.ps1
. $PSScriptRoot\Get-AzureApplication.ps1
. $PSScriptRoot\Get-AzureServicePrincipal.ps1
. $PSScriptRoot\Get-AzureSignedInUserInformation.ps1
. $PSScriptRoot\Grant-AzureApplicationAdminConsent.ps1
. $PSScriptRoot\..\AzureFunctions\Get-Consent.ps1

<#
.SYNOPSIS
    Updates an Azure AD application with missing API permissions and grants Admin Consent.

.DESCRIPTION
    This function updates an existing Azure AD application by adding any missing API permissions
    and granting Admin Consent for those permissions. It processes the results from
    Test-AzureApplicationPermission to identify which permissions need to be added and which
    require Admin Consent.

    The function performs the following operations:
    1. Retrieves the Azure application by name
    2. Validates the signed-in user has permission to grant Admin Consent
    3. For each permission entry that needs updating:
       - Adds missing API permissions to the application using Add-AzureApplicationRole
       - Grants Admin Consent for permissions that require it using Grant-AzureApplicationAdminConsent
    4. Optionally prompts the user for consent before granting permissions (when AskForConsent is set)

    The function returns a rich result object that provides detailed information about:
    - Overall success or failure status
    - Which permissions were successfully added
    - Which admin consents were granted
    - Which admin consents were skipped (due to user declining or insufficient permissions)
    - Error details including which step failed and a descriptive message

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context for Graph API calls.

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL to use for API requests.

.PARAMETER AzureApplicationName
    The display name of the Azure AD application to update.

.PARAMETER TestAzureApplicationPermissionResult
    An array of PSCustomObject results from Test-AzureApplicationPermission containing:
    Name, ApplicationId, FirstPartyAppId, AllPermissionsFound, MissingApiPermissions,
    AdminConsentGranted, and MissingAdminConsents properties.

.PARAMETER AskForConsent
    When set to $true, prompts the user to confirm before granting Admin Consent for each
    set of missing permissions.

.PARAMETER AllowCreationWithoutConsentPermission
    When set to $true, allows the function to continue adding permissions even if the
    signed-in user does not have permission to grant Admin Consent. The Admin Consent
    granting step will be skipped in this case.

.OUTPUTS
    PSCustomObject with the following properties:
    - Success: Boolean indicating overall success or failure
    - PermissionsAdded: Array of permissions that were successfully added to the application
    - AdminConsentsGranted: Array of admin consents that were successfully granted
    - SkippedAdminConsents: Array of admin consents that were skipped (user declined or insufficient permissions)
    - ErrorStep: String indicating which step failed (e.g., "GetApplication", "AddPermissions", "GrantConsent")
    - ErrorMessage: Descriptive error message if the operation failed

.EXAMPLE
    $result = Update-ExchangeAzureApplication -AzAccountsObject $azContext -GraphApiUrl "https://graph.microsoft.com/v1.0" -AzureApplicationName "MyExchangeApp" -TestAzureApplicationPermissionResult $testResults

    if ($result.Success) {
        Write-Host "Permissions added: $($result.PermissionsAdded.Count)"
        Write-Host "Consents granted: $($result.AdminConsentsGranted.Count)"
    } else {
        Write-Host "Failed at step: $($result.ErrorStep) - $($result.ErrorMessage)"
    }

.NOTES
    This function requires the following dependent functions:
    - Get-AzureApplication
    - Get-AzureSignedInUserInformation
    - Get-AzureServicePrincipal
    - Add-AzureApplicationRole
    - Grant-AzureApplicationAdminConsent
    - Get-Consent
#>
function Update-ExchangeAzureApplication {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Justification = "ShouldProcess is used by the sub-functions which are used in this function")]
    [OutputType([PSCustomObject])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        [ValidateNotNullOrEmpty()]
        $AzureApplicationName,

        # Object(s) returned by Test-AzureApplicationPermission containing:
        # Name, ApplicationId, FirstPartyAppId, AllPermissionsFound, MissingApiPermissions, AdminConsentGranted, MissingAdminConsents
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$TestAzureApplicationPermissionResult,

        $AskForConsent = $false,

        $AllowCreationWithoutConsentPermission = $false
    )

    begin {
        Write-Verbose "Updating application: $AzureApplicationName via Graph Api: $GraphApiUrl"

        # Base parameters which we need to run any of the following Graph API calls
        $graphApiBaseParams = @{
            AzAccountsObject = $AzAccountsObject
            GraphApiUrl      = $GraphApiUrl
        }

        # Initialize tracking lists for the result object
        $permissionsAddedList = New-Object System.Collections.Generic.List[object]
        $adminConsentsGrantedList = New-Object System.Collections.Generic.List[object]
        $skippedAdminConsentsList = New-Object System.Collections.Generic.List[object]

        # Helper function to create the result object
        # Using "Get-" verb since this only constructs and returns an object without modifying state
        function Get-UpdateResult {
            param(
                [bool]$Success,
                [string]$ErrorStep = $null,
                [string]$ErrorMessage = $null
            )
            return [PSCustomObject]@{
                Success              = $Success
                PermissionsAdded     = $permissionsAddedList.ToArray()
                AdminConsentsGranted = $adminConsentsGrantedList.ToArray()
                SkippedAdminConsents = $skippedAdminConsentsList.ToArray()
                ErrorStep            = $ErrorStep
                ErrorMessage         = $ErrorMessage
            }
        }
    } end {
        # PROCESSING FLOW:
        # 1. Validate inputs and retrieve the target Azure application
        # 2. Check if the signed-in user has permission to grant Admin Consent
        # 3. For each API (Graph, EWS, etc.) in TestAzureApplicationPermissionResult:
        #    a. Skip if all permissions are already configured
        #    b. Add any missing API permissions to the application's requiredResourceAccess
        #    c. Grant Admin Consent for permissions that need it (creates appRoleAssignments)

        if ([System.String]::IsNullOrWhiteSpace($AzureApplicationName)) {
            Write-Verbose "Azure Application name not provided"
            return (Get-UpdateResult -Success $false -ErrorStep "Validation" -ErrorMessage "Azure Application name not provided")
        }

        $getAzureApplication = Get-AzureApplication @graphApiBaseParams -AzureApplicationName $AzureApplicationName

        if ($null -eq $getAzureApplication.AppId) {
            Write-Verbose "Unable to find Azure Application: $AzureApplicationName"
            return (Get-UpdateResult -Success $false -ErrorStep "GetApplication" -ErrorMessage "Unable to find Azure Application: $AzureApplicationName")
        }

        # Graph API call to get the current logged in user - we need this information to run the Admin Consent Graph API calls
        $getAzureSignedInUserInformation = Get-AzureSignedInUserInformation @graphApiBaseParams

        if ($null -eq $getAzureSignedInUserInformation) {
            Write-Verbose "Unable to query the signed-in user information"
            return (Get-UpdateResult -Success $false -ErrorStep "GetSignedInUser" -ErrorMessage "Unable to query the signed-in user information")
        }

        # Azure AD has two levels of permission configuration:
        # 1. API Permissions (requiredResourceAccess) - Declares what permissions the app requests
        # 2. Admin Consent (appRoleAssignments) - Actually grants those permissions tenant-wide
        # A user needs sufficient privileges (Global Admin, Privileged Role Admin, etc.) to grant Admin Consent
        $eligibleToGrantAdminConsent = $getAzureSignedInUserInformation.EligibleToGrantAdminConsent

        if ($eligibleToGrantAdminConsent -eq $false -and
            $AllowCreationWithoutConsentPermission -eq $false) {
            Write-Verbose "The account which was used has insufficient permission to grant Admin Consent"
            return (Get-UpdateResult -Success $false -ErrorStep "ValidatePermissions" -ErrorMessage "The signed-in account has insufficient permission to grant Admin Consent. Use -AllowCreationWithoutConsentPermission to skip consent granting.")
        }

        # Each entry in TestAzureApplicationPermissionResult represents a different API:
        # - Name: API identifier (e.g., "Graph", "EWS")
        # - ApplicationId: Object ID of our Azure application
        # - FirstPartyAppId: AppId of the Microsoft API (e.g., Graph API's well-known AppId)
        # - MissingApiPermissions: Permissions not yet in requiredResourceAccess
        # - MissingAdminConsents: Permissions without tenant-wide admin consent
        foreach ($entry in $TestAzureApplicationPermissionResult) {
            Write-Verbose "Processing $($entry.Name) permissions"

            if ($entry.AllPermissionsFound -and
                $entry.AdminConsentGranted) {
                Write-Verbose "All required permissions for $($entry.Name) are already assigned to the Azure Application: $AzureApplicationName"
                continue
            }

            if ($entry.MissingApiPermissions.Count -gt 0) {
                Write-Verbose "Some required permissions for $($entry.Name) are missing - attempting to add them now"

                # MissingApiPermissions already contains { AppRole, PermissionType } entries
                # from Test-AzureApplicationPermission, so we can pass them directly.
                # Note: We use foreach + Add() instead of AddRange() because PowerShell's
                # PSCustomObject[] type causes an "Argument types do not match" exception
                # with List[object].AddRange(IEnumerable).
                $missingPermissionsList = New-Object System.Collections.Generic.List[object]
                foreach ($missingPermission in $entry.MissingApiPermissions) {
                    $missingPermissionsList.Add($missingPermission)
                }

                # Add the missing permissions to the Azure Application
                $addAzureApplicationRoleParams = $graphApiBaseParams + @{
                    ApplicationId  = $entry.ApplicationId
                    ResourceId     = $entry.FirstPartyAppId
                    ApiPermissions = $missingPermissionsList
                }

                $addAzureApplicationRole = Add-AzureApplicationRole @addAzureApplicationRoleParams

                if ($addAzureApplicationRole -eq $false) {
                    Write-Verbose "Unable to add the new permissions to the Azure Application: $AzureApplicationName"
                    return (Get-UpdateResult -Success $false -ErrorStep "AddPermissions" -ErrorMessage "Unable to add $($entry.Name) permissions to the Azure Application: $AzureApplicationName")
                }

                # Track successfully added permissions
                foreach ($addedPermission in $missingPermissionsList) {
                    $permissionsAddedList.Add([PSCustomObject]@{
                            ApiType        = $entry.Name
                            PermissionName = $addedPermission.AppRole.value
                            PermissionType = $addedPermission.PermissionType
                            AppRoleId      = $addedPermission.AppRole.id
                        })
                }
            }

            if ($entry.MissingAdminConsents.Count -gt 0) {
                Write-Verbose "Some required permissions for $($entry.Name) are missing Admin Consent - attempting to grant Admin Consent now"

                if ($eligibleToGrantAdminConsent -eq $false -and
                    $AllowCreationWithoutConsentPermission) {
                    Write-Verbose "User has insufficient permission to grant Admin Consent but AllowCreationWithoutConsentPermission is set - skipping Admin Consent granting"
                    # Track skipped consents due to insufficient permissions
                    foreach ($skippedConsent in $entry.MissingAdminConsents) {
                        $skippedAdminConsentsList.Add([PSCustomObject]@{
                                ApiType        = $entry.Name
                                PermissionName = $skippedConsent.AppRole.value
                                AppRoleId      = $skippedConsent.AppRole.id
                                Reason         = "InsufficientPermissions"
                            })
                    }
                    continue
                }

                # To grant Admin Consent, we need the Object IDs (not AppIds) of both service principals:
                # - firstPartyServicePrincipal: The Microsoft API's service principal (e.g., Microsoft Graph)
                # - dedicatedAppServicePrincipal: Our application's service principal in this tenant
                # Admin Consent creates an appRoleAssignment linking these two service principals

                # Query the first party service principal object as we need its Id to grant Admin Consent
                $firstPartyServicePrincipal = Get-AzureServicePrincipal @graphApiBaseParams -AzureApplicationId $entry.FirstPartyAppId

                # Query the service principal of the Azure Application to get its object Id
                $dedicatedAppServicePrincipal = Get-AzureServicePrincipal @graphApiBaseParams -AzureApplicationId $getAzureApplication.AppId

                if ($null -eq $firstPartyServicePrincipal.SpnObjectId -or
                    $null -eq $dedicatedAppServicePrincipal.SpnObjectId) {
                    Write-Verbose "Unable to find the Service Principal for the first party application $($entry.FirstPartyAppId) or the Azure Application $($getAzureApplication.Id)"
                    return (Get-UpdateResult -Success $false -ErrorStep "GetServicePrincipal" -ErrorMessage "Unable to find the Service Principal for the first party application $($entry.FirstPartyAppId) or the Azure Application $($getAzureApplication.AppId)")
                }

                if ($AskForConsent) {
                    $permissionsString = ""
                    foreach ($permissionEntry in $entry.MissingAdminConsents) {
                        $permissionsString += "`r`n- $($permissionEntry.AppRole.value) ($($permissionEntry.PermissionType))"
                    }

                    $consentGiven = Get-Consent -Message "`r`nDo you want to grant the following $($entry.Name) permission to all accounts in your tenant?$permissionsString`r`n`nThis action will update any existing admin consent records for this application."
                }

                if ($consentGiven -or
                    $AskForConsent -eq $false) {
                    # Now we need to grant Admin Consent for the missing permissions
                    # TODO: This loop grants consent via appRoleAssignments, which is only correct for
                    # Application permissions. To support Delegated permissions, partition MissingAdminConsents
                    # by PermissionType and use a new Grant-AzureApplicationDelegatedConsent function
                    # (POST/PATCH oauth2PermissionGrants) for Delegated entries.
                    foreach ($adminConsent in $entry.MissingAdminConsents) {
                        $grantAdminConsentParams = $graphApiBaseParams + @{
                            DisplayName        = $AzureApplicationName
                            ServicePrincipalId = $dedicatedAppServicePrincipal.SpnObjectId # Service principal of the Azure Application
                            ResourceId         = $firstPartyServicePrincipal.SpnObjectId # Object Id of the first-party service principal (Graph API, EWS, etc.)
                            AppRoleId          = $adminConsent.AppRole.id # App role Id of the permission to grant consent for
                        }

                        $grantAdminConsent = Grant-AzureApplicationAdminConsent @grantAdminConsentParams

                        if ($grantAdminConsent -eq $false) {
                            Write-Verbose "Unable to grant Admin Consent for permission with AppRoleId: $($adminConsent.AppRole.id) on resource with ResourceId: $($firstPartyServicePrincipal.SpnObjectId) to the Azure Application: $AzureApplicationName"
                            return (Get-UpdateResult -Success $false -ErrorStep "GrantConsent" -ErrorMessage "Unable to grant Admin Consent for permission '$($adminConsent.AppRole.value)' (AppRoleId: $($adminConsent.AppRole.id)) to the Azure Application: $AzureApplicationName")
                        }

                        # Track successfully granted consent
                        $adminConsentsGrantedList.Add([PSCustomObject]@{
                                ApiType        = $entry.Name
                                PermissionName = $adminConsent.AppRole.value
                                AppRoleId      = $adminConsent.AppRole.id
                            })
                    }
                } else {
                    Write-Verbose "Ask for consent: $AskForConsent - Consent given: $consentGiven"
                    # Track consents skipped because user declined
                    foreach ($declinedConsent in $entry.MissingAdminConsents) {
                        $skippedAdminConsentsList.Add([PSCustomObject]@{
                                ApiType        = $entry.Name
                                PermissionName = $declinedConsent.AppRole.value
                                AppRoleId      = $declinedConsent.AppRole.id
                                Reason         = "UserDeclined"
                            })
                    }
                }
            }
        }

        # Return success result with all tracked information
        return (Get-UpdateResult -Success $true)
    }
}
