# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AzureApiPermission.ps1
. $PSScriptRoot\Get-AzureApplication.ps1
. $PSScriptRoot\Get-AzureAppRoleAssignments.ps1
. $PSScriptRoot\Get-AzureServicePrincipal.ps1

<#
    Validates the configuration and admin consent status of an Azure AD application.

    This function performs a comprehensive validation of an Azure application's API permissions
    by checking whether the configured permissions match the expected permissions for
    Microsoft Graph and/or Exchange Web Services (EWS) APIs. The function accepts an array of
    permission objects, allowing validation of multiple API types in a single call.

    The validation includes:
    - Iterating through each API permission set (Graph or EWS) provided in ApiPermissionsObject
    - Verifying that the application's resourceAppId matches the expected first-party API
    - Confirming each configured permission (Role/Scope) exists and is correctly typed
    - Querying the application's service principal to retrieve app role assignments
    - Verifying tenant-wide admin consent has been granted for each expected permission

    Returns a list of validation objects, one per API type, each containing:
    - Name: The API type (Graph or EWS)
    - AllPermissionsFound: Whether all expected permissions are configured
    - MissingApiPermissions: List of expected permissions that are not configured on the application
    - AdminConsentGranted: Whether admin consent has been granted for all expected permissions
    - MissingAdminConsents: List of expected permissions that are missing admin consent
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
        [object[]]$ApiPermissionsObject
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        # List to hold the validation results for each API type
        $testAzureApplicationReturnList = New-Object System.Collections.Generic.List[System.Object]

        # ID of the first-party Graph API application
        $graphFirstPartyApplicationId = "00000003-0000-0000-c000-000000000000"

        # ID of the first-party EWS application
        $ewsFirstPartyApplicationId = "00000002-0000-0ff1-ce00-000000000000"

        $graphApiBaseParams = @{
            GraphApiUrl      = $GraphApiUrl
            AzAccountsObject = $AzAccountsObject
        }
    } process {
        if ([System.String]::IsNullOrWhiteSpace($AzureApplicationName) -and
            $null -eq $AzureApplicationObject) {
            Write-Verbose "No Application name or Azure Application object was provided - validation can't be performed"
            return
        }

        if (-not([System.String]::IsNullOrWhiteSpace($AzureApplicationName))) {
            $AzureApplicationObject = Get-AzureApplication @graphApiBaseParams -AzureApplicationName $AzureApplicationName

            if ($null -eq $AzureApplicationObject.AppId) {
                Write-Verbose "Unable to query the Azure application: $AzureApplicationName - this could be due to the application not existing or a failure in the Graph API call"
                return
            }
        }

        foreach ($element in $ApiPermissionsObject) {
            Write-Verbose "Validating $($element.ApiType) permissions"

            # Create a list to track the permissions found for the current API type being processed
            $apiPermissionsList = New-Object System.Collections.Generic.List[string]

            # Create a list to track the permissions missing for the current API type being processed
            $missingApiPermissionsList = New-Object System.Collections.Generic.List[System.Object]

            # Create a list to track the admin consent granted for the current API type being processed
            $adminConsentGrantedList = New-Object System.Collections.Generic.List[string]

            # Create a list to track the admin consents missing for the current API type being processed
            $missingAdminConsentsList = New-Object System.Collections.Generic.List[System.Object]

            # Count of expected permissions for the current API type being processed
            $apiPermissionsCount = ($element.Permissions.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum

            # Determine the first-party application id based on the API type being processed
            $firstPartyApplicationId = if ($element.ApiType -eq "Graph") { $graphFirstPartyApplicationId } else { $ewsFirstPartyApplicationId }

            # Create a validation object to track the status of the current API type being processed
            $validationObject = [PSCustomObject]@{
                Name                  = $element.ApiType
                ApplicationId         = $AzureApplicationObject.Id
                FirstPartyAppId       = $firstPartyApplicationId
                AllPermissionsFound   = $false
                MissingApiPermissions = $missingApiPermissionsList
                AdminConsentGranted   = $false
                MissingAdminConsents  = $missingAdminConsentsList
            }

            $getAzureApiPermissionsParams = $graphApiBaseParams + @{
                AppId       = $firstPartyApplicationId # Well-known first party application id
                Permissions = $element.Permissions # Hashtable of permissions to validate
            }

            # Get the API permission information for the specified first party application based on the permissions hashtable
            $apiPermissionsResponse = Get-AzureApiPermission @getAzureApiPermissionsParams

            if ($null -eq $apiPermissionsResponse) {
                Write-Verbose "Failed to retrieve API permissions for first party application with id: $firstPartyApplicationId"
                $testAzureApplicationReturnList.Add($validationObject)
                continue
            }

            # We can't proceed if, for example, invalid (non-existing) permissions were provided or the mapping is incorrect
            # (for example, providing Graph permissions but setting ApiType to EWS)
            if ($apiPermissionsResponse.AllPermissionsFound -eq $false) {
                Write-Verbose "Some of the Api permissions could not be found for the first party application with id: $firstPartyApplicationId"
                $testAzureApplicationReturnList.Add($validationObject)
                continue
            }

            # If the application exists, we're checking if resourceAppId and resourceAccess is configured as expected, otherwise the app needs to be re-created
            $requiredResourceAccessInformation = $AzureApplicationObject.RequiredResourceAccess

            # Filter the API permissions assigned to the service principal by using the first-party application id
            $resourceAccessEntry = $requiredResourceAccessInformation | Where-Object { $_.resourceAppId -eq $firstPartyApplicationId }

            if ($null -ne $resourceAccessEntry) {
                # Iterate through each expected API permission to validate if it exists in the resource access entries
                # Each entry in ApiPermissions contains { AppRole, PermissionType } so we preserve both
                foreach ($apiPermissionEntry in $apiPermissionsResponse.ApiPermissions) {
                    $appRole = $apiPermissionEntry.AppRole
                    $expectedType = if ($apiPermissionEntry.PermissionType -eq "Application") { "Role" } else { "Scope" }
                    Write-Verbose "Validating API Permission - Id: '$($appRole.id)' Name: '$($appRole.value)' PermissionType: '$($apiPermissionEntry.PermissionType)'"

                    $result = $resourceAccessEntry.resourceAccess | Where-Object {
                        $_.id -eq $appRole.id -and $_.type -eq $expectedType
                    }

                    if ($null -ne $result) {
                        Write-Verbose "Found expected API Permission - Id: '$($appRole.id)' Name: '$($appRole.value)'"
                        $apiPermissionsList.Add($appRole.id)
                        continue
                    } else {
                        Write-Verbose "Expected API Permission not found - Id: '$($appRole.id)' Name: '$($appRole.value)'"
                        $missingApiPermissionsList.Add($apiPermissionEntry)
                    }
                }

                # Validate if all expected permissions are set
                $validationObject.AllPermissionsFound = $apiPermissionsList.Count -eq $apiPermissionsCount
                Write-Verbose "All expected permissions found for API type: '$($element.ApiType)'? '$($validationObject.AllPermissionsFound)'"
            } else {
                # No resource access entry found means that no API permissions are configured for this API type
                # However, admin consent (appRoleAssignments) may still exist from a previous configuration,
                # so we must not skip the admin consent check below
                foreach ($apiPermissionEntry in $apiPermissionsResponse.ApiPermissions) {
                    $missingApiPermissionsList.Add($apiPermissionEntry)
                }
                Write-Verbose "No resource access entries found for Resource App Id: '$firstPartyApplicationId'"
            }

            # We need to validate if admin consent has been granted - to do so, we need to query the service principal assigned to the application first
            $getAzureServicePrincipalInformation = Get-AzureServicePrincipal @graphApiBaseParams -AzureApplicationId $AzureApplicationObject.AppId

            # Next we need to validate the role assignments for that service principal - we must provide the servicePrincipalId here which we got by previous call
            # TODO: This block only validates Application permission consent via appRoleAssignments.
            # To support Delegated permissions, also query GET servicePrincipals/{id}/oauth2PermissionGrants
            # (new function: Get-AzureOAuth2PermissionGrants) and check the scope string for each
            # expected Delegated permission.
            if ($null -ne $getAzureServicePrincipalInformation) {
                $getAzureAppRoleAssignmentsInformation = Get-AzureAppRoleAssignments @graphApiBaseParams -ServicePrincipalId $getAzureServicePrincipalInformation.SpnObjectId

                if ($null -eq $getAzureAppRoleAssignmentsInformation) {
                    Write-Verbose "No appRoleAssignments granted to the Service Principal: $($getAzureServicePrincipalInformation.SpnObjectId) were found"
                    continue
                }

                # Filter the app role assignments to find the specific assignment for the resource access id
                $appRoleAssignments = $getAzureAppRoleAssignmentsInformation | Where-Object {
                    $_.PrincipalId -eq $getAzureServicePrincipalInformation.SpnObjectId
                }

                # Iterate through each expected API permission to validate if admin consent has been granted
                foreach ($apiPermissionEntry in $apiPermissionsResponse.ApiPermissions) {
                    $appRole = $apiPermissionEntry.AppRole
                    Write-Verbose "Checking Admin Consent for API Permission - Id: '$($appRole.id)' Name: '$($appRole.value)' PermissionType: '$($apiPermissionEntry.PermissionType)'"
                    $result = $appRoleAssignments | Where-Object {
                        $null -ne $_.Id -and
                        $_.AppRoleId -eq $appRole.id
                    }

                    if ($null -ne $result) {
                        Write-Verbose "Admin Consent granted for expected API Permission - Id: '$($appRole.id)' Name: '$($appRole.value)'"
                        $adminConsentGrantedList.Add($appRole.id)
                    } else {
                        Write-Verbose "Admin Consent NOT granted for expected API Permission - Id: '$($appRole.id)' Name: '$($appRole.value)'"
                        $missingAdminConsentsList.Add($apiPermissionEntry)
                    }
                }

                # Validate if admin consent has been granted for all expected permissions
                $validationObject.AdminConsentGranted = $adminConsentGrantedList.Count -eq $apiPermissionsCount
                Write-Verbose "Admin Consent granted for all expected permissions for API type: '$($element.ApiType)'? '$($validationObject.AdminConsentGranted)'"
            } else {
                Write-Verbose "Unable to query Service Principal - validation can't be performed"
            }

            $testAzureApplicationReturnList.Add($validationObject)
        }
    } end {
        Write-Verbose "Returning validation results for all API types"
        return $testAzureApplicationReturnList
    }
}
