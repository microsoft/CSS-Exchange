# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Adds a user as an owner to an existing Azure AD application.

.DESCRIPTION
    This function adds a specified user as an owner of an Azure AD application using the
    Microsoft Graph API. Application owners have full control over the application registration,
    including the ability to modify its configuration, credentials, and permissions.

    The function performs the following operations:
    1. Queries the existing owners of the Azure application
    2. Checks if the specified user is already an owner
    3. If not already an owner, adds the user as a new owner via Graph API
    4. Returns a result object indicating success and the reason

    The function is idempotent - if the user is already an owner, it returns success
    without making any changes.

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context (AccessToken) for Graph API calls.

.PARAMETER ApplicationId
    The Object ID (not AppId) of the Azure AD application to add the owner to.
    This is the unique identifier of the application object in Azure AD.

.PARAMETER NewOwnerUserId
    The Object ID of the user to add as an owner of the application.
    This must be a valid directory object ID for a user in the tenant.

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL to use for API requests (e.g., "https://graph.microsoft.com").

.OUTPUTS
    PSCustomObject with the following properties:
    - IsOwner: Boolean indicating whether the user is now an owner (true if added or already was an owner)
    - Reason: String indicating the result:
        - "Successful": User was successfully added as an owner
        - "AlreadyAnOwner": User was already an owner, no changes made
        - "UnableToQueryExistingOwners": Failed to query the current owners list
        - "AddFailed": Failed to add the user as an owner

.EXAMPLE
    $result = Add-AzureApplicationOwner -AzAccountsObject $azContext -ApplicationId "12345678-1234-1234-1234-123456789012" -NewOwnerUserId "87654321-4321-4321-4321-210987654321" -GraphApiUrl "https://graph.microsoft.com"

    if ($result.IsOwner) {
        Write-Host "User is now an owner. Reason: $($result.Reason)"
    } else {
        Write-Host "Failed to add owner. Reason: $($result.Reason)"
    }

.NOTES
    Required Graph API permissions:
    - Application.ReadWrite.All (to read and modify application owners)

    API References:
    - Get application owners: https://learn.microsoft.com/graph/api/application-list-owners
    - Add application owner: https://learn.microsoft.com/graph/api/application-post-owners

    This function supports -WhatIf and -Confirm through ShouldProcess.
#>
function Add-AzureApplicationOwner {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $ApplicationId,

        [ValidateNotNullOrEmpty()]
        $NewOwnerUserId,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    begin {
        Write-Verbose "Adding User with Id: $NewOwnerUserId as Owner of the Azure Application: $ApplicationId via Graph Api: $GraphApiUrl"

        $reason = $null

        $getAzureApplicationOwnerParams = @{
            AccessToken = $AzAccountsObject.AccessToken
            GraphApiUrl = $GraphApiUrl
        }
    } process {
        # Graph API call to query the existing owners of the Azure Application as we need to check if the user is already an owner
        if ($PSCmdlet.ShouldProcess("GET applications/$ApplicationId/owners", "Invoke-GraphApiRequest")) {
            $getAzureApplicationOwner = Invoke-GraphApiRequest @getAzureApplicationOwnerParams -Query "applications/$ApplicationId/owners"

            if ($getAzureApplicationOwner.Successful -eq $false) {
                Write-Verbose "Something went wrong while querying the existing Owners of this Azure Application"

                $reason = "UnableToQueryExistingOwners"
                break
            }
        }

        if ($getAzureApplicationOwner.Content.value.Length -eq 0 -or
            (-not($getAzureApplicationOwner.Content.Value.id.Contains($NewOwnerUserId)))) {

            Write-Verbose "User: $NewOwnerUserId is not yet an Owner of this Azure Application and must be added"

            # Graph API call to add the user as a new owner of the Azure Application
            $addNewOwnerToApplicationParams = $getAzureApplicationOwnerParams + @{
                Query              = "applications/$ApplicationId/owners/`$ref"
                Body               = @{ "@odata.id" = "$GraphApiUrl/v1.0/directoryObjects/$NewOwnerUserId" } | ConvertTo-Json
                Method             = "POST"
                ExpectedStatusCode = 204
            }
            if ($PSCmdlet.ShouldProcess("POST $NewOwnerUserId", "Invoke-GraphApiRequest")) {
                $addNewOwnerToApplicationResponse = Invoke-GraphApiRequest @addNewOwnerToApplicationParams

                if ($addNewOwnerToApplicationResponse.Successful -eq $false) {
                    Write-Verbose "Something went wrong while adding the User: $NewOwnerUserId as Owner to this Azure Application"

                    $reason = "AddFailed"
                    break
                }

                $reason = "Successful"
            }
        } else {
            Write-Verbose "User: $NewOwnerUserId is already an Owner of this Azure Application"

            $reason = "AlreadyAnOwner"
        }
    } end {
        return [PSCustomObject]@{
            IsOwner = ($reason -eq "Successful" -or $reason -eq "AlreadyAnOwner")
            Reason  = $reason
        }
    }
}
