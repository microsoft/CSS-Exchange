# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AzureApplication.ps1

<#
.SYNOPSIS
    Creates a new client secret for an Azure AD application.

.DESCRIPTION
    This function creates a new client secret (application password) for an existing Azure AD
    application using the Microsoft Graph API. The secret is valid for 7 days from creation.

    The function performs the following operations:
    1. Retrieves the Azure application by name to get its Object ID
    2. Garbage collects any expired secrets by removing them from the application
    3. Creates a new client secret with a 7-day expiration
    4. Waits 60 seconds for Azure AD replication before returning the secret

    IMPORTANT: The secret value is only returned once at creation time and cannot be retrieved
    later. Store the returned secret securely.

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context (AccessToken) for Graph API calls.

.PARAMETER AzureApplicationName
    The display name of the Azure AD application to create the secret for.

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL to use for API requests (e.g., "https://graph.microsoft.com").

.OUTPUTS
    System.String
    The plain-text secret value that can be used for authentication.

    Returns $null if:
    - The application is not found
    - The application query fails
    - Secret creation fails

.EXAMPLE
    $secret = New-AzureApplicationAppSecret -AzAccountsObject $azContext -AzureApplicationName "MyExchangeApp" -GraphApiUrl "https://graph.microsoft.com"

    if ($secret) {
        Write-Host "Secret created successfully. Store this value securely!"
        # Use the secret for authentication
    } else {
        Write-Host "Failed to create secret"
    }

.NOTES
    Required Graph API permissions:
    - Application.ReadWrite.All (to add and remove password credentials)

    The created secret:
    - Has a display name of "AppAccessKey"
    - Expires after 7 days
    - Cannot be retrieved after creation - store it immediately

    This function automatically cleans up expired secrets before creating a new one.

    This function supports -WhatIf and -Confirm through ShouldProcess (for secret deletion).

    API Reference:
    - Add password: https://learn.microsoft.com/graph/api/application-addpassword
    - Remove password: https://learn.microsoft.com/graph/api/application-removepassword
#>
function New-AzureApplicationAppSecret {
    [CmdletBinding(SupportsShouldProcess)]
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
        Write-Verbose "Please re-run the script with -CreateAzureApplication to create the application"
        return
    }

    # Garbage collect expired secrets
    if (($getAzureApplicationResponse.PasswordCredentials).Count -gt 0) {
        Write-Verbose "The Azure application already has application secrets - checking for expired ones..."
        foreach ($password in $getAzureApplicationResponse.PasswordCredentials) {
            $endDateTime = [DateTime]::Parse($password.endDateTime).ToUniversalTime()
            if ($endDateTime -lt (Get-Date).ToUniversalTime()) {
                Write-Verbose "Secret with id: $($password.keyId) has expired since: $endDateTime - deleting it now..."
                $deleteAadApplicationPasswordParams = @{
                    Query              = "applications/$($getAzureApplicationResponse.Id)/removePassword"
                    AccessToken        = $AzAccountsObject.AccessToken
                    Body               = @{ "keyId" = $password.keyId } | ConvertTo-Json
                    Method             = "POST"
                    ExpectedStatusCode = 204
                    GraphApiUrl        = $GraphApiUrl
                }
                if ($PSCmdlet.ShouldProcess("POST applications/$($getAzureApplicationResponse.Id)/removePassword", "Invoke-GraphApiRequest")) {
                    $deleteAadApplicationPasswordResponse = Invoke-GraphApiRequest @deleteAadApplicationPasswordParams

                    if ($deleteAadApplicationPasswordResponse.Successful -eq $false) {
                        Write-Verbose "Unable to delete secret with id: $($password.keyId) - please delete it manually"
                    }
                }
            }
        }
    }

    # Specify secret expiration time which must be in ISO 8601 format and is always in UTC time
    $pwdEndDateTime = ([DateTime]::UtcNow).AddDays(7).ToString("o")
    # Graph API call to create a new application password
    $newAadApplicationPasswordParams = @{
        Query       = "applications/$($getAzureApplicationResponse.Id)/addPassword"
        AccessToken = $AzAccountsObject.AccessToken
        Body        = @{
            "passwordCredential" = @{
                "displayName" = "AppAccessKey"
                "endDateTime" = $pwdEndDateTime
            }
        } | ConvertTo-Json
        Method      = "POST"
        GraphApiUrl = $GraphApiUrl
    }
    $newAadApplicationPasswordResponse = Invoke-GraphApiRequest @newAadApplicationPasswordParams

    if ($newAadApplicationPasswordResponse.Successful -eq $false) {
        Write-Verbose "Unable to create the Azure application password"
        return
    }

    Write-Host "Secret created for Azure application: $AzureApplicationName - waiting 60 seconds for replication..."
    Start-Sleep -Seconds 60

    return $newAadApplicationPasswordResponse.Content.secretText
}
