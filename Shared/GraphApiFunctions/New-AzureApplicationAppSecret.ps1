# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AzureApplication.ps1

<#
    This function creates an App secret for a given application and return it.
    The assigned App Password is valid for 7 days.
    https://learn.microsoft.com/graph/api/application-addpassword?view=graph-rest-1.0&tabs=http#request
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
