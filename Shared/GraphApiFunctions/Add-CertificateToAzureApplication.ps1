# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AzureApplication.ps1
. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    This function will upload a certificate to an Azure application to enable it for CBA
    https://learn.microsoft.com/graph/api/application-update?view=graph-rest-1.0&tabs=http
#>
function Add-CertificateToAzureApplication {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AzureApplicationName,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        $DisplayName = "Added by $($script:MyInvocation.MyCommand.Name) on $(Get-Date)",

        [ValidateNotNullOrEmpty()]
        $CertificateObject,

        $RemoveExpiredCertificates = $true
    )

    Write-Verbose "Adding keyCredentials to Azure Application: $AzureApplicationName via Graph Api: $GraphApiUrl"

    $keyCredentialsList = New-Object System.Collections.Generic.List[object]
    $certificateIsAlreadyThere = $false

    # Check if Azure application exists - we need these details for the next step
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

    # Check for existing key credentials, retain existing ones and delete (optional) expired ones
    if ($null -ne $getAzureApplicationResponse.KeyCredentials) {
        Write-Verbose "Existing key credentials for this Azure Application have been located"

        foreach ($key in $getAzureApplicationResponse.KeyCredentials) {
            $certificateThumbprint = $key.customKeyIdentifier

            # Check if the certificate that we're processing is already there by comparing thumbprints
            if ($CertificateObject.CertificateThumbprint -eq $certificateThumbprint) {
                $certificateIsAlreadyThere = $true
            }

            if ($RemoveExpiredCertificates) {
                [DateTime]$expDate = $key.endDateTime

                if ($expDate -lt (Get-Date)) {
                    Write-Verbose "Certificate: $certificateThumbprint has expired and will be removed from the Azure Application"
                    continue
                }
            }

            Write-Verbose "Certificate: $certificateThumbprint will be retained"
            $keyCredentialsList.Add($key)
        }
    } else {
        Write-Verbose "No existing key credentials found for this Azure Application"
    }

    # Add the new certificate to the Azure Application - don't add it again if it already exists
    if ($certificateIsAlreadyThere -eq $false ) {
        $keyCredentialsList.Add([PSCustomObject]@{
                displayName = $DisplayName
                keyId       = (New-Guid).Guid
                type        = "AsymmetricX509Cert"
                usage       = "Verify"
                key         = $CertificateObject.CertificateBase64
            })
    }

    if ($keyCredentialsList.Count -ge 1) {
        $keyCredentialsObject = [PSCustomObject]@{
            keyCredentials = $keyCredentialsList
        }

        # Upload the key credentials to the Azure Application
        $addCertificateToAzureApplicationParams = @{
            Query              = "applications/$($getAzureApplicationResponse.Id)"
            AccessToken        = $AzAccountsObject.AccessToken
            Body               = $keyCredentialsObject | ConvertTo-Json
            Method             = "PATCH"
            ExpectedStatusCode = 204
            GraphApiUrl        = $GraphApiUrl
        }
        if ($PSCmdlet.ShouldProcess("PATCH applications/$($getAzureApplicationResponse.Id)", "Invoke-GraphApiRequest")) {
            $addCertificateToAzureApplicationResponse = Invoke-GraphApiRequest @addCertificateToAzureApplicationParams

            if ($addCertificateToAzureApplicationResponse.Successful -eq $false) {
                Write-Verbose "Failed to upload key credentials to this Azure Application"
                return $false
            }
        }
    } else {
        Write-Verbose "There are no valid key credential objects available for upload to this Azure Application"
        return $false
    }

    Write-Verbose "The key credentials for the Azure Application: $AzureApplicationName have been successfully updated"
    return $true
}
