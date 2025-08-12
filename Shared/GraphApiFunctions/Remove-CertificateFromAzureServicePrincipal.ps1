# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AzureApplication.ps1
. $PSScriptRoot\Get-AzureServicePrincipal.ps1
. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    This function removes a certificate from a Service Principal in Microsoft Entra ID.
    It will also remove any certificate that has expired. This functionality is enabled by default but can be disabled if needed.
    https://learn.microsoft.com/graph/api/serviceprincipal-update
#>
function Remove-CertificateFromAzureServicePrincipal {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        $AzureApplicationName,

        [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
        $WellKnownApplicationId,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[a-fA-F0-9]{40}$")]
        $CertificateThumbprint,

        $RemoveAllCertificates = $false,

        $RemoveExpiredCertificates = $true
    )

    Write-Verbose "Removing keyCredentials from Service Principal of Azure Application: $AzureApplicationName via Graph Api: $GraphApiUrl"

    $keyCredentialsList = New-Object System.Collections.Generic.List[object]

    $graphApiBasicParams = @{
        AzAccountsObject = $AzAccountsObject
        GraphApiUrl      = $GraphApiUrl
    }

    # If the name of an Azure Application was provided, we need to check first if it exists as we need additional information to continue
    if (-not([System.String]::IsNullOrWhiteSpace($AzureApplicationName))) {
        $getAzureApplicationResponse = Get-AzureApplication @graphApiBasicParams -AzureApplicationName $AzureApplicationName

        if ($null -eq $getAzureApplicationResponse -or
            [System.String]::IsNullOrEmpty($getAzureApplicationResponse.Id)) {
            Write-Verbose "It looks like the Azure Application: $AzureApplicationName doesn't exist"
            return $false
        }

        $appId = $getAzureApplicationResponse.AppId
    } elseif (-not([System.String]::IsNullOrWhiteSpace($WellKnownApplicationId))) {
        $appId = $WellKnownApplicationId
    } else {
        Write-Verbose "No Application Name or WellKnown ApplicationId was provided"
        return $false
    }

    Write-Verbose "Searching for Service Principal which is assigned to Azure Application: $appId"

    # Next we need to query the service principal of the application, we need the appId to do so
    $getAzureServicePrincipalResponse = Get-AzureServicePrincipal @graphApiBasicParams -AzureApplicationId $appId

    if ($null -eq $getAzureServicePrincipalResponse -or
        [System.String]::IsNullOrEmpty($getAzureServicePrincipalResponse.SpnObjectId)) {
        Write-Verbose "Something went wrong while querying the Service Principal"
        return $false
    }

    # Check for existing key credentials, retain existing ones which don't match the thumbprint that was passed
    if (($getAzureServicePrincipalResponse.KeyCredentials).Count -ge 1) {
        Write-Verbose "Existing key credentials for this Service Principal have been located"

        if ($RemoveAllCertificates) {
            Write-Verbose "RemoveAllCertificates was set to true - all key credentials will be removed"
        } else {
            foreach ($key in $getAzureServicePrincipalResponse.KeyCredentials) {

                # If the certificate matches the thumbprint, do not retain it
                if ($CertificateThumbprint -eq $key.customKeyIdentifier) {
                    Write-Verbose "Certificate: $CertificateThumbprint was detected and will be removed from the Service Principal"
                    continue
                }

                # If the certificate has expired and RemoveExpiredCertificates is true, do not retain it
                if ($RemoveExpiredCertificates) {
                    [DateTime]$expDate = $key.endDateTime

                    if ($expDate -lt (Get-Date)) {
                        Write-Verbose "Certificate: $CertificateThumbprint has expired and will be removed from the Service Principal"
                        continue
                    }
                }

                Write-Verbose "Certificate: $($key.customKeyIdentifier) will be retained"
                # Make sure to only pass these three values, otherwise the PATCH call will fail
                $keyCredentialsList.Add([PSCustomObject]@{
                        key   = $key.key
                        type  = $key.type
                        usage = $key.usage
                    })
            }
        }
    } else {
        Write-Verbose "No existing key credentials found for this Service Principal"
        return $true
    }

    # If there are keyCredentials that should be retained, provide them, otherwise, pass an empty array to clean up all keyCredentials
    if ($keyCredentialsList.Count -ge 1) {
        $keyCredentialsObject = [PSCustomObject]@{
            keyCredentials = $keyCredentialsList
        }
    } else {
        $keyCredentialsObject = @{
            "keyCredentials" = @()
        }
    }

    # Update the keyCredentials of the Service Principal with all the certificates that should be retained
    $addCertificateToAzureApplicationParams = @{
        Query              = "servicePrincipals/$($getAzureServicePrincipalResponse.SpnObjectId)"
        AccessToken        = $AzAccountsObject.AccessToken
        Body               = $keyCredentialsObject | ConvertTo-Json
        Method             = "PATCH"
        ExpectedStatusCode = 204
        GraphApiUrl        = $GraphApiUrl
    }

    if ($PSCmdlet.ShouldProcess("PATCH applications/$($getAzureServicePrincipalResponse.SpnObjectId)", "Invoke-GraphApiRequest")) {
        $updateServicePrincipalKeyCredentialsResponse = Invoke-GraphApiRequest @addCertificateToAzureApplicationParams

        if ($updateServicePrincipalKeyCredentialsResponse.Successful -eq $false) {
            Write-Verbose "Failed to update the key credentials of Service Principal: $($getAzureServicePrincipalResponse.SpnObjectId)"
            return $false
        }

        Write-Verbose "The key of Service Principal:$($getAzureServicePrincipalResponse.SpnObjectId) have been successfully updated"
        return $true
    }

    return $false
}
