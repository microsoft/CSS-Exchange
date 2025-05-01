# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    Creates a new Azure Application with a specified Display Name, SignInAudience and when provided, logo.
    The logo must be a JPEG provided as byte array.
    signInAudience information: https://learn.microsoft.com/graph/api/resources/application#signinaudience-values
    Create application method: https://learn.microsoft.com/graph/api/application-post-applications
    Upload logo: https://learn.microsoft.com/graph/api/application-update?view=graph-rest-1.0&tabs=http#http-request
#>
function New-AzureApplication {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $DisplayName,

        [ValidateSet("AzureADMyOrg", "AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount", "PersonalMicrosoftAccount")]
        $SignInAudience = "AzureADMyOrg",

        $Description = "Added by $($script:MyInvocation.MyCommand.Name)",

        $JpegByteArray,

        $Notes,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Creating a new Azure Application: $DisplayName with Sign-in Audience: $SignInAudience via Graph Api: $GraphApiUrl"

    if ([System.String]::IsNullOrWhiteSpace($Notes)) {
        Write-Verbose "No notes were provided when calling the function - default placeholder will be used"
        $scriptName = $($script:MyInvocation.MyCommand.Name)
        $Notes = "This Enterprise Application was automatically created by the $scriptName script. The script can be downloaded here: https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName"
    }

    $azureApplicationBasicParams = @{
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $newAzureApplicationParams = $azureApplicationBasicParams + @{
        Query              = "applications"
        Body               = @{ "displayName" = $DisplayName; "signInAudience" = $SignInAudience; "description" = $Description; "notes" = $Notes } | ConvertTo-Json
        Method             = "POST"
        ExpectedStatusCode = 201
    }

    if ($PSCmdlet.ShouldProcess("POST $AzureApplicationName", "Invoke-GraphApiRequest")) {
        $newAzureApplicationResponse = Invoke-GraphApiRequest @newAzureApplicationParams

        if ($newAzureApplicationResponse.Successful -eq $false) {
            Write-Verbose "Something went wrong while creating the Azure Application: $AzureApplicationName"
            return
        }

        # We check if the binary data starts with the JPEG signature (FFD8)
        if ($null -ne $JpegByteArray -and
            ($JpegByteArray -eq 0xFF -and
            $JpegByteArray -eq 0xD8)) {
            Write-Verbose "Logo was provided and will be uploaded to the Azure Application"

            try {
                $memoryStream = New-Object System.IO.MemoryStream
                $memoryStream.Write($JpegByteArray, 0, $JpegByteArray.Length)
                $memoryStream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null

                $uploadLogoParams = $azureApplicationBasicParams + @{
                    ContentType        = "image/jpeg"
                    Query              = "applications(appId='{$($newAzureApplicationResponse.Content.appId)}')/logo"
                    Body               = $memoryStream
                    Method             = "PUT"
                    ExpectedStatusCode = "204"
                }

                # Uploading the logo is optional, we continue processing even if this call fails
                if ($PSCmdlet.ShouldProcess("PUT $AzureApplicationName", "Invoke-GraphApiRequest")) {
                    $uploadLogoResponse = Invoke-GraphApiRequest @uploadLogoParams

                    Write-Verbose "Logo upload was successful? $($uploadLogoResponse.Successful)"
                }
            } catch {
                Write-Verbose "Something went wrong while adding the logo to the Azure Application. Inner Exception: $_"
            } finally {
                $memoryStream.Dispose()
            }
        }

        # Add any additional property which we should return as part of the custom object
        return [PSCustomObject]@{
            DisplayName = $newAzureApplicationResponse.Content.displayName
            Id          = $newAzureApplicationResponse.Content.id
            AppId       = $newAzureApplicationResponse.Content.appId
        }
    }

    return
}
