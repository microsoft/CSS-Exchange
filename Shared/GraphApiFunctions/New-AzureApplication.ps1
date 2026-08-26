# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Creates a new Azure AD application registration with optional logo.

.DESCRIPTION
    This function creates a new Azure AD application registration using the Microsoft Graph API.
    It configures the application with a display name, sign-in audience, description, and notes.
    Optionally, a PNG logo can be uploaded to the application.

    The function performs the following operations:
    1. Creates the application registration via the Graph API applications endpoint
    2. If a valid PNG byte array is provided, uploads it as the application logo
    3. Returns the created application's identifiers

    The logo upload is optional and non-blocking - if it fails, the function still returns
    the successfully created application details.

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context (AccessToken) for Graph API calls.

.PARAMETER DisplayName
    The display name for the new Azure AD application.

.PARAMETER SignInAudience
    Specifies what Microsoft accounts are supported for the application. Valid values:
    - AzureADMyOrg: Users in this organizational directory only (single tenant) [Default]
    - AzureADMultipleOrgs: Users in any organizational directory (multi-tenant)
    - AzureADandPersonalMicrosoftAccount: Users in any org directory and personal Microsoft accounts
    - PersonalMicrosoftAccount: Personal Microsoft accounts only

.PARAMETER Description
    The description for the application. Defaults to "Added by <script name>".

.PARAMETER PngByteArray
    Optional byte array containing a PNG image to use as the application logo.
    The image must be a valid PNG file (validated by checking the PNG magic number signature).

.PARAMETER Notes
    Optional notes for the application. If not provided, defaults to a message indicating
    the application was created by the script with a link to the CSS-Exchange releases.

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL to use for API requests (e.g., "https://graph.microsoft.com").

.OUTPUTS
    PSCustomObject with the following properties:
    - DisplayName: The display name of the created application
    - Id: The Object ID of the application (unique identifier in Azure AD)
    - AppId: The Application (Client) ID used for authentication

    Returns $null if the application creation fails or is skipped via -WhatIf.

.EXAMPLE
    $app = New-AzureApplication -AzAccountsObject $azContext -DisplayName "MyExchangeApp" -GraphApiUrl "https://graph.microsoft.com"

    Write-Host "Created application with AppId: $($app.AppId)"

.EXAMPLE
    # Create a multi-tenant application with a custom logo
    $logoBytes = [System.IO.File]::ReadAllBytes("C:\logo.png")
    $app = New-AzureApplication -AzAccountsObject $azContext `
        -DisplayName "MyMultiTenantApp" `
        -SignInAudience "AzureADMultipleOrgs" `
        -Description "Custom application for Exchange management" `
        -PngByteArray $logoBytes `
        -GraphApiUrl "https://graph.microsoft.com"

.NOTES
    Required Graph API permissions:
    - Application.ReadWrite.All (to create application registrations)

    This function supports -WhatIf and -Confirm through ShouldProcess.

    API References:
    - Create application: https://learn.microsoft.com/graph/api/application-post-applications
    - Update application logo: https://learn.microsoft.com/graph/api/application-update
    - SignInAudience values: https://learn.microsoft.com/graph/api/resources/application#signinaudience-values
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

        $PngByteArray,

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

        # We check if the binary data starts with the PNG signature (magic number)
        if ($null -ne $PngByteArray -and
            ($PngByteArray.Length -ge 8) -and
            ([System.BitConverter]::ToString(@(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)) -ceq [System.BitConverter]::ToString($PngByteArray[0..7]))) {
            Write-Verbose "Logo was provided and will be uploaded to the Azure Application"

            try {
                $memoryStream = New-Object System.IO.MemoryStream
                $memoryStream.Write($PngByteArray, 0, $PngByteArray.Length)
                $memoryStream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null

                $uploadLogoParams = $azureApplicationBasicParams + @{
                    ContentType        = "image/png"
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
