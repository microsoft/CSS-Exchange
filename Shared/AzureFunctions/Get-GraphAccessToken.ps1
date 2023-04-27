# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Convert-JsonWebTokenToObject.ps1
. $PSScriptRoot\Get-NewS256CodeChallengeVerifier.ps1
. $PSScriptRoot\..\Helpers\Start-LocalListener.ps1
. $PSScriptRoot\..\ScriptUpdateFunctions\Invoke-WebRequestWithProxyDetection.ps1

function Get-GraphAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AzureADEndpoint = "https://login.microsoftonline.com",

        [Parameter(Mandatory = $false)]
        [string]$GraphApiUrl = "https://graph.microsoft.com",

        [Parameter(Mandatory = $false)]
        [string]$ClientId = "1950a258-227b-4e31-a9cf-717495945fc2", # Well-known Microsoft Azure PowerShell application ID

        [Parameter(Mandatory = $false)]
        [string]$Scope = "$($GraphApiUrl)//AuditLog.Read.All Directory.AccessAsUser.All email openid profile"
    )

    <#
        This function is used to get an access token for the Azure Graph API by using the OAuth 2.0 authorization code flow
        with PKCE (Proof Key for Code Exchange). The OAuth 2.0 authorization code grant type, or auth code flow,
        enables a client application to obtain authorized access to protected resources like web APIs.
        The auth code flow requires a user-agent that supports redirection from the authorization server
        (the Microsoft identity platform) back to your application.

        More information about the auth code flow with PKCE can be found here:
        https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow#protocol-details
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        $tenantType = if ($AzureADEndpoint -eq "https://login.live.com") { "Consumers" } else { "Enterprise" }
        $responseType = "code" # Provides the code as a query string parameter on our redirect URI
        $prompt = "select_account" # We want to show the select account dialog
        $redirectUri = "http://localhost:8004" # This is the default port for the local listener
        $codeChallengeMethod = "S256" # The code challenge method is S256 (SHA256)
        $codeChallengeVerifier = Get-NewS256CodeChallengeVerifier
        $state = ([guid]::NewGuid()).Guid
        $connectionSuccessful = $false
    }
    process {
        $codeChallenge = $codeChallengeVerifier.CodeChallenge
        $codeVerifier = $codeChallengeVerifier.Verifier

        # Request an authorization code from the Microsoft Azure Active Directory endpoint
        if ($tenantType -eq "Consumers") {
            $authCodeRequestUrl = "$AzureADEndpoint/oauth20_authorize.srf?client_id=$ClientId" +
            "&response_type=$responseType&redirect_uri=$redirectUri&scope=$scope&state=$state&prompt=$prompt" +
            "&code_challenge_method=$codeChallengeMethod&code_challenge=$codeChallenge"
            $tokenEndpoint = "https://login.live.com/oauth20_token.srf"
        } else {
            $authCodeRequestUrl = "$AzureADEndpoint/organizations/oauth2/v2.0/authorize?client_id=$ClientId" +
            "&response_type=$responseType&redirect_uri=$redirectUri&scope=$scope&state=$state&prompt=$prompt" +
            "&code_challenge_method=$codeChallengeMethod&code_challenge=$codeChallenge"
            $tokenEndpoint = "$AzureADEndpoint/organizations/oauth2/v2.0/token"
        }

        Start-Process -FilePath $authCodeRequestUrl
        $authCodeResponse = Start-LocalListener

        if ($null -ne $authCodeResponse) {
            # Redeem the returned code for an access token
            $redeemAuthCodeParams = @{
                Uri             = $tokenEndpoint
                Method          = "POST"
                ContentType     = "application/x-www-form-urlencoded"
                Body            = @{
                    client_id     = $ClientId
                    scope         = $scope
                    code          = ($($authCodeResponse.Split("=")[1]).Split("&")[0])
                    redirect_uri  = $redirectUri
                    grant_type    = "authorization_code"
                    code_verifier = $codeVerifier
                }
                UseBasicParsing = $true
            }
            $redeemAuthCodeResponse = Invoke-WebRequestWithProxyDetection -ParametersObject $redeemAuthCodeParams

            if ($redeemAuthCodeResponse.StatusCode -eq 200) {
                $tokens = $redeemAuthCodeResponse.Content | ConvertFrom-Json
                $connectionSuccessful = $true
            } else {
                Write-Host "Unable to redeem the authorization code for an access token." -ForegroundColor Red
            }
        } else {
            Write-Host "Unable to acquire an authorization code from the Microsoft Azure Active Directory endpoint." -ForegroundColor Red
        }
    }
    end {
        if ($connectionSuccessful) {
            $tenantId = if ($tenantType -eq "Consumers") { "common" } else { (Convert-JsonWebTokenToObject $tokens.id_token).Payload.tid }

            return [PSCustomObject]@{
                AccessToken = $tokens.access_token
                TenantId    = $tenantId
                ClientId    = $ClientId
                RedirectUri = $redirectUri
            }
        }

        exit
    }
}
