# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Convert-JsonWebTokenToObject.ps1
. $PSScriptRoot\Get-NewS256CodeChallengeVerifier.ps1
. $PSScriptRoot\..\Helpers\Start-LocalListener.ps1
. $PSScriptRoot\..\ScriptUpdateFunctions\Invoke-WebRequestWithProxyDetection.ps1

<#
    This function is used to get an access token for the Azure Graph API by using the OAuth 2.0 authorization code flow
    with PKCE (Proof Key for Code Exchange). The OAuth 2.0 authorization code grant type, or auth code flow,
    enables a client application to obtain authorized access to protected resources like web APIs.
    The auth code flow requires a user-agent that supports redirection from the authorization server
    (the Microsoft identity platform) back to your application.

    More information about the auth code flow with PKCE can be found here:
    https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow#protocol-details
#>
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

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"

        <#
            This helper function takes a query string (such as the one returned in an OAuth 2.0 redirect URI)
            and converts it into a PowerShell hashtable for easier access to individual parameters.
            It handles query strings starting with "/?", "?", or "#" and supports multiple values for the same key.
            Special handling is included to avoid logging sensitive values like the full authorization code.

            Example query string: /?code=1.AWEBopV8FWgvEkyBGMjt_4b...&state=54889...&session_state=007cd9
        #>
        function ConvertFrom-QueryString {
            param(
                [string]$Query
            )

            $map = @{}

            if ($Query.StartsWith("/?")) {
                Write-Verbose "Query starts with '/?'"
                $Query = $Query.Substring(2)
            } elseif ($Query.StartsWith("?") -or $Query.StartsWith("#")) {
                Write-Verbose "Query starts with '?' or '#'"
                $Query = $Query.Substring(1)
            }

            # Return an empty hashtable if the query string is null or empty
            if ([System.String]::IsNullOrEmpty($Query)) {
                Write-Verbose "Empty or null string was passed to the function"
                return $map
            }

            # Split the query by "&" to get its elements (code, state, session_state...)
            foreach ($pair in ($Query -split "&")) {
                # Skip guard to skip empty strings
                if (-not $pair) {
                    Write-Verbose "Empty string will be skipped"
                    continue
                }

                # Next, split the string by "=" to separate key and value
                $keyValue = $pair -split "=", 2

                $key = $keyValue[0]
                Write-Verbose "Key '$key' was assigned"

                if ($keyValue.Count -gt 1) {
                    # Extract the value part after "="
                    $value = $keyValue[1]

                    # Make sure to not log the full authorization code
                    if ($key -eq "code") {
                        Write-Verbose "Value '$($value.Substring(0, 8))...' was assigned"
                    } else {
                        Write-Verbose "Value '$value' was assigned"
                    }
                }

                # In case the key already exists, add the new value as array to the existing key
                if ($map.ContainsKey($key)) {
                    Write-Verbose "Key '$key' already exists in the hashtable - adding new value as array"
                    $map[$key] = @($map[$key]) + $value
                } else {
                    $map[$key] = $value
                }
            }

            return $map
        }

        $responseType = "code" # Provides the code as a query string parameter on our redirect URI
        $prompt = "select_account" # We want to show the select account dialog
        $redirectUri = "http://localhost:8004" # This is the default port for the local listener
        $codeChallengeMethod = "S256" # The code challenge method is S256 (SHA256)
        $codeChallengeVerifier = Get-NewS256CodeChallengeVerifier
        $state = ([guid]::NewGuid()).Guid # State which is needed for CSRF protection
        $nonce = ([guid]::NewGuid()).Guid # Nonce to prevent replay attacks
        $connectionSuccessful = $false
    }
    process {
        $codeChallenge = $codeChallengeVerifier.CodeChallenge
        $codeVerifier = $codeChallengeVerifier.Verifier

        # Request an authorization code from the Microsoft Azure Active Directory endpoint
        $authCodeRequestUrl = "$AzureADEndpoint/organizations/oauth2/v2.0/authorize?client_id=$ClientId" +
        "&response_type=$responseType&redirect_uri=$redirectUri&scope=$scope&state=$state&nonce=$nonce&prompt=$prompt" +
        "&code_challenge_method=$codeChallengeMethod&code_challenge=$codeChallenge"

        Start-Process -FilePath $authCodeRequestUrl
        $authCodeResponse = Start-LocalListener -TimeoutSeconds 120

        if ($null -ne $authCodeResponse) {
            # Parse the authCodeResponse to get the state that was returned
            # We need the state to add CSRF and mix-up defense protection
            $queryString = ConvertFrom-QueryString -Query $authCodeResponse

            $returnedState = $queryString["state"]

            if (-not $returnedState) {
                Write-Host "No state value was returned" -ForegroundColor Red

                return
            }

            Write-Verbose "Script state: '$state' - Returned state: '$returnedState'"

            if ($returnedState -cne $state) {
                Write-Host "State mismatch detected! Expected '$state', got '$returnedState'" -ForegroundColor Red

                return
            }

            $code = $queryString["code"]

            if (-not $code) {
                Write-Host "Authorization code is missing in callback" -ForegroundColor Red

                return
            }

            # Redeem the returned code for an access token
            $redeemAuthCodeParams = @{
                Uri             = "$AzureADEndpoint/organizations/oauth2/v2.0/token"
                Method          = "POST"
                ContentType     = "application/x-www-form-urlencoded"
                Body            = @{
                    client_id     = $ClientId
                    scope         = $scope
                    code          = $code
                    redirect_uri  = $redirectUri
                    grant_type    = "authorization_code"
                    code_verifier = $codeVerifier
                }
                UseBasicParsing = $true
            }
            $redeemAuthCodeResponse = Invoke-WebRequestWithProxyDetection -ParametersObject $redeemAuthCodeParams

            if ($redeemAuthCodeResponse.StatusCode -eq 200) {
                $tokens = $redeemAuthCodeResponse.Content | ConvertFrom-Json
                $idTokenPayload = (Convert-JsonWebTokenToObject $tokens.id_token).Payload

                Write-Verbose "Script nonce: '$nonce' - Returned nonce: '$($idTokenPayload.nonce)'"

                if ($idTokenPayload.nonce -cne $nonce) {
                    Write-Host "Nonce mismatch detected" -ForegroundColor Red

                    return
                }

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
            return [PSCustomObject]@{
                AccessToken = $tokens.access_token
                TenantId    = $idTokenPayload.tid
            }
        }

        return $null
    }
}
