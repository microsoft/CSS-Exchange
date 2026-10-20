# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Convert-JsonWebTokenToObject.ps1
. $PSScriptRoot\Get-NewS256CodeChallengeVerifier.ps1
. $PSScriptRoot\..\Helpers\Start-LocalListener.ps1
. $PSScriptRoot\..\ScriptUpdateFunctions\Invoke-WebRequestWithProxyDetection.ps1

<#
    This function is used to get an access token for the Microsoft Graph API. By default, it uses the OAuth 2.0 authorization
    code flow with PKCE (Proof Key for Code Exchange). If a local browser callback can't be completed, it falls back to
    the OAuth 2.0 device code flow so the user can authenticate from another device.

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
        [string]$Scope = "$($GraphApiUrl)//AuditLog.Read.All Directory.AccessAsUser.All email openid profile",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Auto", "AuthorizationCode", "DeviceCode")]
        [string]$AuthFlow = "Auto"
    )

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"

        function ConvertTo-GraphAccessTokenResult {
            param(
                [Parameter(Mandatory = $true)]
                [psobject]$TokenResponse
            )

            $tenantId = $null
            $idToken = if ($null -ne $TokenResponse.PSObject.Properties["id_token"]) {
                $TokenResponse.id_token
            } else {
                $null
            }
            $accessToken = if ($null -ne $TokenResponse.PSObject.Properties["access_token"]) {
                $TokenResponse.access_token
            } else {
                $null
            }

            if (-not [System.String]::IsNullOrEmpty($idToken)) {
                $idTokenPayload = (Convert-JsonWebTokenToObject $idToken).Payload
                $tenantId = $idTokenPayload.tid
            }

            if ([System.String]::IsNullOrEmpty($tenantId) -and
                -not [System.String]::IsNullOrEmpty($accessToken)) {
                $accessTokenPayload = (Convert-JsonWebTokenToObject $accessToken).Payload
                $tenantId = $accessTokenPayload.tid
            }

            return [PSCustomObject]@{
                AccessToken = $accessToken
                TenantId    = $tenantId
            }
        }

        function Invoke-OAuthRestMethod {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Uri,

                [Parameter(Mandatory = $true)]
                [hashtable]$Body
            )

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            $requestParams = @{
                Uri             = $Uri
                Method          = "POST"
                ContentType     = "application/x-www-form-urlencoded"
                Body            = $Body
                UseBasicParsing = $true
                ErrorAction     = "Stop"
            }

            try {
                $proxyUri = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($Uri)
                if ($Uri -ne $proxyUri.OriginalString) {
                    Write-Verbose "Proxy server configuration detected"
                    Write-Verbose $proxyUri.OriginalString
                    $requestParams.Proxy = $proxyUri.OriginalString
                    $requestParams.ProxyUseDefaultCredentials = $true
                }
            } catch {
                Write-Verbose "Unable to check for proxy server configuration"
            }

            try {
                return [PSCustomObject]@{
                    StatusCode = 200
                    Content    = (Invoke-RestMethod @requestParams)
                }
            } catch {
                $statusCode = $null
                $content = $null
                $rawContent = $null

                if (-not [System.String]::IsNullOrEmpty($_.ErrorDetails.Message)) {
                    $rawContent = $_.ErrorDetails.Message
                }

                if ($null -ne $_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode

                    if ([System.String]::IsNullOrEmpty($rawContent) -and
                        $_.Exception.Response -is [System.Net.Http.HttpResponseMessage]) {
                        $rawContent = $_.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    } elseif ([System.String]::IsNullOrEmpty($rawContent)) {
                        $stream = $_.Exception.Response.GetResponseStream()

                        if ($null -ne $stream) {
                            $reader = New-Object System.IO.StreamReader($stream)

                            try {
                                $rawContent = $reader.ReadToEnd()
                            } finally {
                                $reader.Dispose()
                                $stream.Dispose()
                            }
                        }
                    }
                }

                if (-not [System.String]::IsNullOrEmpty($rawContent)) {
                    try {
                        $content = $rawContent | ConvertFrom-Json
                    } catch {
                        $content = $rawContent
                    }
                }

                return [PSCustomObject]@{
                    StatusCode = $statusCode
                    Content    = $content
                }
            }
        }

        function Get-OAuthErrorMessage {
            param(
                [Parameter(Mandatory = $true)]
                [string]$DefaultMessage,

                [Parameter(Mandatory = $false)]
                [object]$ErrorContent,

                [Parameter(Mandatory = $false)]
                [Nullable[int]]$StatusCode
            )

            $errorMessageParts = New-Object System.Collections.Generic.List[string]
            $errorMessageParts.Add($DefaultMessage) | Out-Null

            if ($null -ne $StatusCode) {
                $errorMessageParts.Add("Status code: $StatusCode") | Out-Null
            }

            if ($ErrorContent -is [string]) {
                if (-not [System.String]::IsNullOrEmpty($ErrorContent)) {
                    $errorMessageParts.Add($ErrorContent) | Out-Null
                }
            } elseif ($null -ne $ErrorContent) {
                $oauthError = $ErrorContent.error
                $oauthErrorDescription = $ErrorContent.error_description

                if (-not [System.String]::IsNullOrEmpty($oauthError)) {
                    $errorMessageParts.Add("Error: $oauthError") | Out-Null
                }

                if (-not [System.String]::IsNullOrEmpty($oauthErrorDescription)) {
                    $errorMessageParts.Add("Error description: $oauthErrorDescription") | Out-Null
                }
            }

            return $errorMessageParts -join " "
        }

        function Test-AuthorizationCodeFlowAvailable {
            if ($null -ne (Get-Variable -Name PSSenderInfo -ErrorAction SilentlyContinue)) {
                Write-Verbose "Remote PowerShell session detected. Device code authentication will be used."
                return $false
            }

            if ($Host.Name -eq "ServerRemoteHost") {
                Write-Verbose "Remote PowerShell host detected. Device code authentication will be used."
                return $false
            }

            if (-not [System.Environment]::UserInteractive) {
                Write-Verbose "Non-interactive PowerShell session detected. Device code authentication will be used."
                return $false
            }

            try {
                $currentVersionPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                $installationType = (Get-ItemProperty -Path $currentVersionPath -Name InstallationType -ErrorAction Stop).InstallationType
                if ($installationType -eq "Server Core") {
                    Write-Verbose "Server Core installation detected. Device code authentication will be used."
                    return $false
                }
            } catch {
                Write-Verbose "Unable to determine Windows installation type."
            }

            return $true
        }

        function ConvertTo-OAuthQueryString {
            param(
                [Parameter(Mandatory = $true)]
                [System.Collections.IDictionary]$Parameters
            )

            $queryParameters = New-Object System.Collections.Generic.List[string]

            foreach ($parameter in $Parameters.GetEnumerator()) {
                $queryParameters.Add(("{0}={1}" -f
                        [System.Uri]::EscapeDataString([string]$parameter.Key),
                        [System.Uri]::EscapeDataString([string]$parameter.Value))) | Out-Null
            }

            return $queryParameters -join "&"
        }

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

        function Invoke-DeviceCodeFlow {
            param(
                [Parameter(Mandatory = $true)]
                [string]$AzureADEndpoint,

                [Parameter(Mandatory = $true)]
                [string]$ClientId,

                [Parameter(Mandatory = $true)]
                [string]$Scope
            )

            $deviceCodeResponse = Invoke-OAuthRestMethod -Uri "$AzureADEndpoint/organizations/oauth2/v2.0/devicecode" -Body @{
                client_id = $ClientId
                scope     = $Scope
            }

            if ($deviceCodeResponse.StatusCode -ne 200 -or $null -eq $deviceCodeResponse.Content) {
                Write-Host (Get-OAuthErrorMessage `
                        -DefaultMessage "Unable to initiate device code authentication." `
                        -ErrorContent $deviceCodeResponse.Content `
                        -StatusCode $deviceCodeResponse.StatusCode) -ForegroundColor Red
                return $null
            }

            $deviceCodeInfo = $deviceCodeResponse.Content
            $verificationUri = if (-not [System.String]::IsNullOrEmpty($deviceCodeInfo.verification_uri)) {
                $deviceCodeInfo.verification_uri
            } else {
                $deviceCodeInfo.verification_url
            }

            if (-not [System.String]::IsNullOrEmpty($deviceCodeInfo.message)) {
                Write-Host $deviceCodeInfo.message -ForegroundColor Yellow
            } else {
                Write-Host ("To sign in, use a browser on any device to open '{0}' and enter code '{1}'." -f $verificationUri, $deviceCodeInfo.user_code) -ForegroundColor Yellow
            }

            $tokens = $null
            $pollingInterval = if ($deviceCodeInfo.interval) { [int]$deviceCodeInfo.interval } else { 5 }
            $pollDeadline = (Get-Date).AddSeconds([int]$deviceCodeInfo.expires_in)

            while ((Get-Date) -lt $pollDeadline) {
                Start-Sleep -Seconds $pollingInterval

                $pollResponse = Invoke-OAuthRestMethod -Uri "$AzureADEndpoint/organizations/oauth2/v2.0/token" -Body @{
                    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                    client_id   = $ClientId
                    device_code = $deviceCodeInfo.device_code
                }

                if ($pollResponse.StatusCode -eq 200 -and $null -ne $pollResponse.Content) {
                    $tokens = $pollResponse.Content
                    break
                }

                $oauthError = $pollResponse.Content.error

                if ($oauthError -eq "authorization_pending") {
                    continue
                }

                if ($oauthError -eq "slow_down") {
                    $pollingInterval += 5
                    continue
                }

                if ($oauthError -eq "expired_token") {
                    Write-Host "Device code authentication expired before sign-in completed." -ForegroundColor Red
                    return $null
                }

                if ($oauthError -eq "authorization_declined") {
                    Write-Host "Device code authentication was declined." -ForegroundColor Red
                    return $null
                }

                $errorDescription = $pollResponse.Content.error_description

                if ([System.String]::IsNullOrEmpty($errorDescription)) {
                    $errorDescription = if (-not [System.String]::IsNullOrEmpty($oauthError)) {
                        $oauthError
                    } else {
                        "No error details were returned by the token endpoint."
                    }
                }

                Write-Host ("Device code authentication failed: {0}" -f $errorDescription) -ForegroundColor Red
                return $null
            }

            if ($null -eq $tokens) {
                Write-Host "Device code authentication timed out before sign-in completed." -ForegroundColor Red
                return $null
            }

            return ConvertTo-GraphAccessTokenResult -TokenResponse $tokens
        }

        function Invoke-AuthorizationCodeFlow {
            param(
                [Parameter(Mandatory = $true)]
                [string]$AzureADEndpoint,

                [Parameter(Mandatory = $true)]
                [string]$ClientId,

                [Parameter(Mandatory = $true)]
                [string]$Scope
            )

            $responseType = "code" # Provides the code as a query string parameter on our redirect URI
            $prompt = "select_account" # We want to show the select account dialog
            $redirectUri = "http://localhost:8004" # This is the default port for the local listener
            $codeChallengeMethod = "S256" # The code challenge method is S256 (SHA256)
            $codeChallengeVerifier = Get-NewS256CodeChallengeVerifier
            $state = ([guid]::NewGuid()).Guid # State which is needed for CSRF protection
            $nonce = ([guid]::NewGuid()).Guid # Nonce to prevent replay attacks

            $authorizationCodeResult = [PSCustomObject]@{
                GraphAccessToken                 = $null
                AuthorizationCodeFlowUnavailable = $false
                AuthorizationCodeFailureMessage  = $null
            }

            $authorizeQueryString = ConvertTo-OAuthQueryString -Parameters ([ordered]@{
                    client_id             = $ClientId
                    response_type         = $responseType
                    redirect_uri          = $redirectUri
                    scope                 = $Scope
                    state                 = $state
                    nonce                 = $nonce
                    prompt                = $prompt
                    code_challenge_method = $codeChallengeMethod
                    code_challenge        = $codeChallengeVerifier.CodeChallenge
                })

            # Request an authorization code from the Microsoft Azure Active Directory endpoint
            $authCodeRequestUrl = "{0}/organizations/oauth2/v2.0/authorize?{1}" -f $AzureADEndpoint, $authorizeQueryString

            try {
                Start-Process -FilePath $authCodeRequestUrl -ErrorAction Stop
                $authCodeResponse = Start-LocalListener -TimeoutSeconds 120
            } catch {
                Write-Verbose "Unable to launch a browser for authorization code authentication: $($_.Exception.Message)"
                $authorizationCodeResult.AuthorizationCodeFlowUnavailable = $true
                $authorizationCodeResult.AuthorizationCodeFailureMessage = "Unable to launch a browser for authorization code authentication."

                return $authorizationCodeResult
            }

            if ($null -eq $authCodeResponse) {
                $authorizationCodeResult.AuthorizationCodeFlowUnavailable = $true
                $authorizationCodeResult.AuthorizationCodeFailureMessage = "Unable to acquire an authorization code from the Microsoft Azure Active Directory endpoint."

                return $authorizationCodeResult
            }

            # Parse the authCodeResponse to get the state that was returned.
            # We need the state to add CSRF and mix-up defense protection.
            $queryString = ConvertFrom-QueryString -Query $authCodeResponse

            $returnedState = $queryString["state"]

            if (-not $returnedState) {
                Write-Host "No state value was returned" -ForegroundColor Red

                return $authorizationCodeResult
            }

            Write-Verbose "Script state: '$state' - Returned state: '$returnedState'"

            if ($returnedState -cne $state) {
                Write-Host "State mismatch detected! Expected '$state', got '$returnedState'" -ForegroundColor Red

                return $authorizationCodeResult
            }

            $code = $queryString["code"]

            if (-not $code) {
                $authorizationCodeResult.AuthorizationCodeFailureMessage = Get-OAuthErrorMessage `
                    -DefaultMessage "Authorization code is missing in callback." `
                    -ErrorContent ([PSCustomObject]@{
                        error             = $queryString["error"]
                        error_description = $queryString["error_description"]
                    })

                Write-Host $authorizationCodeResult.AuthorizationCodeFailureMessage -ForegroundColor Red

                return $authorizationCodeResult
            }

            $redeemAuthCodeResponse = Invoke-WebRequestWithProxyDetection -ParametersObject @{
                Uri             = "$AzureADEndpoint/organizations/oauth2/v2.0/token"
                Method          = "POST"
                ContentType     = "application/x-www-form-urlencoded"
                Body            = @{
                    client_id     = $ClientId
                    scope         = $Scope
                    code          = $code
                    redirect_uri  = $redirectUri
                    grant_type    = "authorization_code"
                    code_verifier = $codeChallengeVerifier.Verifier
                }
                UseBasicParsing = $true
            }

            if ($redeemAuthCodeResponse.StatusCode -eq 200) {
                $tokens = $redeemAuthCodeResponse.Content | ConvertFrom-Json
                $idTokenPayload = (Convert-JsonWebTokenToObject $tokens.id_token).Payload

                Write-Verbose "Script nonce: '$nonce' - Returned nonce: '$($idTokenPayload.nonce)'"

                if ($idTokenPayload.nonce -cne $nonce) {
                    Write-Host "Nonce mismatch detected" -ForegroundColor Red

                    return $authorizationCodeResult
                }

                $authorizationCodeResult.GraphAccessToken = ConvertTo-GraphAccessTokenResult -TokenResponse $tokens
            } else {
                Write-Host "Unable to redeem the authorization code for an access token." -ForegroundColor Red
            }

            return $authorizationCodeResult
        }

        $graphAccessToken = $null
    }
    process {
        $effectiveAuthFlow = $AuthFlow

        if ($effectiveAuthFlow -eq "Auto" -and -not (Test-AuthorizationCodeFlowAvailable)) {
            $effectiveAuthFlow = "DeviceCode"
        }

        $authFlowParams = @{
            AzureADEndpoint = $AzureADEndpoint
            ClientId        = $ClientId
            Scope           = $Scope
        }

        if ($effectiveAuthFlow -eq "DeviceCode") {
            $graphAccessToken = Invoke-DeviceCodeFlow @authFlowParams
        } else {
            $authorizationCodeResult = Invoke-AuthorizationCodeFlow @authFlowParams
            $graphAccessToken = $authorizationCodeResult.GraphAccessToken

            if ($authorizationCodeResult.AuthorizationCodeFlowUnavailable) {
                if ($AuthFlow -eq "Auto") {
                    Write-Host "Unable to complete browser-based authentication. Falling back to device code authentication." -ForegroundColor Yellow
                    $graphAccessToken = Invoke-DeviceCodeFlow @authFlowParams
                } else {
                    Write-Host $authorizationCodeResult.AuthorizationCodeFailureMessage -ForegroundColor Red
                }
            }
        }
    }
    end {
        if ($null -ne $graphAccessToken) {
            return $graphAccessToken
        }

        return $null
    }
}
