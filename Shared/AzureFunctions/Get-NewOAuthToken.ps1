# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-NewOAuthToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantID,

        [Parameter(Mandatory = $true)]
        [string]$ClientID,

        [Parameter(Mandatory = $true)]
        [string]$Secret,

        [Parameter(Mandatory = $true)]
        [string]$Endpoint,

        [Parameter(Mandatory = $false)]
        [string]$TokenService = "oauth2/v2.0/token",

        [Parameter(Mandatory = $false)]
        [switch]$CertificateBasedAuthentication,

        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    <#
        Shared function to create an OAuth token by using a JWT or secret.
        If you want to use a certificate, set the CertificateBasedAuthentication switch and pass a JWT token as the Secret parameter.
        You can use the Get-NewJsonWebToken function to create a JWT token.
        If you want to use a secret, pass the secret as the Secret parameter.
        This function returns a PSCustomObject with the OAuth token, status and the time the token was created.
        If the request fails, the PSCustomObject will contain the exception message.
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        $oAuthTokenCallSuccess = $false
        $exceptionMessage = $null

        Write-Verbose "TenantID: $TenantID - ClientID: $ClientID - Endpoint: $Endpoint - TokenService: $TokenService - Scope: $Scope"
        $body = @{
            scope      = $Scope
            client_id  = $ClientID
            grant_type = "client_credentials"
        }

        if ($CertificateBasedAuthentication) {
            Write-Verbose "Function was called with CertificateBasedAuthentication switch"
            $body.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            $body.Add("client_assertion", $Secret)
        } else {
            Write-Verbose "Authentication is based on a secret"
            $body.Add("client_secret", $Secret)
        }

        $invokeRestMethodParams = @{
            ContentType = "application/x-www-form-urlencoded"
            Method      = "POST"
            Body        = $body # Create string by joining bodyList with '&'
            Uri         = "$Endpoint/$TenantID/$TokenService"
        }
    }
    process {
        try {
            Write-Verbose "Now calling the Invoke-RestMethod cmdlet to create an OAuth token"
            $oAuthToken = Invoke-RestMethod @invokeRestMethodParams
            Write-Verbose "Invoke-RestMethod call was successful"
            $oAuthTokenCallSuccess = $true
        } catch {
            Write-Host "We fail to create an OAuth token - Exception: $($_.Exception.Message)" -ForegroundColor Red
            $exceptionMessage = $_.Exception.Message
        }
    }
    end {
        return [PSCustomObject]@{
            OAuthToken           = $oAuthToken
            Successful           = $oAuthTokenCallSuccess
            ExceptionMessage     = $exceptionMessage
            LastTokenRefreshTime = (Get-Date)
        }
    }
}
