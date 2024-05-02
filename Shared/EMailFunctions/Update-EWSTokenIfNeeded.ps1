function Update-EWSTokenIfNeeded {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # This should be the object returned by Connect-EWSExchangeOnline
        $ServiceInfo
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"

    # if token is going to expire in next 5 min then refresh it
    if ($null -eq $ServiceInfo.LastRefreshTime -or $ServiceInfo.LastRefreshTime.AddMinutes(55) -lt (Get-Date)) {
        if (-not $PSCmdlet.ShouldProcess("OAuth Token", "Refresh")) {
            return $ServiceInfo
        }

        $createOAuthTokenParams = @{
            TenantID                       = $ServiceInfo.TenantID
            ClientID                       = $ServiceInfo.ClientID
            Endpoint                       = $ServiceInfo.AzureADEndpoint
            CertificateBasedAuthentication = (-not([System.String]::IsNullOrEmpty($ServiceInfo.CertificateThumbprint)))
            Scope                          = $ServiceInfo.EWSOnlineScope
        }

        # Check if we use an app secret or certificate by using regex to match Json Web Token (JWT)
        if ($ServiceInfo.AppSecret -match "^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)") {
            $jwtParams = @{
                CertificateThumbprint = $ServiceInfo.CertificateThumbprint
                CertificateStore      = "CurrentUser"
                Issuer                = $ServiceInfo.ClientID
                Audience              = "$($ServiceInfo.AzureADEndpoint)/$($ServiceInfo.TenantID)/oauth2/v2.0/token"
                Subject               = $ServiceInfo.ClientID
            }
            $jwt = Get-NewJsonWebToken @jwtParams

            if ($null -eq $jwt) {
                Write-Host "Unable to sign a new Json Web Token by using certificate: $($ServiceInfo.CertificateThumbprint)" -ForegroundColor Red
                exit
            }

            $createOAuthTokenParams.Add("Secret", $jwt)
        } else {
            $createOAuthTokenParams.Add("Secret", $ServiceInfo.AppSecret)
        }

        $oAuthReturnObject = Get-NewOAuthToken @createOAuthTokenParams
        if ($oAuthReturnObject.Successful -eq $false) {
            Write-Host ""
            Write-Host "Unable to refresh EWS OAuth token. Please review the error message below and re-run the script:" -ForegroundColor Red
            Write-Host $oAuthReturnObject.ExceptionMessage -ForegroundColor Red
            exit
        }

        $ServiceInfo.Token = $oAuthReturnObject.OAuthToken
        $ServiceInfo.ExchangeService.Credentials = New-Object Microsoft.Exchange.WebServices.Data.OAuthCredentials($oAuthReturnObject.OAuthToken.access_token)
        $ServiceInfo.LastRefreshTime = (Get-Date)
    }

    return $ServiceInfo
}
