# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# Test-HMAEAS
# Modified 2019/03/24
# Syntax for running this script:
#
# .\Test-HMAEAS.ps1 -SMTP <User's SMTP Address> -CustomAutoD <Specify a custom AutoDiscover Hostname> -SMTPAddress -TestEAS
#
# Example:
# AutoD/Empty Bearer Token Test
# .\Test-HMAEAS onprem@contoso.com
#
# EAS Connection Test (Credentials Needed)
# .\Test-HMAEAS onprem@contoso.com -TestEAS
#
# AutoD/Empty Bearer Token Test with a customer AutoD Endpoint
# .\Test-HMAEAS onprem@contoso.com -CustomAutoD autodiscover.contoso.com
#
# EAS Connection Test (Credentials Needed) with a customer AutoD Endpoint
# .\Test-HMAEAS onprem@contoso.com -TestEAS -CustomAutoD autodiscover.contoso.com
##############################################################################################
#
# This script is not officially supported by Microsoft, use it at your own risk.
# Microsoft has no liability, obligations, warranty, or responsibility regarding
# any result produced by use of this file.
#
##############################################################################################
# The sample scripts are not supported under any Microsoft standard support
# program or service. The sample scripts are provided AS IS without warranty
# of any kind. Microsoft further disclaims all implied warranties including, without
# limitation, any implied warranties of merchantability or of fitness for a particular
# purpose. The entire risk arising out of the use or performance of the sample scripts
# and documentation remains with you. In no event shall Microsoft, its authors, or
# anyone else involved in the creation, production, or delivery of the scripts be liable
# for any damages whatsoever (including, without limitation, damages for loss of business
# profits, business interruption, loss of business information, or other pecuniary loss)
# arising out of the use of or inability to use the sample scripts or documentation,
# even if Microsoft has been advised of the possibility of such damages
##############################################################################################

param (
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [String[]]$SMTP,
    [Switch]$TestEAS,
    [String]$CustomAutoD
)

process {

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $SMTPAddress = $SMTP.Split("@")

    Function Read-AutoDv2EAS {
        [CmdletBinding()]
        param (
            [Parameter()]
            [string]
            $CustomAutoD
        )
        process {
            try {
                if ($CustomAutoD) {
                    $requestURI = $requestURI = "https://$($CustomAutoD)/autodiscover/autodiscover.json?Email=$($SMTP)&Protocol=activesync&RedirectCount=3"
                } else {
                    $requestURI = $requestURI = "https://autodiscover.$($SMTPAddress[1])/autodiscover/autodiscover.json?Email=$($SMTP)&Protocol=activesync&RedirectCount=3"
                }
                $headers = @{
                    'Accept'         = 'application/json'
                    'Content-Length' = '0'
                }
                $webResponse = Invoke-WebRequest -Uri $requestURI -Headers $headers -Method GET -UseBasicParsing
                $jsonResponse = $webResponse.Content | ConvertFrom-Json
                Write-Host
                Write-Host "We sent an AutoDiscover Request to On-Premises for the Exchange ActiveSync Virtual Directory and below is the response" -ForegroundColor Green
                Write-Host "The response should contain the Protocol ActiveSync with a valid URL" -ForegroundColor Yellow
                Write-Host "---------------------------------------------------------------------------------------------------------------"
                Write-Host $jsonResponse.Url
                return $jsonResponse.Url
                Write-Host
            } catch [System.Net.Sockets.SocketException] {
                Write-Host
                Write-Host "We sent an AutoDiscover Request to On-Premises for the Exchange ActiveSync Virtual Directory and below is the response" -ForegroundColor Green
                Write-Host "The response should contain the Protocol ActiveSync with a valid URL" -ForegroundColor Yellow
                Write-Host "---------------------------------------------------------------------------------------------------------------"
                Write-Host "ERROR: We were unable to complete the AutoDiscover request." -ForegroundColor Red -Verbose
                Write-Host "Please ensure that autodiscover.$($SMTPAddress[1]) is the correct AutoDiscover endpoint and is not being blocked by a firewall" -ForegroundColor Yellow -Verbose
                Write-Host
            } catch [System.Net.WebException] {
                Write-Host
                Write-Host "We sent an AutoDiscover Request to On-Premises for the Exchange ActiveSync Virtual Directory and below is the response" -ForegroundColor Green
                Write-Host "The response should contain the Protocol ActiveSync with a valid URL" -ForegroundColor Yellow
                Write-Host "---------------------------------------------------------------------------------------------------------------"
                Write-Host "ERROR: We were unable to complete the AutoDiscover request." -ForegroundColor Red -Verbose
                Write-Host "Please ensure that autodiscover.$($SMTPAddress[1]) is the correct AutoDiscover endpoint and is able to be resolved in DNS" -ForegroundColor Yellow -Verbose
                Write-Host
            } catch {
                Write-Host
                Write-Error $_.Exception.Message
                Write-Host
            }
        }
    }

    Function Test-EASBearer {
        process {
            try {
                $requestURI = $easUrl
                $authType = "Bearer "
                $headers = @{
                    'Accept'         = 'application/json'
                    'Authorization'  = $authType
                    'Content-Length' = '0'
                }
                Invoke-RestMethod -Uri $requestURI -Headers $headers -Method Get | Out-Null
            } catch [System.Net.Sockets.SocketException] {
                Write-Host
                Write-Host "We sent an Empty Bearer Token Request to the On-Premises Exchange ActiveSync Virtual Directory and below is the response" -ForegroundColor Green
                Write-Host "The response should contain a valid WWW-Authenticate=Bearer. Make sure the authorization_uri is populated" -ForegroundColor Yellow
                Write-Host "---------------------------------------------------------------------------------------------------------------"
                Write-Host "ERROR: We were unable to connect to the Exchange ActiveSync Virtual Directory." -ForegroundColor Red -Verbose
                Write-Host "Please ensure that $easUrl is the correct Exchange ActiveSync endpoint and is not being blocked by a firewall" -ForegroundColor Yellow -Verbose
                Write-Host
            } catch [System.Management.Automation.ValidationMetadataException] {
                Write-Host
                Write-Host "We sent an Empty Bearer Token Request to the On-Premises Exchange ActiveSync Virtual Directory and below is the response" -ForegroundColor Green
                Write-Host "The response should contain a valid WWW-Authenticate=Bearer. Make sure the authorization_uri is populated" -ForegroundColor Yellow
                Write-Host "---------------------------------------------------------------------------------------------------------------"
                Write-Host "ERROR: We did not receive a response from AutoDiscover so we cannot test the Exchange ActiveSync Virtual Directory" -ForegroundColor Red -Verbose
                Write-Host
            } catch [System.Security.Authentication.AuthenticationException] {
                Write-Host
                Write-Host "We sent an Empty Bearer Token Request to the On-Premises Exchange ActiveSync Virtual Directory and below is the response" -ForegroundColor Green
                Write-Host "The response should contain a valid WWW-Authenticate=Bearer. Make sure the authorization_uri is populated" -ForegroundColor Yellow
                Write-Host "---------------------------------------------------------------------------------------------------------------"
                Write-Host "ERROR: We noticed a certificate error so we cannot test the Exchange ActiveSync Virtual Directory, please chect your certificates for $easUrl" -ForegroundColor Red -Verbose
                Write-Host
            } catch {
                Write-Host
                Write-Host "We sent an Empty Bearer Token Request to the On-Premises Exchange ActiveSync Virtual Directory and below is the response" -ForegroundColor Green
                Write-Host "The response should contain a valid WWW-Authenticate=Bearer. Make sure the authorization_uri is populated" -ForegroundColor Yellow
                Write-Host "---------------------------------------------------------------------------------------------------------------"
                $headers = $_.Exception.Response.Headers
                $cookies = $_.Exception.Response.Cookies
                $headers | ForEach-Object { Write-Host "$_=$($headers[$_])" }
                $cookies | ForEach-Object { Write-Host "$_=$($cookies[$_])" }
                Write-Host
            }
        }
    }

    Function Test-AutoDetect {
        process {
            try {
                $RequestURI = "https://prod-autodetect.outlookmobile.com/detect?services=office365,outlook,google,icloud,yahoo&protocols=rest-cloud,rest-outlook,rest-office365,eas,imap,smtp"
                $webResponse = Invoke-WebRequest -Uri $RequestURI -Headers @{'x-email' = $($SMTP) } -Method GET -UseBasicParsing
                $jsonResponse = $webResponse.Content | ConvertFrom-Json
                if (!$jsonResponse.services) {
                    Write-Host
                    Write-Host "Autodetect has the following services listed for the user" -ForegroundColor Green
                    Write-Host "This should have AAD pointing to Microsoft Online and On-Premises to the correct EAS URL" -ForegroundColor Yellow
                    Write-Host "---------------------------------------------------------------------------------------------------------------"
                    Write-Host "Service:    " $jsonResponse.protocols.service
                    Write-Host "Protocol:   " $jsonResponse.protocols.protocol
                    Write-Host "Hostname:   " $jsonResponse.protocols.hostname
                    Write-Host "Azure AD:   " $jsonResponse.protocols.aad
                    Write-Host "On-Premises:" $jsonResponse.protocols.onprem
                    Write-Host "Error:      " $jsonResponse.protocols.insecure
                    Write-Host
                }

                else {
                    Write-Host
                    Write-Host "Autodetect has the following services listed for the user" -ForegroundColor Green
                    Write-Host "This should have AAD pointing to Microsoft Online and On-Premises to the correct EAS URL" -ForegroundColor Yellow
                    Write-Host "---------------------------------------------------------------------------------------------------------------"
                    Write-Host "Service:    " $jsonResponse.services.service
                    Write-Host "Protocol:   " $jsonResponse.services.protocol
                    Write-Host "Hostname:   " $jsonResponse.services.hostname
                    Write-Host "Azure AD:   " $jsonResponse.services.aad
                    Write-Host "On-Premises:" $jsonResponse.services.onprem
                    Write-Host
                }
            } catch {
                Write-Host
                Write-Error $_.Exception.Message
                Write-Host
            }
        }
    }

    Function Read-EASOptions {
        process {
            try {
                Write-Host
                Write-Host "We sent an OPTIONS Request to the On-Premises Exchange ActiveSync Virtual Directory and below is the response" -ForegroundColor Green
                Write-Host "The response should contain HTTP code 200 OK" -ForegroundColor Yellow
                Write-Host
                $authType = $('Bearer {0}' -f $accessToken)
                $headers = @{
                    'content-type'   = 'application/vnd.ms-sync.wbxml'
                    'Authorization'  = $authType
                    'Content-Length' = '0'
                }
                $requestURI = New-Object "System.Uri" -ArgumentList $easUrl
                $webResponse = Invoke-WebRequest -Uri $requestURI -Headers $headers -Method OPTIONS -UseBasicParsing
                $webResponse.RawContent
            } catch [System.Net.WebException] {
                Write-Host
                Write-Error $_.Exception.Message
                Write-Host
                throw
            }
        }
    }

    Function Read-EASSettings {
        process {
            try {
                Write-Host
                Write-Host "We sent a SETTINGS Request to the On-Premises Exchange ActiveSync Virtual Directory and below is the response" -ForegroundColor Green
                Write-Host "The response should contain HTTP code 200 OK" -ForegroundColor Yellow
                Write-Host
                $requestURI = New-Object "System.Uri" -ArgumentList "$($easUrl)?Cmd=Settings&DeviceId=OutlookService&DeviceType=OutlookService"
                $authType = $('Bearer {0}' -f $accessToken)
                $headers = @{
                    'content-type'         = 'application/vnd.ms-sync.wbxml'
                    'Content-Length'       = '11'
                    'Authorization'        = $authType
                    'MS-ASProtocolVersion' = '14.1'
                }
                #Actual payload: "<Settings xmlns=\"Settings:\">  <UserInformation>    <Get />  </UserInformation>   </Settings>"
                #Converted to wbxml byte array
                $bytes = [byte[]](0x03, 0x01, 0x6a, 0x00, 0x00, 0x12, 0x45, 0x5D, 0x07, 0x01, 0x01)
                $webResponse = Invoke-WebRequest -Uri $requestURI -Headers $headers -Body $bytes -Method POST -UseBasicParsing
                $webResponse.RawContent
                [System.Convert]::ToBase64String($webResponse.Content)
            } catch {
                Write-Host
                Write-Error $_.Exception.Message
                Write-Host
                throw
            }
        }
    }

    Function Get-AccessToken {
        process {
            try {
                Write-Host
                Write-Host "We are trying to get an access token to access the EAS endpoint. Please login with your credentials when prompted." -ForegroundColor Green
                Write-Host "The token should contain Outlook Mobile under app_displayname" -ForegroundColor Yellow
                Write-Host
                $authority = "https://login.windows.net/common/oauth2/authorize"
                $uri = New-Object "System.Uri" -ArgumentList $easUrl
                $resource = "$($uri.Scheme)://$($uri.Host)"
                $applicationClientId = "27922004-5251-4030-b22d-91ecd9a37ea4"
                $redirectUri = [System.Uri]"urn:ietf:wg:oauth:2.0:oob"
                $authenticationContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
                $PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::RefreshSession
                $platformParam = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $PromptBehavior, $NULL
                $userIdentifier = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $SMTP, 1
                $authResult = $authenticationContext.AcquireTokenAsync($resource, $applicationClientId, $redirectUri, $platformParam, $userIdentifier).Result
                $accessToken = $authResult.AccessToken
                if ($NULL -eq $accessToken) {
                    throw [System.Exception] "Failed to get access token."
                }
                return $authResult.AccessToken
            } catch {
                Write-Host
                Write-Error $_.Exception.Message
                Write-Host
                exit
            }
        }
    }

    function Show-JWTtoken {
        param (
            [string]$token
        )
        process {
            $tokenheader = $token.Split(".")[0]
            while ($tokenheader.Length % 4) { $tokenheader += "=" }
            $decodedHeader = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json
            Write-Host "Token Headers"
            $decodedHeader | Format-List
            Write-Host "Token Claims"
            $tokenPayload = $token.Split(".")[1]
            while ($tokenPayload.Length % 4) { $tokenPayload += "=" }
            $decodedPayload = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenPayload)) | ConvertFrom-Json
            $decodedPayload
        }
    }

    If ($TestEAS) {
        Write-Host "Installing ADAL package. Please accept if prompted." -ForegroundColor Green
        Install-Package Microsoft.IdentityModel.Clients.ActiveDirectory -RequiredVersion 3.19.8 -Source 'https://www.nuget.org/api/v2' -SkipDependencies -Scope CurrentUser
        Write-Host "Loading ADAL package" -ForegroundColor Green
        $package = Get-Package "Microsoft.IdentityModel.Clients.ActiveDirectory"
        $packagePath = Split-Path $package.Source -Parent
        $dllPath = Join-Path -Path $packagePath -ChildPath "lib/net45/Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        Add-Type -Path $dllPath -ErrorAction Stop
        $easUrl = Read-AutoDv2EAS -CustomAutoD $CustomAutoD
        Test-EASBearer
        Test-AutoDetect
        $accessToken = Get-AccessToken -easUrl $easUrl -SMTPAddress $SMTPAddress
        Show-JWTtoken -token $accessToken
        Read-EASOptions -easUrl $easUrl -accessToken $accessToken
        Read-EASSettings -easUrl $easUrl -accessToken $accessToken
    } else {
        $easUrl = Read-AutoDv2EAS -CustomAutoD $CustomAutoD
        Test-EASBearer
        Test-AutoDetect
    }
}
