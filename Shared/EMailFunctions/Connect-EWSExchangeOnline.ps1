. $PSScriptRoot\..\Get-NuGetPackage.ps1
. $PSScriptRoot\..\Invoke-ExtractArchive.ps1
. $PSScriptRoot\..\LoggerFunctions.ps1
. $PSScriptRoot\..\AzureFunctions\Get-AzureApplication.ps1
. $PSScriptRoot\..\AzureFunctions\Get-CloudServiceEndpoint.ps1
. $PSScriptRoot\..\AzureFunctions\Get-GraphAccessToken.ps1
. $PSScriptRoot\..\AzureFunctions\Get-NewOAuthToken.ps1
. $PSScriptRoot\..\AzureFunctions\New-AzureApplication.ps1
. $PSScriptRoot\..\AzureFunctions\New-AzureApplicationAppSecret.ps1
. $PSScriptRoot\..\AzureFunctions\Remove-AzureApplication.ps1

function Connect-EWSExchangeOnline {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "CreateAzureApplication")]
        [switch]$CreateAzureApplication,

        [Parameter(Mandatory = $true, ParameterSetName = "DeleteAzureApplication")]
        [switch]$DeleteAzureApplication,

        [Parameter(Mandatory = $true, ParameterSetName = "CreateAzureApplication")]
        [Parameter(Mandatory = $true, ParameterSetName = "DeleteAzureApplication")]
        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [string]$AzureApplicationName,

        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [string]$ImpersonatedUserId,

        [Parameter()]
        [ValidateSet("Global", "USGovernmentL4", "USGovernmentL5", "ChinaCloud")]
        [string]$AzureEnvironment = "Global",

        [Parameter(ParameterSetName = "Default")]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = "Default")]
        [string]$AppId,

        [Parameter(ParameterSetName = "Default")]
        [string]$Organization,

        [Parameter(ParameterSetName = "Default")]
        [ValidateScript({ Test-Path $_ })]
        [string]$DLLPath,

        [Parameter(ParameterSetName = "Default")]
        [ValidateRange(1, 2147483)]
        [int]$TimeoutSeconds = 300
    )

    $cloudService = Get-CloudServiceEndpoint $AzureEnvironment

    $ewsOnlineURL = "$($cloudService.ExchangeOnlineEndpoint)/EWS/Exchange.asmx"
    $ewsOnlineScope = "$($cloudService.ExchangeOnlineEndpoint)/.default"
    $azureADEndpoint = $cloudService.AzureADEndpoint
    $graphApiEndpoint = $cloudService.GraphApiEndpoint

    if ($CreateAzureApplication) {
        $createAzureApplicationParams = @{
            AccessToken          = (Get-GraphAccessToken -AzureADEndpoint $azureADEndpoint -GraphApiUrl $graphApiEndpoint).AccessToken
            AzureApplicationName = $AzureApplicationName
            GraphApiUrl          = $graphApiEndpoint
        }
        New-AzureApplication @createAzureApplicationParams
        exit
    }

    if ($DeleteAzureApplication) {
        $deleteAzureApplicationParams = @{
            AccessToken          = (Get-GraphAccessToken -AzureADEndpoint $azureADEndpoint -GraphApiUrl $graphApiEndpoint).AccessToken
            AzureApplicationName = $AzureApplicationName
            GraphApiUrl          = $graphApiEndpoint
        }
        Remove-AzureApplication @deleteAzureApplicationParams
        exit
    }

    $path = $DLLPath

    if ([System.String]::IsNullOrEmpty($path)) {
        Write-Verbose "Trying to find Microsoft.Exchange.WebServices.dll in the script folder"
        $path = (Get-ChildItem -LiteralPath "$PSScriptRoot\EWS" -Recurse -Filter "Microsoft.Exchange.WebServices.dll" -ErrorAction SilentlyContinue |
                Select-Object -First 1).FullName

        if ([System.String]::IsNullOrEmpty($path)) {
            Write-Host "Microsoft.Exchange.WebServices.dll wasn't found - attempting to download it from the internet" -ForegroundColor Yellow
            $nuGetPackage = Get-NuGetPackage -PackageId "Microsoft.Exchange.WebServices" -Author "Microsoft"

            if ($nuGetPackage.DownloadSuccessful) {
                $unzipNuGetPackage = Invoke-ExtractArchive -CompressedFilePath $nuGetPackage.NuGetPackageFullPath -TargetFolder "$PSScriptRoot\EWS"

                if ($unzipNuGetPackage.DecompressionSuccessful) {
                    $path = (Get-ChildItem -Path $unzipNuGetPackage.FullPathToDecompressedFiles -Recurse -Filter "Microsoft.Exchange.WebServices.dll" |
                            Select-Object -First 1).FullName
                } else {
                    Write-Warning "Failed to unzip Microsoft.Exchange.WebServices.dll. Please unzip the package manually."
                    exit
                }
            } else {
                Write-Warning "Failed to download Microsoft.Exchange.WebServices.dll from the internet. Please download the package manually and extract the dll. Provide the path to dll using DLLPath parameter."
                exit
            }
        } else {
            Write-Verbose "Microsoft.Exchange.WebServices.dll was found: $path"
        }
    }

    try {
        Import-Module -Name $path -ErrorAction Stop
    } catch {
        Write-Warning "Failed to import Microsoft.Exchange.WebServices.dll Inner Exception`n`n$_"
        exit
    }

    if (([System.String]::IsNullOrEmpty($AppId)) -or
            ([System.String]::IsNullOrEmpty($Organization)) -or
            ([System.String]::IsNullOrEmpty($CertificateThumbprint))) {
        # We need to query the Azure application information from the Azure AD if not explicitly provided via parameter
        $graphTokenInfo = Get-GraphAccessToken -AzureADEndpoint $azureADEndpoint -GraphApiUrl $graphApiEndpoint
        $application = Get-AzureApplication -Accesstoken $graphTokenInfo.AccessToken -AzureApplicationName $AzureApplicationName -GraphApiUrl $graphApiEndpoint

        $tenantID = $graphTokenInfo.TenantId
        $clientID = $application.value.appId
    } else {
        $tenantID = $Organization
        $clientID = $AppId
    }

    $applicationInfo = @{
        "TenantID" = $tenantID
        "ClientID" = $clientID
    }

    if ([System.String]::IsNullOrEmpty($CertificateThumbprint)) {
        $secret = New-AzureApplicationAppSecret -AccessToken $graphTokenInfo.AccessToken -AzureApplicationName $AzureApplicationName -GraphApiUrl $graphApiEndpoint
        if ([System.String]::IsNullOrEmpty($secret)) {
            Write-Warning "Unable to generate application secret for Azure application: $AzureApplicationName"
            exit
        }
        $applicationInfo.Add("AppSecret", $secret)
    } else {
        $jwtParams = @{
            CertificateThumbprint = $CertificateThumbprint
            CertificateStore      = "CurrentUser"
            Issuer                = $clientID
            Audience              = "$azureADEndpoint/$tenantID/oauth2/v2.0/token"
            Subject               = $clientID
        }
        $jwt = Get-NewJsonWebToken @jwtParams

        if ($null -eq $jwt) {
            Write-Warning "Unable to generate Json Web Token by using certificate: $CertificateThumbprint"
            exit
        }

        $applicationInfo.Add("AppSecret", $jwt)
        $applicationInfo.Add("CertificateThumbprint", $CertificateThumbprint)
    }

    $createOAuthTokenParams = @{
        TenantID                       = $applicationInfo.TenantID
        ClientID                       = $applicationInfo.ClientID
        Secret                         = $applicationInfo.AppSecret
        Scope                          = $ewsOnlineScope
        Endpoint                       = $azureADEndpoint
        CertificateBasedAuthentication = (-not([System.String]::IsNullOrEmpty($CertificateThumbprint)))
    }

    $oAuthReturnObject = Get-NewOAuthToken @createOAuthTokenParams
    if ($oAuthReturnObject.Successful -eq $false) {
        Write-Warning "Unable to fetch an OAuth token for accessing EWS. Please review the error message below and re-run the script:"
        Write-Warning $oAuthReturnObject.ExceptionMessage
        exit
    }

    $service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2016)
    $service.Url = $ewsOnlineURL
    $service.Credentials = New-Object Microsoft.Exchange.WebServices.Data.OAuthCredentials($oAuthReturnObject.OAuthToken.access_token)
    $service.ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId("SmtpAddress", $ImpersonatedUserId)
    $service.Timeout = $TimeoutSeconds * 1000

    $serviceInfo = [PSCustomObject]@{
        ExchangeService       = $service
        Token                 = $oAuthReturnObject.OAuthToken
        LastRefreshTime       = (Get-Date)
        TenantID              = $applicationInfo.TenantID
        ClientID              = $applicationInfo.ClientID
        AppSecret             = $applicationInfo.AppSecret
        CertificateThumbprint = $applicationInfo.CertificateThumbprint
        AzureADEndpoint       = $azureADEndpoint
        EWSOnlineScope        = $ewsOnlineScope
        EWSOnlineUrl          = $ewsOnlineURL
    }

    return $serviceInfo
}
