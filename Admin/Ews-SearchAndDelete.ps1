# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# Ews-SearchAndDelete.ps1
#
# By David Barrett and Jim Martin, Microsoft Ltd. 2013-2023. Use at your own risk.  No warranties are given.
#
#  DISCLAIMER:
# THIS CODE IS SAMPLE CODE. THESE SAMPLES ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
# MICROSOFT FURTHER DISCLAIMS ALL IMPLIED WARRANTIES INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR OF FITNESS FOR
# A PARTICULAR PURPOSE. THE ENTIRE RISK ARISING OUT OF THE USE OR PERFORMANCE OF THE SAMPLES REMAINS WITH YOU. IN NO EVENT SHALL
# MICROSOFT OR ITS SUPPLIERS BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF BUSINESS PROFITS,
# BUSINESS INTERRUPTION, LOSS OF BUSINESS INFORMATION, OR OTHER PECUNIARY LOSS) ARISING OUT OF THE USE OF OR INABILITY TO USE THE
# SAMPLES, EVEN IF MICROSOFT HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. BECAUSE SOME STATES DO NOT ALLOW THE EXCLUSION OR LIMITATION
# OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL DAMAGES, THE ABOVE LIMITATION MAY NOT APPLY TO YOU.

param (
    [Parameter(Position=0,Mandatory=$True,HelpMessage="The Mailbox parameter specifies the mailbox to be accessed.")] [ValidateNotNullOrEmpty()] [string]$Mailbox,
	[Parameter(Mandatory=$False,HelpMessage="The Archive parameter is a switch to search the archive mailbox (otherwise, the main mailbox is searched).")] [alias("SearchArchive")] [switch]$Archive,
    [Parameter(Mandatory=$False,HelpMessage="The ProcessSubfolders parameter is a switch to enable searching the subfolders of any specified folder.")] [switch]$ProcessSubfolders,
	[Parameter(Mandatory=$False,HelpMessage="The IncludeFolderList parameter specifies the folder(s) to be searched (if not present, then the Inbox folder will be searched).  Any exclusions override this list.")] $IncludeFolderList,
    [Parameter(Mandatory=$False,HelpMessage="The ExcludeFolderList parameter specifies the folder(s) to be excluded (these folders will not be searched).")] $ExcludeFolderList,
    [Parameter(Mandatory=$False,HelpMessage="The MessageClass parameter specifies the message class of the items being searched.")] [ValidateNotNullOrEmpty()] [string]$MessageClass,
    [Parameter(Mandatory=$false, HelpMessage="The CreatedBefore parameter specifies only messages created before this date will be searched.")] [datetime]$CreatedBefore,
    [Parameter(Mandatory=$false, HelpMessage="The CreatedAfter parameter specifies only messages created after this date will be searched.")] [datetime]$CreatedAfter,
    [Parameter(Mandatory=$False,HelpMessage="The Subject paramter specifies the subject string used by the search.")] [string]$Subject,
    [Parameter(Mandatory=$False,HelpMessage="The Sender paramter specifies the sender email address used by the search.")] [string]$Sender,
    [Parameter(Mandatory=$False,HelpMessage="The Recipient paramter specifies the recipient email address used by the search (include Cc and Bcc).")] [string]$Recipient,
    [Parameter(Mandatory=$False,HelpMessage="The MessageBody parameter specifies the body string used by the search.")] [string]$MessageBody,
    [Parameter(Mandatory=$false,HelpMessage="The SearchDumpster parameter is a switch to search the recoverable items.")] [switch]$SearchDumpster,
    [Parameter(Mandatory=$False,HelpMessage="The MessageId parameter specified the MessageId used by the search.")] [string]$MessageId,
    [Parameter(Mandatory=$False,HelpMessage="The ViewProperties parameter adds the given property(ies) to the list of those that will be retrieved for an item (must be supplied as hash table @{}).  By default, Id, Subject and Sender are retrieved.")] $ViewProperties,
	[Parameter(Mandatory=$False,HelpMessage="The DeleteContent parameter is a switch to delete the items found in the search results (moved to Deleted Items).")][switch]$DeleteContent,
	[Parameter(Mandatory=$False,HelpMessage="The HardDelete parameter is a swithch to hard-delete the items found in the search results (otherwise, they'll be moved to Deleted Items).")][switch]$HardDelete,
	    
#>** EWS/OAUTH PARAMETERS START **#
	#[Parameter(Mandatory=$False,HelpMessage="If set, then we will use OAuth to access the mailbox (required for Office 365)")] [switch]$OAuth,
    [Parameter(Mandatory=$False,HelpMessage="The OAuthClientId parameter is the Azure Application Id that this script uses to obtain the OAuth token.  Must be registered in Azure AD.")] [string]$OAuthClientId = "",
    [Parameter(Mandatory=$False,HelpMessage="The OAuthTenantId paramter is the tenant Id where the application is registered (Must be in the same tenant as mailbox being accessed).")] [string]$OAuthTenantId = "",
    [Parameter(Mandatory=$False,HelpMessage="The OAuthRedirectUri parameter is the redirect Uri of the Azure registered application.")] [string]$OAuthRedirectUri = "http://localhost/code",
    [Parameter(Mandatory=$False,HelpMessage="The OAuthSecretKey parameter is the the secret for the registered application.")] [string]$OAuthSecretKey = "",
    [Parameter(Mandatory=$False,HelpMessage="The OAuthCertificate parameter is the certificate for the registerd application. Certificate auth requires MSAL libraries to be available.")] $OAuthCertificate = $null,
    [Parameter(Mandatory=$False,HelpMessage="The GlobalTokenStorage parameter is a switch when set, OAuth tokens will be stored in global variables for access in other scripts/console.  These global variable will be checked by later scripts using delegate auth to prevent additional log-in prompts.")][switch]$GlobalTokenStorage,

    [Parameter(Mandatory=$False,HelpMessage="The OAuthDebug parameter is used For debugging purposes.")][switch]$OAuthDebug,

    [Parameter(Mandatory=$False,HelpMessage="The DebugTokenRenewal parameter enables token debugging with a value greater than 0 (specify total number of token renewals to debug).")]	$DebugTokenRenewal = 0,

    [Parameter(Mandatory=$False,HelpMessage="The Impersonate parameter enables impersonation to access the mailbox when set to True.")] [boolean]$Impersonate=$True,
	
    [Parameter(Mandatory=$False,HelpMessage="The EWSManagedApiPath parameter specifies the path to managed API (if omitted, a search of standard paths is performed).")][string]$EWSManagedApiPath = "",
	
    [Parameter(Mandatory=$False,HelpMessage="The TraceFile parameter specified the Trace file path - if specified, EWS tracing information is written to this file.")]	[string]$TraceFile,
#>** EWS/OAUTH PARAMETERS END **#

#>** LOGGING PARAMETERS START **#
    [Parameter(Mandatory=$False,HelpMessage="The LogFile parameter specifies the Log file path - activity is logged to this file if specified.")][string]$LogFile = "",
    [Parameter(Mandatory=$False,HelpMessage="The VerboseLogFile parameter is a switch that enables verbose log file.  Verbose logging is written to the log whether -Verbose is enabled or not.")]	[switch]$VerboseLogFile,
    [Parameter(Mandatory=$False,HelpMessage="The DebugLogFile parameter is a switch that enables debug log file.  Debug logging is written to the log whether -Debug is enabled or not.")][switch]$DebugLogFile,
    [Parameter(Mandatory=$False,HelpMessage="The FastFileLogging parameter is a switch that if selected, an optimised log file creator is used that should be signficantly faster (but may leave file lock applied if script is cancelled).")][switch]$FastFileLogging,
    [Parameter(Mandatory=$True,HelpMessage="The ResultsFile parameter specifies the results file path - items returned by the search results are saved into this file.")]	[string]$ResultsFile,
#>** LOGGING PARAMETERS END **#

    [Parameter(Mandatory=$False,HelpMessage="The ThrottlingDelay parameter specifies the throttling delay (time paused between sending EWS requests) - note that this will be increased automatically if throttling is detected")]	[int]$ThrottlingDelay = 0,

    [Parameter(Mandatory=$False,HelpMessage="The BatchSize parameter specifies the batch size (number of items batched into one EWS request) - this will be decreased if throttling is detected")] [int]$BatchSize = 200
)
$script:ScriptVersion = "20240227.1948"

# Define our functions

#>** LOGGING FUNCTIONS START **#
function LogToFile([string]$Details)
{
	if ( [String]::IsNullOrEmpty($LogFile) ) { return }
	"$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToLongTimeString())   $Details" | Out-File $LogFile -Append
}

function UpdateDetailsWithCallingMethod([string]$Details)
{
    # Update the log message with details of the function that logged it
    $timeInfo = "$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToLongTimeString())"
    $callingFunction = (Get-PSCallStack)[2].Command # The function we are interested in will always be frame 2 on the stack
    if (![String]::IsNullOrEmpty($callingFunction))
    {
        return "$timeInfo [$callingFunction] $Details"
    }
    return "$timeInfo $Details"
}

function LogToFile([string]$logInfo)
{
    if ( [String]::IsNullOrEmpty($LogFile) ) { return }
    
    if ($FastFileLogging)
    {
        # Writing the log file using a FileStream (that we keep open) is significantly faster than using out-file (which opens, writes, then closes the file each time it is called)
        $fastFileLogError = $Error[0]
        if (!$script:logFileStream)
        {
            # Open a filestream to write to our log
            Write-Verbose "Opening/creating log file: $LogFile"
            $script:logFileStream = New-Object IO.FileStream($LogFile, ([System.IO.FileMode]::Append), ([IO.FileAccess]::Write), ([IO.FileShare]::Read) )
            if ( $Error[0] -ne $fastFileLogError )
            {
                $FastFileLogging = $false
                Write-Host "Fast file logging disabled due to error: $Error[0]" -ForegroundColor Red
                $script:logFileStream = $null
            }
        }
        if ($script:logFileStream)
        {
            if (!$script:logFileStreamWriter)
            {
                $script:logFileStreamWriter = New-Object System.IO.StreamWriter($script:logFileStream)
            }
            $script:logFileStreamWriter.WriteLine($logInfo)
            $script:logFileStreamWriter.Flush()
            if ( $Error[0] -ne $fastFileLogError )
            {
                $FastFileLogging = $false
                Write-Host "Fast file logging disabled due to error: $Error[0]" -ForegroundColor Red
            }
            else
            {
                return
            }
        }
    }

	$logInfo | Out-File $LogFile -Append
}

function Log([string]$Details, [ConsoleColor]$Colour)
{
    if ($Colour -eq $null)
    {
        $Colour = [ConsoleColor]::White
    }
    $Details = UpdateDetailsWithCallingMethod( $Details )
    Write-Host $Details -ForegroundColor $Colour
    LogToFile $Details
}
Log "$($MyInvocation.MyCommand.Name) version $($script:ScriptVersion) starting" Green

function LogVerbose([string]$Details)
{
    Write-Verbose $Details
    #if ( !$VerboseLogFile -and !$DebugLogFile -and ($VerbosePreference -eq "SilentlyContinue") ) { return }
    LogToFile $Details
}

function LogDebug([string]$Details)
{
    Write-Debug $Details
    if (!$DebugLogFile -and ($DebugPreference -eq "SilentlyContinue") ) { return }
    LogToFile $Details
}

$script:LastError = $Error[0]
function ErrorReported($Context)
{
    # Check for any error, and return the result ($true means a new error has been detected)

    # We check for errors using $Error variable, as try...catch isn't reliable when remoting
    if ([String]::IsNullOrEmpty($Error[0])) { return $false }

    # We have an error, have we already reported it?
    if ($Error[0] -eq $script:LastError) { return $false }

    # New error, so log it and return $true
    $script:LastError = $Error[0]
    if ($Context)
    {
        Log "ERROR ($Context): $($Error[0])" Red
    }
    else
    {
        $log = UpdateDetailsWithCallingMethod("ERROR: $($Error[0])")
        Log $log Red
    }
    return $true
}

function ReportError($Context)
{
    # Reports error without returning the result
    ErrorReported $Context | Out-Null
}
#>** LOGGING FUNCTIONS END **#

#>** EWS/OAUTH FUNCTIONS START **#
function LoadLibraries()
{
    param (
        [bool]$searchProgramFiles,
        $dllNames,
        [ref]$dllLocations = @()
    )
    # Attempt to find and load the specified libraries

    foreach ($dllName in $dllNames)
    {
        # First check if the dll is in current directory
        LogDebug "Searching for DLL: $dllName"
        $dll = $null
        $dll = Get-ChildItem $dllName -ErrorAction Ignore

        if ($searchProgramFiles)
        {
            if ($dll -eq $null)
            {
	            $dll = Get-ChildItem -Recurse "C:\Program Files (x86)" -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) -and ( $_.Name -eq $dllName ) }
	            if (!$dll)
	            {
		            $dll = Get-ChildItem -Recurse "C:\Program Files" -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) -and ( $_.Name -eq $dllName ) }
	            }
            }
        }

        if ($dll -eq $null)
        {
            Log "Unable to load locate $dll" Red
            return $false
        }
        else
        {
            try
            {
		        LogVerbose ([string]::Format("Loading {2} v{0} found at: {1}", $dll.VersionInfo.FileVersion, $dll.VersionInfo.FileName, $dllName))
		        Add-Type -Path $dll.VersionInfo.FileName
                if ($dllLocations)
                {
                    $dllLocations.value += $dll.VersionInfo.FileName
                    ReportError
                }
            }
            catch
            {
                ReportError "LoadLibraries"
                return $false
            }
        }
    }
    return $true
}

function GetTokenWithCertificate
{
    # We use MSAL with certificate auth
    if (!script:msalApiLoaded)
    {
        $msalLocation = @()
        $script:msalApiLoaded = $(LoadLibraries -searchProgramFiles $false -dllNames @("Microsoft.Identity.Client.dll") -dllLocations ([ref]$msalLocation))
        if (!$script:msalApiLoaded)
        {
            Log "Failed to load MSAL.  Cannot continue with certificate authentication." Red
            exit
        }
    }   

    $cca = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($OAuthClientId)
    $cca = $cca.WithCertificate($OAuthCertificate)
    $cca = $cca.WithTenantId($OAuthTenantId)
    $cca = $cca.Build()

    $scopes = New-Object System.Collections.Generic.List[string]
    $scopes.Add("https://outlook.office365.com/.default")
    $acquire = $cca.AcquireTokenForClient($scopes)
    $authResult = $acquire.ExecuteAsync().Result
    $script:oauthToken = $authResult
    $script:oAuthAccessToken = $script:oAuthToken.AccessToken
    $script:Impersonate = $true
}

function GetTokenViaCode
{
    # Acquire auth code (needed to request token)
    $authUrl = "https://login.microsoftonline.com/$OAuthTenantId/oauth2/v2.0/authorize?client_id=$OAuthClientId&response_type=code&redirect_uri=$OAuthRedirectUri&response_mode=query&scope=openid%20profile%20email%20offline_access%20https://outlook.office365.com/.default"
    Write-Host "Please complete log-in via the web browser, and then copy the redirect URL (including auth code) to the clipboard to continue" -ForegroundColor Green
    Set-Clipboard -Value "Waiting for auth code"
    Start-Process $authUrl

    do
    {
        $authcode = Get-Clipboard
        Start-Sleep -Milliseconds 250
    } while ($authCode -eq "Waiting for auth code")

    $codeStart = $authcode.IndexOf("?code=")
    if ($codeStart -gt 0)
    {
        $authcode = $authcode.Substring($codeStart+6)
        $codeEnd = $authcode.IndexOf("&session_state=")
        if ($codeEnd -gt 0)
        {
            $authcode = $authcode.Substring(0, $codeEnd)
        }
        Write-Verbose "Using auth code: $authcode"
    }
    else
    {
        throw "Failed to obtain Auth code from clipboard"
    }

    # Acquire token (using the auth code)
    $body = @{grant_type="authorization_code";scope="https://outlook.office365.com/.default";client_id=$OAuthClientId;code=$authcode;redirect_uri=$OAuthRedirectUri}
    try
    {
        $script:oauthToken = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$OAuthTenantId/oauth2/v2.0/token -Body $body
        $script:oAuthAccessToken = $script:oAuthToken.access_token
        $script:oauthTokenAcquireTime = [DateTime]::UtcNow
        return
    }
    catch {}

    throw "Failed to obtain OAuth token"
}

function RenewOAuthToken
{
    # Renew the delegate token (original token was obtained by auth code, but we can now renew using the access token)
    if (!$script:oAuthToken)
    {
        # We don't have a token, so we can't renew
        GetTokenViaCode
        return
    }

    $body = @{grant_type="refresh_token";scope="https://outlook.office365.com/.default";client_id=$OAuthClientId;refresh_token=$script:oauthToken.refresh_token}
    try
    {
        $script:oauthToken = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$OAuthTenantId/oauth2/v2.0/token -Body $body
        $script:oAuthAccessToken = $script:oAuthToken.access_token
        $script:oauthTokenAcquireTime = [DateTime]::UtcNow
    }
    catch
    {
        Write-Host "Failed to renew OAuth token (auth code grant)" -ForegroundColor Red
        exit # Failed to obtain a token
    }
}

function GetTokenWithKey
{
    $Body = @{
      "grant_type"    = "client_credentials";
      "client_id"     = "$OAuthClientId";
      "scope"         = "https://outlook.office365.com/.default"
    }

    if ($script:oAuthToken -ne $null)
    {
        # If we have a refresh token, add that to our request body and change grant type
        if (![String]::IsNullOrEmpty($script:oAuthToken.refresh_token))
        {
            $Body.Add("refresh_token", $script:oAuthToken.refresh_token)
            $Body["grant_type"] = "refresh_token"
        }
    }
    if ($Body["grant_type"] -eq "client_credentials")
    {
        # To obtain our first access token we need to use the secret key
        $Body.Add("client_secret", $OAuthSecretKey)
    }

    try
    {
        $script:oAuthToken = Invoke-RestMethod -Method POST -uri "https://login.microsoftonline.com/$OAuthTenantId/oauth2/v2.0/token" -Body $body
        $script:oAuthAccessToken = $script:oAuthToken.access_token
        $script:oauthTokenAcquireTime = [DateTime]::UtcNow
    }
    catch
    {
        Log "Failed to obtain OAuth token: $Error" Red
        exit # Failed to obtain a token
    }
    $script:Impersonate = $true
}

function JWTToPSObject
{
    param([Parameter(Mandatory=$true)][string]$token)

    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
    while ($tokenheader.Length % 4) { $tokenheader = "$tokenheader=" }    
    $tokenHeaderObject = [System.Text.Encoding]::UTF8.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json

    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { $tokenPayload = "$tokenPayload=" }
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArray = [System.Text.Encoding]::UTF8.GetString($tokenByteArray)
    $tokenObject = $tokenArray | ConvertFrom-Json
    return $tokenObject
}

function LogOAuthTokenInfo
{
    if ($global:OAuthResponse -eq $null)
    {
        Log "No OAuth token obtained." Red
        return
    }

    if ([String]::IsNullOrEmpty($global:OAuthResponse.id_token))
    {
        Log "OAuth ID Token not present" Yellow
    }
    else
    {
        $global:idTokenDecoded = JWTToPSObject($global:OAuthResponse.id_token)
        Log "OAuth ID Token (`$idTokenDecoded):" Yellow
        Log $global:idTokenDecoded Yellow
    }

    $global:accessTokenDecoded = JWTToPSObject($global:OAuthResponse.access_token)
    Log "OAuth Access Token (`$accessTokenDecoded):" Yellow
    Log $global:accessTokenDecoded Yellow
}

function GetOAuthCredentials
{
    # Obtain OAuth token for accessing mailbox
    param (
        [switch]$RenewToken
    )
    $exchangeCredentials = $null

    if ($script:oauthToken -ne $null)
    {
        # We already have a token
        if ($script:oauthTokenAcquireTime.AddSeconds($script:oauthToken.expires_in) -gt [DateTime]::UtcNow.AddMinutes(1))
        {
            # Token still valid, so return that
            $exchangeCredentials = New-Object Microsoft.Exchange.WebServices.Data.OAuthCredentials($script:oAuthAccessToken)
            return $exchangeCredentials
        }
        # Token needs renewing
    }

    if (![String]::IsNullOrEmpty($OAuthSecretKey))
    {
        GetTokenWithKey
    }
    elseif ($OAuthCertificate -ne $null)
    {
        GetTokenWithCertificate
    }
    else
    {
        if ($RenewToken)
        {
            RenewOAuthToken
        }
        else
        {
            if ($GlobalTokenStorage -and $script:oauthToken -eq $null)
            {
                # Check if we have token variable set globally
                if ($global:oAuthPersistAppId -eq $OAuthClientId)
                {
                    $script:oAuthToken = $global:oAuthPersistToken
                    $script:oauthTokenAcquireTime = $global:oAuthPersistTokenAcquireTime
                }
                RenewOAuthToken
            }
            else
            {
                GetTokenViaCode
            }
        }
    }

    if ($GlobalTokenStorage -or $OAuthDebug)
    {
        # Store the OAuth in a global variable for later access
        $global:oAuthPersistToken = $script:oAuthToken
        $global:oAuthPersistAppId = $OAuthClientId
        $global:oAuthPersistTokenAcquireTime = $script:oauthTokenAcquireTime
    } 

    if ($OAuthDebug)
    {
        LogVerbose "`$oAuthPersistToken contains token response"
        $global:OAuthAccessToken = $script:oAuthAccessToken
        LogVerbose "`$OAuthAccessToken: `r`n$($global:OAuthAccessToken)"
        LogOAuthTokenInfo
    }

   

    # If we get here we have a valid token
    $exchangeCredentials = New-Object Microsoft.Exchange.WebServices.Data.OAuthCredentials($script:oAuthAccessToken)
    return $exchangeCredentials
}

$script:oAuthDebugStop = $false
$script:oAuthDebugStopCount = 0
function ApplyEWSOAuthCredentials
{
    # Apply EWS OAuth credentials to all our service objects

    if ( $script:services -eq $null ) { return }

    
    if ($DebugTokenRenewal -gt 0 -and $script:oauthToken)
    {
        # When debugging tokens, we stop after on every other EWS call and wait for the token to expire
        if ($script:oAuthDebugStop)
        {
            # Wait until token expires (we do this after every call when debugging OAuth)
            # Access tokens can't be revoked, but a policy can be assigned to reduce lifetime to 10 minutes: https://learn.microsoft.com/en-us/graph/api/resources/tokenlifetimepolicy?view=graph-rest-1.0
            if ($OAuthCertificate -ne $null)
            {
                $tokenExpire = $script:oauthToken.ExpiresOn.UtcDateTime
            }
            else
            {
                $tokenExpire = $script:oauthTokenAcquireTime.AddSeconds($script:oauthToken.expires_in)
            }
            $timeUntilExpiry = $tokenExpire.Subtract([DateTime]::UtcNow).TotalSeconds
            if ($timeUntilExpiry -gt 0)
            {
                Write-Host "Waiting until token has expired: $tokenExpire (UTC)" -ForegroundColor Cyan
                Start-Sleep -Seconds $tokenExpire.Subtract([DateTime]::UtcNow).TotalSeconds
            }
            Write-Host "Token expired, continuing..." -ForegroundColor Cyan
            $oAuthDebugStop = $false
            $script:oAuthDebugStopCount++
        }
        else
        {
            if ($DebugTokenRenewal-$script:oAuthDebugStopCount -gt 0)
            {
                $script:oAuthDebugStop = $true
            }
        }
    }
    
    if ($OAuthCertificate -ne $null)
    {
        if ( [DateTime]::UtcNow -ge $script:oauthToken.ExpiresOn.UtcDateTime) { return }
    }
    elseif ($script:oauthTokenAcquireTime.AddSeconds($script:oauthToken.expires_in) -gt [DateTime]::UtcNow.AddMinutes(1)) { return }

    # The token has expired and needs refreshing
    LogVerbose("[ApplyEWSOAuthCredentials] OAuth access token invalid, attempting to renew")
    $exchangeCredentials = GetOAuthCredentials -RenewToken
    if ($exchangeCredentials -eq $null) { return }

    if ($OAuthCertificate -ne $null)
    {
        $tokenExpire = $script:oauthToken.ExpiresOn.UtcDateTime
        if ( [DateTime]::UtcNow -ge $tokenExpire)
        {
            Log "[ApplyEWSOAuthCredentials] OAuth Token renewal failed (certificate auth)"
            exit # We no longer have access to the mailbox, so we stop here
        }
    }
    else
    {
        if ( $script:oauthTokenAcquireTime.AddSeconds($script:oauthToken.expires_in) -lt [DateTime]::UtcNow )
        { 
            Log "[ApplyEWSOAuthCredentials] OAuth Token renewal failed"
            exit # We no longer have access to the mailbox, so we stop here
        }
        $tokenExpire = $script:oauthTokenAcquireTime.AddSeconds($script:oauthToken.expires_in)
    }

    Log "[ApplyEWSOAuthCredentials] OAuth token successfully renewed; new expiry: $tokenExpire"
    if ($script:services.Count -gt 0)
    {
        foreach ($service in $script:services.Values)
        {
            $service.Credentials = $exchangeCredentials
        }
        LogVerbose "[ApplyEWSOAuthCredentials] Updated OAuth token for $($script.services.Count) ExchangeService object(s)"
    }
}

function LoadEWSManagedAPI
{
	# Find and load the managed API
    $ewsApiLocation = @()
    $ewsApiLoaded = $(LoadLibraries -searchProgramFiles $true -dllNames @("Microsoft.Exchange.WebServices.dll") -dllLocations ([ref]$ewsApiLocation))
    ReportError "LoadEWSManagedAPI"

    if (!$ewsApiLoaded)
    {
        # Failed to load the EWS API, so try to install it from Nuget
        $ewsapi = Find-Package "Exchange.WebServices.Managed.Api"
        if ($ewsapi.Entities.Name.Equals("Microsoft"))
        {
	        # We have found EWS API package, so install as current user (confirm with user first)
	        Write-Host "EWS Managed API is not installed, but is available from Nuget.  Install now for current user (required for this script to continue)? (Y/n)" -ForegroundColor Yellow
	        $response = Read-Host
	        if ( $response.ToLower().Equals("y") )
	        {
		        Install-Package $ewsapi -Scope CurrentUser -Force
                $ewsApiLoaded = $(LoadLibraries -searchProgramFiles $true -dllNames @("Microsoft.Exchange.WebServices.dll") -dllLocations ([ref]$ewsApiLocation))
                ReportError "LoadEWSManagedAPI"
	        }
        }
    }

    if ($ewsApiLoaded)
    {
        if ($ewsApiLocation[0])
        {
            Log "Using EWS Managed API found at: $($ewsApiLocation[0])" Gray
            $script:EWSManagedApiPath = $ewsApiLocation[0]
        }
        else
        {
            Write-Host "Failed to read EWS API location: $ewsApiLocation"
            exit
        }
    }

    return $ewsApiLoaded
}

function CurrentUserPrimarySmtpAddress()
{
    # Attempt to retrieve the current user's primary SMTP address
    $searcher = [adsisearcher]"(samaccountname=$env:USERNAME)"
    $result = $searcher.FindOne()

    if ($result -ne $null)
    {
        $mail = $result.Properties["mail"]
        LogDebug "Current user's SMTP address is: $mail"
        return $mail
    }
    return $null
}

function CreateTraceListener($service)
{
    # Create trace listener to capture EWS conversation (useful for debugging)

    if ([String]::IsNullOrEmpty($EWSManagedApiPath))
    {
        Log "Managed API path missing; unable to create tracer" Red
        exit
    }

    if ($script:Tracer -eq $null)
    {
        $traceFileForCode = ""

        $Provider=New-Object Microsoft.CSharp.CSharpCodeProvider
        $Params=New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable=$False
        $Params.GenerateInMemory=$True
        $Params.IncludeDebugInformation=$False
	    $Params.ReferencedAssemblies.Add("System.dll") | Out-Null
        $Params.ReferencedAssemblies.Add($EWSManagedApiPath) | Out-Null

        $traceFileForCode = $traceFile.Replace("\", "\\")

        if (![String]::IsNullOrEmpty($TraceFile))
        {
            Log "Tracing to: $TraceFile"
        }

        $TraceListenerClass = @"
		    using System;
		    using System.Text;
		    using System.IO;
		    using System.Threading;
		    using Microsoft.Exchange.WebServices.Data;
		
            namespace TraceListener {
		        class EWSTracer: Microsoft.Exchange.WebServices.Data.ITraceListener
		        {
			        private StreamWriter _traceStream = null;
                    private string _lastResponse = String.Empty;

			        public EWSTracer()
			        {
				        try
				        {
					        _traceStream = File.AppendText("$traceFileForCode");
				        }
				        catch { }
			        }

			        ~EWSTracer()
			        {
                        CloseStream();
			        }

                    public void CloseStream()
			        {
				        try
				        {
					        _traceStream.Flush();
					        _traceStream.Close();
				        }
				        catch { }
			        }


			        public void Trace(string traceType, string traceMessage)
			        {
                        if ( traceType.Equals("EwsResponse") )
                            _lastResponse = traceMessage;

                        if ( traceType.Equals("EwsRequest") )
                            _lastResponse = String.Empty;

				        if (_traceStream == null)
					        return;

				        lock (this)
				        {
					        try
					        {
						        _traceStream.WriteLine(traceMessage);
						        _traceStream.Flush();
					        }
					        catch { }
				        }
			        }

                    public string LastResponse
                    {
                        get { return _lastResponse; }
                    }
		        }
            }
"@

        $TraceCompilation=$Provider.CompileAssemblyFromSource($Params,$TraceListenerClass)
        $TraceAssembly=$TraceCompilation.CompiledAssembly
        $script:Tracer=$TraceAssembly.CreateInstance("TraceListener.EWSTracer")

        # Attach the trace listener to the Exchange service
        $service.TraceListener = $script:Tracer
    }
}

function CreateService($smtpAddress, $impersonatedAddress = "")
{
    # Creates and returns an ExchangeService object to be used to access mailboxes

    # First of all check to see if we have a service object for this mailbox already
    if ($script:services -eq $null)
    {
        $script:services = @{}
    }
    if ($script:services.ContainsKey($smtpAddress))
    {
        return $script:services[$smtpAddress]
    }

    # Create new service
    $exchangeService = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP2)

    $exchangeService.Credentials = GetOAuthCredentials
    if ($exchangeService.Credentials -eq $null)
        {
            # OAuth failed
            return $null
    }
    
    # Set EWS URL for Exchange Online.
    $EwsUrl = "https://outlook.office365.com/EWS/Exchange.asmx"
    $exchangeService.URL = New-Object Uri($EwsUrl)
    
    
    if ([String]::IsNullOrEmpty($impersonatedAddress))
    {
        $impersonatedAddress = $smtpAddress
    }
    #$exchangeService.HttpHeaders.Add("X-AnchorMailbox", $smtpAddress)
    if ($Impersonate)
    {
		$exchangeService.ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $impersonatedAddress)
	}

    # We enable tracing so that we can retrieve the last response (and read any throttling information from it - this isn't exposed in the EWS Managed API)
    if (![String]::IsNullOrEmpty($EWSManagedApiPath))
    {
        #CreateTraceListener $exchangeService
        if ($script:Tracer)
        {
            $exchangeService.TraceListener = $script:Tracer
            $exchangeService.TraceFlags = [Microsoft.Exchange.WebServices.Data.TraceFlags]::All
            $exchangeService.TraceEnabled = $True
        }
        else
        {
            Log "Failed to create EWS trace listener.  Throttling back-off time won't be detected." Yellow
        }
    }

    $script:services.Add($smtpAddress, $exchangeService)
    LogVerbose "Currently caching $($script:services.Count) ExchangeService objects" $true
    return $exchangeService
}

#>** EWS/OAUTH FUNCTIONS END **#

function EWSPropertyType($MAPIPropertyType)
{
    # Return the EWS property type for the given MAPI Property value

    switch ([Convert]::ToInt32($MAPIPropertyType,16))
    {
        0x0    { return $Null }
        0x1    { return $Null }
        0x2    { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Short }
        0x1002 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::ShortArray }
        0x3    { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Integer }
        0x1003 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::IntegerArray }
        0x4    { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Float }
        0x1004 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::FloatArray }
        0x5    { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Double }
        0x1005 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::DoubleArray }
        0x6    { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Currency }
        0x1006 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::CurrencyArray }
        0x7    { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::ApplicationTime }
        0x1007 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::ApplicationTimeArray }
        0x0A   { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Error }
        0x0B   { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Boolean }
        0x0D   { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Object }
        0x100D { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::ObjectArray }
        0x14   { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Long }
        0x1014 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::LongArray }
        0x1E   { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::String }
        0x101E { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::StringArray }
        0x1F   { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::String }
        0x101F { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::StringArray }
        0x40   { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::SystemTime }
        0x1040 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::SystemTimeArray }
        0x48   { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::CLSID }
        0x1048 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::CLSIDArray }
        0x102  { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Binary }
        0x1102 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::BinaryArray }
    }
    Write-Verbose "Couldn't match MAPI property type"
    return $Null
}

function InitPropList()
{
    # We need to convert the properties to EWS extended properties
    if ($script:itemPropsEws -eq $Null)
    {
        Write-Verbose "Building list of properties to retrieve"
        $script:property = @()
        foreach ($property in $ViewProperties)
        {
            $propdef = $null

            if ($property.StartsWith("{"))
            {
                # Property definition starts with a GUID, so we expect one of these:
                # {GUID}/name/mapiType - named property
                # {GUID]/id/mapiType   - MAPI property (shouldn't be used when accessing named properties)

                $propElements = $property -Split "/"
                if ($propElements.Length -eq 2)
                {
                    # We expect three elements, but if there are two it most likely means that the MAPI property Id includes the Mapi type
                    if ($propElements[1].Length -eq 8)
                    {
                        $propElements += $propElements[1].Substring(4)
                        $propElements[1] = [Convert]::ToInt32($propElements[1].Substring(0,4),16)
                    }
                }
                $guid = New-Object Guid($propElements[0])
                $propType = EWSPropertyType($propElements[2])

                try
                {
                    $propdef = New-Object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition($guid, $propElements[1], $propType)
                }
                catch {}
            }
            else
            {
                # Assume MAPI property
                if ($property.ToLower().StartsWith("0x"))
                {
                    $property = $deleteProperty.SubString(2)
                }
                $propId = [Convert]::ToInt32($deleteProperty.SubString(0,4),16)
                $propType = EWSPropertyType($deleteProperty.SubString(5))

                try
                {
                    $propdef = New-Object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition($propId, $propType)
                }
                catch {}
            }

            if ($propdef -ne $Null)
            {
                $script:property += $propdef
                Write-Verbose "Added property $property to list of those to retrieve"
            }
            else
            {
                Log "Failed to parse (or convert) property $property" Red
            }
        }
    }
}

$script:excludedProperties = @("Schema","Service","IsDirty","IsAttachment","IsNew")

$script:itemRetryCount = @{}
function RemoveProcessedItemsFromList()
{
    # Process the results of a batch move/copy and remove any items that were successfully moved from our list of items to move
    param (
        $requestedItems,
        $results,
        $suppressErrors = $false,
        $Items
    )

    if ($results -ne $null)
    {
        $failed = 0
        for ($i = 0; $i -lt $requestedItems.Count; $i++)
        {
            if ($results[$i].ErrorCode -eq "NoError")
            {
                LogVerbose "Item successfully processed: $($requestedItems[$i])"
                [void]$Items.Remove($requestedItems[$i])
            }
            else
            {
                if ( ($results[$i].ErrorCode -eq "ErrorMoveCopyFailed") -or ($results[$i].ErrorCode -eq "ErrorInvalidOperation") -or ($results[$i].ErrorCode -eq "ErrorItemNotFound") )
                {
                    # This is a permanent error, so we remove the item from the list
                    [void]$Items.Remove($requestedItems[$i])
                    if (!$suppressErrors)
                    {
                        Log "Permanent error $($results[$i].ErrorCode) ($($results[$i].MessageText)) reported for item: $($requestedItems[$i].UniqueId)" Red
                    }
                }
                else
                {
                    # This is most likely a temporary error, so we don't remove the item from the list
                    $retryCount = 0
                    if ( $script:itemRetryCount.ContainsKey($requestedItems[$i].UniqueId) )
                        { $retryCount = $script:itemRetryCount[$requestedItems[$i].UniqueId] }
                    $retryCount++
                    if ($retryCount -lt 4)
                    {
                        LogVerbose "Error $($results[$i].ErrorCode) ($($results[$i].MessageText)) reported for item (attempt $retryCount): $($requestedItems[$i].UniqueId)"
                        $script:itemRetryCount[$requestedItems[$i].UniqueId] = $retryCount
                    }
                    else
                    {
                        # We got an error 3 times in a row, so we'll admit defeat
                        [void]$Items.Remove($requestedItems[$i])
                        if (!$suppressErrors)
                        {
                            Log "Permanent error $($results[$i].ErrorCode) ($($results[$i].MessageText)) reported for item: $($requestedItems[$i].UniqueId)" Red
                        }
                    }
                }
                $failed++
            } 
        }
    }
    if ( ($failed -gt 0) -and !$suppressErrors )
    {
        Log "$failed items reported error during batch request (if throttled, some failures are expected)" Yellow
    }
}

function ThrottledBatchDelete()
{
    # Send request to move/copy items, allowing for throttling
    param (
        $ItemsToDelete,
        $BatchSize = 200,
        $SuppressNotFoundErrors = $false
    )

    if ($script:MaxBatchSize -gt 0)
    {
        # If we've had to reduce the batch size previously, we'll start with the last size that was successful
        $BatchSize = $script:MaxBatchSize
    }

    if ($HardDelete)
    {
        $deleteMode = [Microsoft.Exchange.WebServices.Data.DeleteMode]::HardDelete
    }
    else {
        $deleteMode = [Microsoft.Exchange.WebServices.Data.DeleteMode]::SoftDelete
    }

    $progressActivity = "Deleting items"
	$itemId = New-Object Microsoft.Exchange.WebServices.Data.ItemId("xx")
	$itemIdType = [Type] $itemId.GetType()
	$genericItemIdList = [System.Collections.Generic.List``1].MakeGenericType(@($itemIdType))
    
    $finished = $false
    $totalItems = $ItemsToDelete.Count
    Write-Progress -Activity $progressActivity -Status "0% complete" -PercentComplete 0

    $consecutiveErrors = 0

    while ( !$finished )
    {
	    $deleteIds = [Activator]::CreateInstance($genericItemIdList)
        
        for ([int]$i=0; $i -lt $BatchSize; $i++)
        {
            if ($ItemsToDelete[$i] -ne $null)
            {
                $deleteIds.Add($ItemsToDelete[$i])
            }
            if ($i -ge $ItemsToDelete.Count)
                { break }
        }

        $results = $null
        try
        {
            LogVerbose "Sending batch request to delete $($deleteIds.Count) items ($($ItemsToDelete.Count) remaining)"

			$results = $script:service.DeleteItems( $deleteIds, $deleteMode, [Microsoft.Exchange.WebServices.Data.SendCancellationsMode]::SendToNone, $null )
            $consecutiveErrors = 0 # Reset the consecutive error count, as if we reach this point then this request succeeded with no error
        }
        catch
        {
            # We reduce the batch size if we encounter an error (sometimes throttling does not return a throttled response, this can happen if the EWS request is proxied, and the proxied request times out)
            if ($BatchSize -gt 50)
            {
                $BatchSize = [int]($BatchSize * 0.8)
                $script:MaxBatchSize = $BatchSize
                LogVerbose "Batch size reduced to $BatchSize"
            }
            else
            {
                # If we've already reached a batch size of 50 or less, we set it to 10 (this is the minimum we reduce to)
                if ($BatchSize -ne 10)
                {
                    $BatchSize = 10
                    LogVerbose "Batch size set to 10"
                }
            }
            if ( -not (Throttled) )
            {
                $consecutiveErrors++
                try
                {
                    Log "Unexpected error: $($Error[0].Exception.InnerException.ToString())" Red
                }
                catch
                {
                    Log "Unexpected error: $($Error[1])" Red
                }
                $finished = ($consecutiveErrors -gt 9) # If we have 10 errors in a row, we stop processing
            }
        }

        RemoveProcessedItemsFromList $deleteIds $results $SuppressNotFoundErrors $ItemsToDelete

        $percentComplete = ( ($totalItems - $ItemsToDelete.Count) / $totalItems ) * 100
        Write-Progress -Activity $progressActivity -Status "$percentComplete% complete" -PercentComplete $percentComplete

        if ($ItemsToDelete.Count -eq 0)
        {
            $finished = $True
        }
    }
    Write-Progress -Activity $progressActivity -Status "Complete" -Completed
}

function InitLists()
{
	$genericItemIdList = [System.Collections.Generic.List``1].MakeGenericType([Microsoft.Exchange.WebServices.Data.ItemId])
    $script:ItemsToDelete = [Activator]::CreateInstance($genericItemIdList)
}

function ProcessItem( $item )
{
	# We have found an item, so this function handles any processing

    # Load any additional requested properties (will only happen if $ViewProperties was set)
    if ($script:itemPropsEws)
    {
        $propset = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::FirstClassProperties)
        if ($script:itemPropsEws.Length -gt 0)
        {
            # We have additional properties to retrieve, so we reload the item asking for first class properties and all the additional ones
            $propset = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::FirstClassProperties, $script:itemPropsEws)
        }
        $item.Load($propset)
    }

    if ( -not (ItemMatchesRecipientRequirements($item) ) ) { return }
    $itemResult = New-Object PSObject -Property @{ InternetMessageId=$item.InternetMessageId; Sender=$item.Sender;ReceivedBy=$item.ReceivedBy;Id=$item.Id;ItemClass=$item.ItemClass;Subject=$item.Subject;DateTimeCreated=$item.DateTimeCreated};
    $itemResult | Export-Csv -Path $ResultsFile -NoTypeInformation -Append
    if ($DeleteContent)
	{
		LogVerbose "Adding item to delete list: $($item.Subject)"
        $script:ItemsToDelete.Add($item.Id)
        return # If we are deleting an item, then no other updates are relevant
	}

}

function GetFolder()
{
	# Return a reference to a folder specified by path
	
	$RootFolder, $FolderPath, $Create = $args[0]
	
    if ( $RootFolder -eq $null )
    {
        LogVerbose "GetFolder called with null root folder"
        return $null
    }

    if ($FolderPath.ToLower().StartsWith("wellknownfoldername"))
    {
        # Well known folder, so bind to it directly
        $wkf = $FolderPath.SubString(20)
        LogVerbose "Attempting to bind to well known folder: $wkf"
        $folderId = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::$wkf, $mbx )
        $Folder = ThrottledFolderBind($folderId)
        return $Folder
    }

	$Folder = $RootFolder
	if ($FolderPath -ne '\')
	{
		$PathElements = $FolderPath -split '\\'
		for ($i=0; $i -lt $PathElements.Count; $i++)
		{
			if ($PathElements[$i])
			{
				$View = New-Object  Microsoft.Exchange.WebServices.Data.FolderView(2,0)
				$View.PropertySet = [Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly
						
				$SearchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName, $PathElements[$i])
				
                $FolderResults = $Null
                try
                {
				    $FolderResults = $Folder.FindFolders($SearchFilter, $View)
                }
                catch {}
                if ($FolderResults -eq $Null)
                {
                    if (Throttled)
                    {
                        try
                        {
				            $FolderResults = $Folder.FindFolders($SearchFilter, $View)
                        }
                        catch {}
                    }
                }
                if ($FolderResults -eq $null)
                {
                    return $null
                }

				if ($FolderResults.TotalCount -gt 1)
				{
					# We have more than one folder returned... We shouldn't ever get this, as it means we have duplicate folders
					$Folder = $null
					Write-Host "Duplicate folders ($($PathElements[$i])) found in path $FolderPath" -ForegroundColor Red
					break
				}
                elseif ( $FolderResults.TotalCount -eq 0 )
                {
                    if ($Create)
                    {
                        # Folder not found, so attempt to create it
					    $subfolder = New-Object Microsoft.Exchange.WebServices.Data.Folder($RootFolder.Service)
					    $subfolder.DisplayName = $PathElements[$i]
                        try
                        {
					        $subfolder.Save($Folder.Id)
                            LogVerbose "Created folder $($PathElements[$i])"
                        }
                        catch
                        {
					        # Failed to create the subfolder
					        $Folder = $null
					        Log "Failed to create folder $($PathElements[$i]) in path $FolderPath" Red
					        break
                        }
                        $Folder = $subfolder
                    }
                    else
                    {
					    # Folder doesn't exist
					    $Folder = $null
					    Log "Folder $($PathElements[$i]) doesn't exist in path $FolderPath" Red
					    break
                    }
                }
                else
                {
				    $Folder = ThrottledFolderBind $FolderResults.Folders[0].Id $null $RootFolder.Service
                }
			}
		}
	}
	
	$Folder
}

function SearchMailbox()
{
    

	$script:service = CreateService($Mailbox)
    if ( $script:service -eq $null) { return }

	# Set our root folder
    if ($Archive)  {
        Log([string]::Format("Processing archive mailbox for {0}", $Mailbox)) Gray
        if($SearchDumpster) 
        {
            $ProcessSubfolders = $True
            $rootFolderId = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::ArchiveRecoverableItemsRoot
        }
        else {
            $rootFolderId = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::ArchiveMsgFolderRoot
        }
    }
    else {
        Log ([string]::Format("Processing mailbox {0}", $Mailbox)) Gray
        if($SearchDumpster) {
            $ProcessSubfolders = $True
            $rootFolderId = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::RecoverableItemsRoot
        }
        else {
            $rootFolderId = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot
        }
    }
    $script:service.HttpHeaders.Add("X-AnchorMailbox",$Mailbox)
    
    InitPropList

    if (!($IncludeFolderList))
    {
        # No folders specified to search, so we use default
        $FolderId = New-Object Microsoft.Exchange.WebServices.Data.FolderId( $rootFolderId )
	    SearchFolder $FolderId
    }
    else
    {
        # We are searching specific folders
        $rootFolder = ThrottledFolderBind $rootFolderId
        foreach ($includedFolder in $IncludeFolderList)
        {
            $folder = $null
            $folder = GetFolder($rootFolder, $includedFolder, $false)

            if ($folder)
            {
                $folderPath = GetFolderPath($folder)
                Log "Starting search in: $folderPath"                
	            SearchFolder $folder.Id
            }
        }
    }
}

function Throttled()
{
    # Checks if we've been throttled.  If we have, we wait for the specified number of BackOffMilliSeconds before returning

    if ([String]::IsNullOrEmpty($script:Tracer.LastResponse))
    {
        return $false # Throttling does return a response, if we don't have one, then throttling probably isn't the issue (though sometimes throttling just results in a timeout)
    }

    $lastResponse = $script:Tracer.LastResponse.Replace("<?xml version=`"1.0`" encoding=`"utf-8`"?>", "")
    $lastResponse = "<?xml version=`"1.0`" encoding=`"utf-8`"?>$lastResponse"
    $responseXml = [xml]$lastResponse

    if ($responseXml.Trace.Envelope.Body.Fault.detail.MessageXml.Value.Name -eq "BackOffMilliseconds")
    {
        # We are throttled, and the server has told us how long to back off for
        Log "Throttling detected, server requested back off for $($responseXml.Trace.Envelope.Body.Fault.detail.MessageXml.Value."#text") milliseconds" Yellow
        Start-Sleep -Milliseconds $responseXml.Trace.Envelope.Body.Fault.detail.MessageXml.Value."#text"
        Log "Throttling budget should now be reset, resuming operations" Gray
        return $true
    }
    return $false
}

function ThrottledFolderBind()
{
    param (
        [Microsoft.Exchange.WebServices.Data.FolderId]$folderId,
        $propset = $null,
        $exchangeService = $null)

    LogVerbose "Attempting to bind to folder $folderId"
    $folder = $null
    if ($exchangeService -eq $null)
    {
        $exchangeService = $script:service
    }

    try
    {
        if ($propset -eq $null)
        {
            $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchangeService, $folderId)
        }
        else
        {
            $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchangeService, $folderId, $propset)
        }
        if (!($folder -eq $null))
        {
            LogVerbose "Successfully bound to folder $folderId"
        }
        return $folder
    }
    catch {}

    if (Throttled)
    {
        try
        {
            if ($propset -eq $null)
            {
                $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchangeService, $folderId)
            }
            else
            {
                $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchangeService, $folderId, $propset)
            }
            if (!($folder -eq $null))
            {
                LogVerbose "Successfully bound to folder $folderId"
            }
            return $folder
        }
        catch {}
    }

    # If we get to this point, we have been unable to bind to the folder
    LogVerbose "FAILED to bind to folder $folderId"
    return $null
}

function GetFolderPath($Folder)
{
    # Return the full path for the given folder

    # We cache our folder lookups for this script
    if (!$script:folderCache)
    {
        # Note that we can't use a PowerShell hash table to build a list of folder Ids, as the hash table is case-insensitive
        # We use a .Net Dictionary object instead
        $script:folderCache = New-Object 'System.Collections.Generic.Dictionary[System.String,System.Object]'
    }

    $propset = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly, [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName, [Microsoft.Exchange.WebServices.Data.FolderSchema]::ParentFolderId)
    $parentFolder = ThrottledFolderBind $Folder.Id $propset $Folder.Service
    $folderPath = $Folder.DisplayName
    $parentFolderId = $Folder.Id
    while ($parentFolder.ParentFolderId -ne $parentFolderId)
    {
        if ($script:folderCache.ContainsKey($parentFolder.ParentFolderId.UniqueId))
        {
            try
            {
                $parentFolder = $script:folderCache[$parentFolder.ParentFolderId.UniqueId]
            }
            catch {}
        }
        else
        {
            $parentFolder = ThrottledFolderBind $parentFolder.ParentFolderId $propset $Folder.Service
            $script:FolderCache.Add($parentFolder.Id.UniqueId, $parentFolder)
        }
        $folderPath = $parentFolder.DisplayName + "\" + $folderPath
        $parentFolderId = $parentFolder.Id
    }
    return $folderPath
}

function GetWellKnownFolderPath($WellKnownFolder)
{
    if (!$script:wellKnownFolderCache)
    {
        $script:wellKnownFolderCache = @{}
    }

    if ($script:wellKnownFolderCache.ContainsKey($WellKnownFolder))
    {
        return $script:wellKnownFolderCache[$WellKnownFolder]
    }

    $folder = $null
    $folderPath = $null
    $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($script:service,$WellKnownFolder)
    if ($folder)
    {
        $folderPath = GetFolderPath($folder)
        LogVerbose "GetWellKnownFolderPath: Path for $($WellKnownFolder): $folderPath"
    }
    $script:wellKnownFolderCache.Add($WellKnownFolder, $folderPath)
    return $folderPath
}

function IsFolderExcluded()
{
    # Return $true if folder is in the excluded list

    param ($folderPath)

    # To support localisation, we need to handle WellKnownFolderName enumeration
    # We do this by putting all our excluded folders into a hash table, and checking that we have the full path for any well known folders (which we retrieve from the mailbox)
    if ($script:excludedFolders -eq $null)
    {
        # Create and build our hash table
        $script:excludedFolders = @{}

        if ($ExcludeFolderList)
        {
            LogVerbose "Building folder exclusion list"#: $($ExcludeFolderList -join ',')"
            foreach ($excludedFolder in $ExcludeFolderList)
            {
                $excludedFolder = $excludedFolder.ToLower()
                $wkfStart = $excludedFolder.IndexOf("wellknownfoldername")
                LogVerbose "Excluded folder: $excludedFolder"
                if ($wkfStart -ge 0)
                {
                    # Replace the well known folder name with its full path
                    $wkfEnd = $excludedFolder.IndexOf("\", $wkfStart)-1
                    if ($wkfEnd -lt 0) { $wkfEnd = $excludedFolder.Length }
                    $wkf = $null
                    $wkf = $excludedFolder.SubString($wkfStart+20, $wkfEnd - $wkfStart - 19)
                    
                    $wellKnownFolder = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::$wkf
                    $wellKnownFolderPath = GetWellKnownFolderPath($wellKnownFolder)

                    $excludedFolder = $excludedFolder.Substring(0, $wkfStart) + $wellKnownFolderPath + $excludedFolder.Substring($wkfEnd+1)
                    LogVerbose "Path of excluded folder: $excludedFolder"
                }
                $script:excludedFolders.Add($excludedFolder, $null)
            }
        }
    }

    return $script:excludedFolders.ContainsKey($folderPath.ToLower())
}

function ItemMatchesRecipientRequirements($item)
{
    if ([string]::IsNullOrEmpty($Recipient))
    {
        return $true
    }
    if (![string]::IsNullOrEmpty($item.ReceivedBy))
    {
                if($Item.ReceivedBy -like "*$Recipient*") {
                    LogVerbose([string]::Format("Found messages that contains the recipient: {0}.", $Recipient))
                    return $true
                }
                else {
                    return $False
                }
    }
}

function SearchFolder( $FolderId )
{
	# Bind to the folder and show which one we are processing
    $folder = $null
    try
    {
	    $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($script:service,$FolderId)
    }
    catch {}
    ReportError "SearchFolder"
    if ($folder -eq $null) { return }

    $folderPath = GetFolderPath($folder)

    if (IsFolderExcluded($folderPath))
    {
        Log "Folder excluded: $folderPath"
        return
    }
	Log "Processing folder: $folderPath"
    InitLists

	# Search the folder for any matching items
	$pageSize = 1000 # We will get details for up to 1000 items at a time
	$moreItems = $true

    # Configure ItemView
    $view = New-Object Microsoft.Exchange.WebServices.Data.ItemView($pageSize, $offset, [Microsoft.Exchange.WebServices.Data.OffsetBasePoint]::Beginning)
    $view.PropertySet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,
        [Microsoft.Exchange.WebServices.Data.ItemSchema]::Subject,
        [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::Sender)
    $view.Offset = 0
	$view.Traversal = [Microsoft.Exchange.WebServices.Data.ItemTraversal]::Shallow
    
    $filters = @()

    if (![String]::IsNullOrEmpty($MessageClass))
    {
	    $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.ItemSchema]::ItemClass, $MessageClass)
    }

    if (![String]::IsNullOrEmpty($Subject))
    {
        $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring([Microsoft.Exchange.WebServices.Data.ItemSchema]::Subject, $Subject)
    }

    if (![String]::IsNullOrEmpty($Sender))
    {
        $senderEmailAddress = New-Object Microsoft.Exchange.WebServices.Data.EmailAddress($Sender)
        $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::Sender, $senderEmailAddress)
    }

    if (![String]::IsNullOrEmpty($MessageId))
    {
        $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::InternetMessageId, $MessageId)
    }

    if(![string]::IsNullOrEmpty($MessageBody)){
        $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring([Microsoft.Exchange.WebServices.Data.ItemSchema]::Body, $MessageBody)
    }

    # Add filter(s) for creation time
    if ( $CreatedAfter )
    {
        $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsGreaterThanOrEqualTo([Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeCreated, $CreatedAfter)
    }
    if ( $CreatedBefore )
    {
        $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsLessThanOrEqualTo([Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeCreated, $CreatedBefore)
    }

    # Create the search filter
    $searchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+SearchFilterCollection([Microsoft.Exchange.WebServices.Data.LogicalOperator]::And)
    foreach ($filter in $filters)
    {
        LogVerbose([string]::Format("Adding search filter: {0}.", $filter.Value))
        $searchFilter.Add($filter)
    }

	# Perform the search and display the results
	while ($moreItems)
	{
        $results = $service.FindItems( $FolderId, $searchFilter, $view )
        $script:RequiredPropSet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,[Microsoft.Exchange.WebServices.Data.ItemSchema]::Subject,
        [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::Sender,[Microsoft.Exchange.WebServices.Data.ItemSchema]::ItemClass,[Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::InternetMessageId,
        [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::ReceivedBy,[Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeCreated)
        #$script:RequiredPropSet = new-object   Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::FirstClassProperties)  
        if($results.Count -gt 0) 
        {
            Log([string]::Format("Found {0} messages.", $results.Items.Count)) Gray
            try {
                [Void]$service.LoadPropertiesForItems($results,$script:RequiredPropSet)   
            }
            catch {}
        }
        
		if(![string]::IsNullOrEmpty($Recipient))
        {
            Log([string]::Format("Filtering the results using the recipient: {0}.", $Recipient)) Gray
        }
        foreach ($item in $results.Items)
        {
	        ProcessItem $item
        }
		
        $moreItems = $results.MoreAvailable
        $view.Offset += $pageSize
	}

    if ($script:ItemsToDelete.Count -gt 0)
    {
        # Delete the items we found in this folder
        ThrottledBatchDelete $script:ItemsToDelete -SuppressNotFoundErrors $true
    }

	# Now search subfolders
    if ($ProcessSubfolders)
    {
	    $view = New-Object Microsoft.Exchange.WebServices.Data.FolderView(500)
        $view.PropertySet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly, [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName)
	    foreach ($subFolder in $folder.FindFolders($view))
	    {
		    SearchFolder $subFolder.Id $folderPath
	    }
    }
}

# The following is the main script

# Load EWS Managed API
if (!(LoadEWSManagedAPI))
{
	Write-Host "Failed to locate EWS Managed API, cannot continue" -ForegroundColor Red
	exit
}

$script:searchResults = @()

# Check for existing result file and remove
if(Get-Item $ResultsFile -ErrorAction Ignore) 
    {
        Log([string]::Format("Deleting the existing results file.")) Yellow
        Remove-Item $ResultsFile -Confirm:$false -ErrorAction Ignore -Force
    }

# Process as single mailbox
SearchMailbox
