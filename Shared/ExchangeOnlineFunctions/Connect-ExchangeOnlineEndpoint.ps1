# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Connects to Exchange Online and applies the endpoint overrides that were supplied by the caller.

.DESCRIPTION
    Exchange Online is reachable under a different host name in every sovereign cloud and the
    endpoints of some of these environments must not be published. The endpoints are therefore
    taken as parameters instead of being resolved from a built-in table, which allows any
    environment to be reached, including environments that do not exist yet.

    Each parameter is forwarded to Connect-ExchangeOnline only when the caller supplied a value.
    A caller that passes nothing therefore connects to the commercial cloud exactly as before,
    because the defaults of the ExchangeOnlineManagement module stay in effect.

.PARAMETER ConnectionUri
    Connection endpoint of the Exchange Online environment to connect to.

.PARAMETER AzureADAuthorizationEndpointUri
    Microsoft Entra authorization endpoint that issues the tokens for the environment.

.PARAMETER Credential
    Credentials that are used to connect to the environment.

.PARAMETER Prefix
    Prefix that is added to the nouns of the imported cmdlets.

.PARAMETER ConnectErrorAction
    ErrorAction that is passed to Connect-ExchangeOnline. The parameter is omitted when the caller
    does not pass a value, which keeps the error handling of the calling script in effect.

.PARAMETER ShowBanner
    Controls whether the module shows its banner. The module default is kept when the caller does
    not pass the parameter.

.EXAMPLE
    Connect-ExchangeOnlineEndpoint -Prefix "Remote" -ConnectErrorAction "SilentlyContinue"

    Connects to the commercial cloud and prefixes the nouns of the imported cmdlets with "Remote".

.EXAMPLE
    Connect-ExchangeOnlineEndpoint -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri

    Connects to an environment whose endpoints were provided by the caller.
#>
function Connect-ExchangeOnlineEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConnectionUri,

        [Parameter(Mandatory = $false)]
        [string]$AzureADAuthorizationEndpointUri,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$Prefix,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Continue", "Ignore", "Inquire", "SilentlyContinue", "Stop", "Suspend")]
        [string]$ConnectErrorAction,

        [Parameter(Mandatory = $false)]
        [bool]$ShowBanner
    )

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
    }
    process {
        $connectParams = @{}

        if (-not [string]::IsNullOrEmpty($ConnectErrorAction)) {
            $connectParams.ErrorAction = $ConnectErrorAction
        }

        if (-not [string]::IsNullOrEmpty($ConnectionUri)) {
            $connectParams.ConnectionUri = $ConnectionUri
        }

        if (-not [string]::IsNullOrEmpty($AzureADAuthorizationEndpointUri)) {
            $connectParams.AzureADAuthorizationEndpointUri = $AzureADAuthorizationEndpointUri
        }

        if ($null -ne $Credential) {
            $connectParams.Credential = $Credential
        }

        if (-not [string]::IsNullOrEmpty($Prefix)) {
            $connectParams.Prefix = $Prefix
        }

        if ($PSBoundParameters.ContainsKey("ShowBanner")) {
            $connectParams.ShowBanner = $ShowBanner
        }

        # Only the names are traced here, because the values can contain credentials.
        Write-Verbose "Connecting to Exchange Online using: $(($connectParams.Keys | Sort-Object) -join ", ")"

        Connect-ExchangeOnline @connectParams
    }
}
