# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Tests whether a Microsoft Graph API endpoint is reachable.

.DESCRIPTION
    Sends an HTTP HEAD request to the specified Graph API URL to verify network connectivity.
    Automatically detects and uses proxy server configuration when present, passing
    default network credentials to the proxy.

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL to test (e.g., "https://graph.microsoft.com").

.OUTPUTS
    System.Boolean - Returns $true if the endpoint is reachable, $false otherwise.

.EXAMPLE
    Test-GraphApiEndpoint -GraphApiUrl "https://graph.microsoft.com"

    Returns $true if the Graph API endpoint responds, $false if it is unreachable.
#>
function Test-GraphApiEndpoint {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GraphApiUrl
    )

    Write-Verbose "Testing connectivity to Graph API endpoint: $GraphApiUrl"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    try {
        $proxyObject = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($GraphApiUrl)
        if ($GraphApiUrl -ne $proxyObject.OriginalString) {
            Write-Verbose "Proxy server detected: $($proxyObject.OriginalString)"
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "PowerShell")
            $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        }
    } catch {
        Write-Verbose "Unable to check for proxy server configuration"
    }

    try {
        $params = @{
            Uri             = $GraphApiUrl
            Method          = "HEAD"
            UseBasicParsing = $true
        }

        if ($null -ne $proxyObject -and $GraphApiUrl -ne $proxyObject.OriginalString) {
            $params.Proxy = $proxyObject
            $params.ProxyUseDefaultCredentials = $true
        }

        $null = Invoke-WebRequest @params
        Write-Verbose "Graph API endpoint is reachable: $GraphApiUrl"
        return $true
    } catch {
        if ($_.Exception.Response) {
            # Server responded with an HTTP error (e.g., 401 Unauthorized) - the endpoint is reachable
            Write-Verbose "Graph API endpoint is reachable (HTTP $([int]$_.Exception.Response.StatusCode)): $GraphApiUrl"
            return $true
        }

        Write-Verbose "Graph API endpoint is not reachable: $GraphApiUrl - Error: $($_.Exception.Message)"
        return $false
    }
}
