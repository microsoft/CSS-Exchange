# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Confirm-ProxyServer.ps1
. $PSScriptRoot\..\Write-ErrorInformation.ps1

function Invoke-WebRequestWithProxyDetection {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [string]
        $Uri,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [switch]
        $UseBasicParsing,

        [Parameter(Mandatory = $true, ParameterSetName = "ParametersObject")]
        [hashtable]
        $ParametersObject,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [string]
        $OutFile,

        [Parameter(Mandatory = $false)]
        [switch]
        $ReturnErrorResponse
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    if ([System.String]::IsNullOrEmpty($Uri)) {
        $Uri = $ParametersObject.Uri
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (Confirm-ProxyServer -TargetUri $Uri) {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell")
        $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    }

    if ($null -eq $ParametersObject) {
        $params = @{
            Uri     = $Uri
            OutFile = $OutFile
        }

        if ($UseBasicParsing) {
            $params.UseBasicParsing = $true
        }
    } else {
        $params = $ParametersObject
    }

    try {
        Invoke-WebRequest @params
    } catch {
        Write-VerboseErrorInformation

        # By default an HTTP error response (for example HTTP 400) is swallowed. When the caller opts in via
        # -ReturnErrorResponse, surface the error response instead so flows that rely on the error body can
        # inspect it. This is required by the OAuth 2.0 device code polling loop, which drives its loop based on
        # the authorization_pending / slow_down error codes returned in the HTTP 400 body. The returned object
        # exposes StatusCode and Content so the caller can treat success and error responses uniformly.
        if ($ReturnErrorResponse -and
            ($null -ne $_.Exception.Response)) {
            Write-Verbose "Returning the error response because -ReturnErrorResponse was specified"
            return [PSCustomObject]@{
                StatusCode = [int]$_.Exception.Response.StatusCode
                Content    = $_.ErrorDetails.Message
            }
        }
    }
}
