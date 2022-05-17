# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Confirm-ProxyServer.ps1

function Invoke-WebRequestWithProxyDetection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Uri,

        [Parameter(Mandatory = $false)]
        [switch]
        $UseBasicParsing,

        [Parameter(Mandatory = $false)]
        [string]
        $OutFile
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (Confirm-ProxyServer -TargetUri $Uri) {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell")
        $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    }

    $params = @{
        Uri     = $Uri
        OutFile = $OutFile
    }

    if ($UseBasicParsing) {
        $params.UseBasicParsing = $true
    }

    Invoke-WebRequest @params
}
