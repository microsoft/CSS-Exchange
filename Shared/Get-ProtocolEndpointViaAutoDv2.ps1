# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\ScriptUpdateFunctions\Invoke-WebRequestWithProxyDetection.ps1

function Get-ProtocolEndpointViaAutoDv2 {
    [CmdletBinding(DefaultParameterSetName = "EXO")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "OnPrem")]
        [Parameter(Mandatory = $true, ParameterSetName = "EXO")]
        [ValidatePattern("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")]
        [string]$SmtpAddress,

        [Parameter(Mandatory = $true, ParameterSetName = "OnPrem")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^(?!http:\/\/|https:\/\/).*(?<!\/)$")]
        [string]$Url,

        [Parameter(Mandatory = $true, ParameterSetName = "OnPrem")]
        [Parameter(Mandatory = $true, ParameterSetName = "EXO")]
        [ValidateSet("EWS", "REST", "ActiveSync", "AutodiscoverV1")]
        [string]$Protocol
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        # AutoDiscover v2 automatically redirect calls to the right cloud - this URL works therefore for all clouds
        $baseUrl = "outlook.office365.com"

        if ($PSCmdlet.ParameterSetName -eq "OnPrem") {
            $baseUrl = $Url
        }

        # The 'ServerLocation' parameter doesn't exist in Exchange Server - it will be ignored by the server and no location will be returned
        $autoDiscoverV2Endpoint = "https://{0}/autodiscover/autodiscover.json/v1.0/{1}?Protocol={2}&ServerLocation=true" -f $baseUrl, $SmtpAddress, $Protocol

        Write-Verbose "Final AutoDiscover URL is: $autoDiscoverV2Endpoint"
    } process {
        $autoDiscoverV2Response = Invoke-WebRequestWithProxyDetection -Uri $autoDiscoverV2Endpoint -UseBasicParsing
        $headers = $autoDiscoverV2Response.Headers

        Write-Verbose "Request: $($headers.'request-id') Date: $($headers.Date) Status: $($autoDiscoverV2Response.StatusCode)"

        if ($null -eq $autoDiscoverV2Response -or
            [System.String]::IsNullOrEmpty($autoDiscoverV2Response.StatusCode) -or
            $autoDiscoverV2Response.StatusCode -ne 200) {

            Write-Verbose "AutoDiscover call failed - this could be caused by using an invalid smtp address or due to network or service issues"
            return
        }

        Write-Verbose "AutoDiscover request successful"

        $content = $autoDiscoverV2Response.Content | ConvertFrom-Json
    } end {
        return [PSCustomObject]@{
            Protocol       = $content.Protocol
            Url            = $content.Url
            ServerLocation = $content.ServerLocation
        }
    }
}
