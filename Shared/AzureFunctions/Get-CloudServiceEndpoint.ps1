# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    This shared function is used to get the endpoints for the Azure and Microsoft 365 services.
    It returns a PSCustomObject with the following properties:
        GraphApiEndpoint: The endpoint for the Microsoft Graph API
        ExchangeOnlineEndpoint: The endpoint for Exchange Online
        AutoDiscoverSecureName: The endpoint for Autodiscover
        AzureADEndpoint: The endpoint for Azure Active Directory
        EnvironmentName: The name of the Azure environment

    The environment name is required and validated, because returning an object whose properties are
    all null would let a caller continue with no endpoints at all and fail later in an unrelated place.
#>
function Get-CloudServiceEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Global", "USGovernmentL4", "USGovernmentL5", "ChinaCloud", "BleuCloud", "DelosCloud")]
        [string]$EndpointName
    )

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
    }
    process {
        # https://learn.microsoft.com/graph/deployments#microsoft-graph-and-graph-explorer-service-root-endpoints
        switch ($EndpointName) {
            "Global" {
                $environmentName = "AzureCloud"
                $graphApiEndpoint = "https://graph.microsoft.com"
                $exchangeOnlineEndpoint = "https://outlook.office.com"
                $autodiscoverSecureName = "https://autodiscover-s.outlook.com"
                $azureADEndpoint = "https://login.microsoftonline.com"
                break
            }
            "USGovernmentL4" {
                $environmentName = "AzureUSGovernment"
                $graphApiEndpoint = "https://graph.microsoft.us"
                $exchangeOnlineEndpoint = "https://outlook.office365.us"
                $autodiscoverSecureName = "https://autodiscover-s.office365.us"
                $azureADEndpoint = "https://login.microsoftonline.us"
                break
            }
            "USGovernmentL5" {
                $environmentName = "AzureUSGovernment"
                $graphApiEndpoint = "https://dod-graph.microsoft.us"
                $exchangeOnlineEndpoint = "https://outlook-dod.office365.us"
                $autodiscoverSecureName = "https://autodiscover-s-dod.office365.us"
                $azureADEndpoint = "https://login.microsoftonline.us"
                break
            }
            "ChinaCloud" {
                $environmentName = "AzureChinaCloud"
                $graphApiEndpoint = "https://microsoftgraph.chinacloudapi.cn"
                $exchangeOnlineEndpoint = "https://partner.outlook.cn"
                $autodiscoverSecureName = "https://autodiscover-s.partner.outlook.cn"
                $azureADEndpoint = "https://login.partner.microsoftonline.cn"
                break
            }
            "BleuCloud" {
                $environmentName = "BleuCloud"
                $graphApiEndpoint = "https://graph.svc.sovcloud.fr"
                $exchangeOnlineEndpoint = "https://outlook.sovcloud.fr"
                $autodiscoverSecureName = "https://autodiscover-s.outlook.sovcloud.fr"
                $azureADEndpoint = "https://login.sovcloud-identity.fr"
                break
            }
            "DelosCloud" {
                $environmentName = "DelosCloud"
                $graphApiEndpoint = "https://graph.svc.sovcloud.de"
                $exchangeOnlineEndpoint = "https://outlook.sovcloud.de"
                $autodiscoverSecureName = "https://autodiscover-s.outlook.sovcloud.de"
                $azureADEndpoint = "https://login.sovcloud-identity.de"
                break
            }
            default {
                # Only reachable if an environment is added to the ValidateSet above without adding
                # its endpoints here. Failing here is better than returning an object full of nulls.
                throw "No endpoints are defined for the cloud environment '$EndpointName'."
            }
        }
    }
    end {
        return [PSCustomObject]@{
            EnvironmentName        = $environmentName
            GraphApiEndpoint       = $graphApiEndpoint
            ExchangeOnlineEndpoint = $exchangeOnlineEndpoint
            AutoDiscoverSecureName = $autodiscoverSecureName
            AzureADEndpoint        = $azureADEndpoint
        }
    }
}
