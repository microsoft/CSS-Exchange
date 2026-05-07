# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
.SYNOPSIS
    Retrieves all domains registered in an Azure AD tenant.

.DESCRIPTION
    This function queries the Microsoft Graph API to retrieve all domains that are registered
    in the Azure AD tenant. It returns detailed information about each domain including its
    verification status, management type, and supported services.

    The function performs the following operations:
    1. Queries the Graph API "domains" endpoint to get all registered domains
    2. Transforms each domain object into a structured PSCustomObject
    3. Adds a convenience property (IsEmailDomain) to indicate if the domain supports email
    4. Returns a list of all domains with their properties

    This function is useful for discovering tenant domains, validating email domains,
    or identifying the default/initial domain of a tenant.

.PARAMETER AzAccountsObject
    The Azure accounts object containing authentication context (AccessToken) for Graph API calls.

.PARAMETER GraphApiUrl
    The Microsoft Graph API endpoint URL to use for API requests (e.g., "https://graph.microsoft.com").

.OUTPUTS
    System.Collections.Generic.List[object] containing PSCustomObjects with the following properties:
    - Id: The fully qualified domain name (e.g., "contoso.com", "contoso.onmicrosoft.com")
    - AdminManaged: Boolean indicating if the domain is managed by an admin (vs. externally managed)
    - IsDefault: Boolean indicating if this is the default domain for the tenant
    - IsInitial: Boolean indicating if this is the initial *.onmicrosoft.com domain
    - IsRoot: Boolean indicating if this is a root domain (not a subdomain)
    - IsVerified: Boolean indicating if domain ownership has been verified
    - IsEmailDomain: Boolean indicating if the domain supports Email (convenience property)
    - SupportedServices: Array of services supported by the domain (e.g., "Email", "OfficeCommunicationsOnline")

    Returns $null if the Graph API query fails.

.EXAMPLE
    $domains = Get-AzureTenantDomainList -AzAccountsObject $azContext -GraphApiUrl "https://graph.microsoft.com"

    # List all verified email domains
    $domains | Where-Object { $_.IsVerified -and $_.IsEmailDomain } | ForEach-Object {
        Write-Host "Email domain: $($_.Id)"
    }

    # Find the default domain
    $defaultDomain = $domains | Where-Object { $_.IsDefault }
    Write-Host "Default domain: $($defaultDomain.Id)"

.NOTES
    Required Graph API permissions:
    - Domain.Read.All (to read domain information)

    API Reference:
    - List domains: https://learn.microsoft.com/graph/api/domain-list
#>
function Get-AzureTenantDomainList {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Getting Azure Tenant Domain List via Graph Api: $GraphApiUrl"

    $domainList = New-Object System.Collections.Generic.List[object]

    $getAzureTenantDomainsParams = @{
        Query       = "domains"
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $getAzureTenantDomainsResponse = Invoke-GraphApiRequest @getAzureTenantDomainsParams

    if ($listAzureTenantDomainsResponse.Successful -eq $false) {
        Write-Verbose "Something went wrong while the domain list was being queried"
        return
    }

    foreach ($d in $getAzureTenantDomainsResponse.Content.value) {
        Write-Verbose "Now processing: $($d.id)"

        $domainList.Add([PSCustomObject]@{
                Id                = $d.id
                AdminManaged      = $d.isAdminManaged
                IsDefault         = $d.isDefault
                IsInitial         = $d.isInitial
                IsRoot            = $d.isRoot
                IsVerified        = $d.isVerified
                IsEmailDomain     = $d.supportedServices -contains "Email"
                SupportedServices = $d.supportedServices
            })
    }

    return $domainList
}
