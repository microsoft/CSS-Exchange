# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    Gets all the domains that are registered in a tenant
    https://learn.microsoft.com/graph/api/domain-list
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
