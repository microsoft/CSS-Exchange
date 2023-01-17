# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-CatchActionError.ps1

function Get-GlobalCatalogServer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SiteName = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name,
        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    <#
        This function returns a Global Catalog server for the Active Directory Site of the computer.
    #>

    try {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose ("Trying to query a Global Catalog for the current forest for site: $($SiteName)")
        return ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest.FindGlobalCatalog($SiteName)).Name
    } catch {
        Write-Verbose ("Error while querying a Global Catalog for current forest - Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
        return
    }
}
