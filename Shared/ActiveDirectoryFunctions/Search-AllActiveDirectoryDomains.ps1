# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Search-AllActiveDirectoryDomains {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Filter,

        [Parameter(Mandatory = $false)]
        [string[]]
        $PropertiesToLoad,

        [Parameter()]
        [bool]
        $CacheResults = $false
    )

    $rootDSE = [ADSI]("GC://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")
    $container = [ADSI]("GC://$($rootDSE.dnsHostName)")
    $searcher = $null
    if ($null -ne $PropertiesToLoad) {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($container, $Filter, $PropertiesToLoad)
    } else {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($container, $Filter)
    }

    $searcher.PageSize = 1000
    $searcher.CacheResults = $CacheResults

    return $searcher.FindAll()
}
