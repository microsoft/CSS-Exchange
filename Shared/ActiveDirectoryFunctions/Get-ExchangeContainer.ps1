# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ExchangeContainer {
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param ()

    $rootDSE = [ADSI]("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")
    $exchangeContainerPath = ("CN=Microsoft Exchange,CN=Services," + $rootDSE.configurationNamingContext)
    $exchangeContainer = [ADSI]("LDAP://" + $exchangeContainerPath)
    Write-Verbose "Exchange Container Path: $($exchangeContainer.path)"
    return $exchangeContainer
}
