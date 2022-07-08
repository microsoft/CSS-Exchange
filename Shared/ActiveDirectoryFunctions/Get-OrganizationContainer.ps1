# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeContainer.ps1

function Get-OrganizationContainer {
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param ()

    $exchangeContainer = Get-ExchangeContainer
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($exchangeContainer, "(objectClass=msExchOrganizationContainer)", @("distinguishedName"))
    return $searcher.FindOne().GetDirectoryEntry()
}
