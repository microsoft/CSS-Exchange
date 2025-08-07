# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeContainer.ps1
. $PSScriptRoot\..\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Get-OrganizationContainer {
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param ()

    $exchangeContainer = $null
    Get-ExchangeContainer | Invoke-RemotePipelineHandler -Result ([ref]$exchangeContainer)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($exchangeContainer, "(objectClass=msExchOrganizationContainer)", @("distinguishedName"))
    return $searcher.FindOne().GetDirectoryEntry()
}
