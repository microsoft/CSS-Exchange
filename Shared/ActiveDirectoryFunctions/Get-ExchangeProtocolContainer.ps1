# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-OrganizationContainer.ps1

function Get-ExchangeProtocolContainer {
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param (
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $ComputerName = $ComputerName.Split(".")[0]

    $organizationContainer = Get-OrganizationContainer
    $protocolContainerPath = ("CN=Protocols,CN=" + $ComputerName + ",CN=Servers,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups," + $organizationContainer.distinguishedName)
    $protocolContainer = [ADSI]("LDAP://" + $protocolContainerPath)
    Write-Verbose "Protocol Container Path: $($protocolContainer.Path)"
    return $protocolContainer
}
