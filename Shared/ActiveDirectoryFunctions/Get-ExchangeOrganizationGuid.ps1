# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeContainer.ps1
. $PSScriptRoot\..\Invoke-CatchActionError.ps1

<#
    This function returns the unique id (Guid) of the organization
    It can be used when no Exchange Management Shell is used to run a script
#>
function Get-ExchangeOrganizationGuid {
    [CmdletBinding()]
    param(
        [ScriptBlock]$CatchActionFunction
    )

    $organizationGuid = $null

    $exchangeContainer = Get-ExchangeContainer
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($exchangeContainer, "(objectClass=msExchOrganizationContainer)", "objectGUID")
    $result = $searcher.FindOne()

    if ($null -ne $result.Properties["objectGuid"]) {
        try {
            $organizationGuid = ([System.Guid]::New($($result.Properties["objectGuid"]))).Guid
        } catch {
            Write-Verbose "Unable to query Exchange Organization Guid. Exception: $_"
            Invoke-CatchActionError $CatchActionFunction
        }
    }

    return $organizationGuid
}
