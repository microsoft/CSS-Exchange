# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Returns the SID of the desired group in string format.
.DESCRIPTION
    Long description
.EXAMPLE
    PS C:\> Get-WellKnownGroupSid -GroupType "Enterprise Admins"

    Returns the SID of the Enterprise Admins group.
.EXAMPLE
    PS C:\> Get-WellKnownGroupSid -GroupType "Schema Admins"

    Returns the SID of the Schema Admins group.
.EXAMPLE
    PS C:\> Get-WellKnownGroupSid -GroupType "Domain Admins"

    Returns the SID of the Domain Admins group from the domain that the current computer is in.
#>
function Get-WellKnownGroupSid {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Enterprise Admins", "Schema Admins", "Domain Admins")]
        [string]
        $GroupType
    )

    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

    $rootDomainSidBytes = [byte[]] $forest.RootDomain.GetDirectoryEntry().Properties["objectSid"][0]
    $rootDomainSid = New-Object System.Security.Principal.SecurityIdentifier($rootDomainSidBytes, 0)

    $computerDomainSidBytes = [byte[]] [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().GetDirectoryEntry().Properties["objectSid"][0]
    $computerDomainSid = New-Object System.Security.Principal.SecurityIdentifier($computerDomainSidBytes, 0)

    switch ($GroupType) {
        "Enterprise Admins" {
            return "${rootDomainSid}-519"
        }
        "Schema Admins" {
            return "${rootDomainSid}-518"
        }
        "Domain Admins" {
            return "${computerDomainSid}-512"
        }
    }
}
