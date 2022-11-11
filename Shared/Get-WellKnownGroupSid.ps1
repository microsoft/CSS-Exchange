# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Returns the SID of the desired group.
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
    [OutputType([System.Security.Principal.SecurityIdentifier])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Enterprise Admins", "Schema Admins", "Domain Admins")]
        [string]
        $GroupType
    )

    $forest = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest

    $rootDomainSidBytes = [byte[]] $forest.RootDomain.GetDirectoryEntry().Properties["objectSid"][0]
    $rootDomainSid = New-Object System.Security.Principal.SecurityIdentifier($rootDomainSidBytes, 0)

    $computerDomainSidBytes = [byte[]] [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().GetDirectoryEntry().Properties["objectSid"][0]
    $computerDomainSid = New-Object System.Security.Principal.SecurityIdentifier($computerDomainSidBytes, 0)

    switch ($GroupType) {
        "Enterprise Admins" {
            return New-Object System.Security.Principal.SecurityIdentifier("${rootDomainSid}-519")
        }
        "Schema Admins" {
            return New-Object System.Security.Principal.SecurityIdentifier("${rootDomainSid}-518")
        }
        "Domain Admins" {
            return New-Object System.Security.Principal.SecurityIdentifier("${computerDomainSid}-512")
        }
    }
}
