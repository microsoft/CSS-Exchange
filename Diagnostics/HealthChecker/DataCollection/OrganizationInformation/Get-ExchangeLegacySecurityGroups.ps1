# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Search-AllActiveDirectoryDomains.ps1

<#
.DESCRIPTION
    Searches the forest for legacy Exchange security groups that were created by Exchange 2000/2003
    and are no longer used by modern Exchange. These groups still carry elevated Active Directory
    permissions, so as a security best practice they should be reviewed and removed if unused.

    Search-AllActiveDirectoryDomains binds to a Global Catalog, so a single forest-wide query covers
    every domain in one round-trip - group objects of all scopes (Global / Domain Local / Universal)
    are published to the GC, and there is no need to iterate each domain individually.

    NOTE: The GC replicates the full membership only for Universal groups. For Global and Domain
    Local groups the 'member' attribute is not available from the GC, so MemberCount is best-effort
    for those scopes and is informational only.

    Reference: https://learn.microsoft.com/en-us/previous-versions/office/exchange-server-2010/gg576862(v=exchg.141)
#>
function Get-ExchangeLegacySecurityGroups {
    [CmdletBinding()]
    param()
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $legacyGroups = New-Object 'System.Collections.Generic.List[object]'

        # Default sAMAccountName values of the legacy Exchange groups.
        # NOTE: Renamed groups cannot be reliably detected by name.
        $legacyGroupNames = @(
            "Exchange Domain Servers",          # Global       (one per domain)
            "Exchange Enterprise Servers",      # Domain local (forest root)
            "Exchange Recipient Administrators" # Universal    (legacy Exchange 2007 role group)
        )
    } process {
        try {
            $filter = "(&(objectClass=group)(|" +
            (($legacyGroupNames | ForEach-Object { "(sAMAccountName=$_)" }) -join "") + "))"
            $propertiesToLoad = @("distinguishedName", "sAMAccountName", "groupType", "member")

            $searchResults = Search-AllActiveDirectoryDomains -Filter $filter -PropertiesToLoad $propertiesToLoad

            foreach ($result in $searchResults) {
                $distinguishedName = [string]($result.Properties["distinguishedName"][0])
                Write-Verbose "Found legacy group: $distinguishedName"

                # Decode the group scope from the low bits of the groupType attribute.
                $groupTypeValue = [int]($result.Properties["groupType"][0])
                $scope = switch ($groupTypeValue -band 0x0000000E) {
                    2 { "Global" }
                    4 { "DomainLocal" }
                    8 { "Universal" }
                    default { "Unknown" }
                }

                $legacyGroups.Add([PSCustomObject]@{
                        Name              = [string]($result.Properties["sAMAccountName"][0])
                        DistinguishedName = $distinguishedName
                        Scope             = $scope
                        MemberCount       = $result.Properties["member"].Count
                    })
            }
        } catch {
            Write-Verbose "Failed to query Active Directory for legacy Exchange security groups. Inner Exception: $_"
            Invoke-CatchActions
        }
    } end {
        return $legacyGroups
    }
}
