# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ActiveDirectoryAcl.ps1

# Collect the ACLs that we want from all domains where the MESO container exists within the forest.
function Get-ExchangeDomainsAclPermissions {
    [CmdletBinding()]
    param ()

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $exchangeDomains = New-Object 'System.Collections.Generic.List[object]'
    } process {

        $forest = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest

        foreach ($domain in $forest.Domains) {

            $domainName = $domain.Name
            Write-Verbose "Working on $domainName"

            $domainObject = [PSCustomObject]@{
                DomainName  = $domainName
                DomainDN    = $null
                Permissions = New-Object 'System.Collections.Generic.List[object]'
                MesoObject  = [PSCustomObject]@{
                    DN            = $null
                    ObjectVersion = 0
                    ACL           = $null
                    WhenChanged   = $null
                }
            }

            try {
                $domainDN = $domain.GetDirectoryEntry().distinguishedName
                $domainObject.DomainDN = $domainDN.ToString()
            } catch {
                Write-Verbose "Domain: $domainName - seems to be offline and will be skipped"
                $domainObject.DomainDN = "Unknown" # Set the domain to unknown vs not knowing it is there.
                Invoke-CatchActions
                continue
            }

            try {
                $mesoEntry = [ADSI]("LDAP://CN=Microsoft Exchange System Objects," + $domainDN)
                $sdFinder = New-Object System.DirectoryServices.DirectorySearcher($mesoEntry)
                $mesoResult = $sdFinder.FindOne()
                Write-Verbose "Found the MESO Container in domain"
            } catch {
                Write-Verbose "Failed to find MESO container in $domainDN"
                Write-Verbose "Skipping over domain"
                Invoke-CatchActions
                continue
            }
            [int]$mesoObjectVersion = $mesoResult.Properties["ObjectVersion"][0]
            $mesoWhenChangedInfo = $mesoResult.Properties["WhenChanged"]
            $mesoDN = $mesoResult.Properties["DistinguishedName"]
            Write-Verbose "Object Version: $mesoObjectVersion"
            Write-Verbose "When Changed: $mesoWhenChangedInfo"
            Write-Verbose "MESO DN: $mesoDN"
            $mesoAcl = $null

            try {
                $mesoAcl = Get-ActiveDirectoryAcl $mesoDN
                Write-Verbose "Got the MESO ACL"
            } catch {
                Write-Verbose "Failed to get the MESO ACL"
                Invoke-CatchActions
            }
            $domainObject.MesoObject.DN = $mesoDN
            $domainObject.MesoObject.ObjectVersion = $mesoObjectVersion
            $domainObject.MesoObject.ACL = $mesoAcl
            $domainObject.MesoObject.WhenChanged = $mesoWhenChangedInfo

            $permissionsCheckList = @($domainDN.ToString(), "CN=AdminSDHolder,CN=System,$domainDN")

            foreach ($permissionDN in $permissionsCheckList) {
                $acl = $null
                try {
                    $acl = Get-ActiveDirectoryAcl $permissionDN
                    Write-Verbose "Got the ACL for: $permissionDN"
                } catch {
                    Write-Verbose "Failed to get the ACL for: $permissionDN"
                    Invoke-CatchActions
                }
                $domainObject.Permissions.Add([PSCustomObject]@{
                        DN  = $permissionDN
                        Acl = $acl
                    })
            }

            $exchangeDomains.Add($domainObject)
        }
    } end {
        return $exchangeDomains
    }
}
