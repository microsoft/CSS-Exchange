# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-ExchangeDomainConfigVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Domain
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    Write-Verbose "Getting domain information for domain: $Domain"
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

    Write-Verbose "Checking if domain is present"
    if ($forest.Domains.Name.Contains($Domain)) {
        Write-Verbose "Domain: $Domain is present in forest: $($forest.Name)"
        $domainObject = $forest.Domains | Where-Object { $_.Name -eq $Domain }
        $domainDN = $domainObject.GetDirectoryEntry().distinguishedName
        $adEntry = [ADSI]("LDAP://CN=Microsoft Exchange System Objects," + $domainDN)
        $sdFinder = New-Object System.DirectoryServices.DirectorySearcher($adEntry)
        $mesoResult = $sdFinder.FindOne()

        if ($null -ne $mesoResult) {
            Write-Verbose "MESO (Microsoft Exchange System Objects) container detected"
            $objectVersion = $mesoResult.Properties.objectversion
            $whenChangedInfo = $mesoResult.Properties.whenchanged
        } else {
            Write-Verbose "No MESO (Microsoft Exchange System Objects) container detected"
        }
    } else {
        Write-Verbose "Domain: $Domain is NOT present in forest: $($forest.Name)"
    }

    return [PSCustomObject]@{
        Domain                    = $Domain
        DomainPreparedForExchange = ($mesoResult.Count -gt 0)
        ObjectVersion             = $objectVersion
        WhenChanged               = $whenChangedInfo
    }
}
