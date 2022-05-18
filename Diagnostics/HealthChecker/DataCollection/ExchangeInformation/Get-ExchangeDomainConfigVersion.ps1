# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Invoke-CatchActions.ps1

function Get-ExchangeDomainConfigVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]
        $Domain
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    if ([System.String]::IsNullOrEmpty($Domain)) {
        Write-Verbose "No domain information passed - using current domain"
        $Domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    }

    Write-Verbose "Getting domain information for domain: $Domain"
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

    Write-Verbose "Checking if domain is present"
    if ($forest.Domains.Name.Contains($Domain)) {
        Write-Verbose "Domain: $Domain is present in forest: $($forest.Name)"
        $domainObject = $forest.Domains | Where-Object { $_.Name -eq $Domain }
        $domainDN = $domainObject.GetDirectoryEntry().distinguishedName
        $adEntry = [ADSI]("LDAP://CN=Microsoft Exchange System Objects," + $domainDN)
        $sdFinder = New-Object System.DirectoryServices.DirectorySearcher($adEntry)
        try {
            $mesoResult = $sdFinder.FindOne()
        } catch {
            Write-Verbose "No result was returned"
            Invoke-CatchActions
        }

        if ($null -ne $mesoResult) {
            Write-Verbose "MESO (Microsoft Exchange System Objects) container detected"
            [int]$objectVersion = $mesoResult.Properties.objectversion[0]
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
