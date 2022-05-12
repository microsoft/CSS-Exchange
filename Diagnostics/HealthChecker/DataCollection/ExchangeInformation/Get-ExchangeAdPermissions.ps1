# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeDomainConfigVersion.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-CatchActions.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ActiveDirectoryAcl.ps1

Function Get-ExchangeAdPermissions {
    [CmdletBinding()]
    param ()

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    Function NewMatchingEntry {
        param(
            [ValidateSet("Domain", "AdminSDHolder")]
            [string]$TargetObject,
            [string]$ObjectTypeGuid,
            [string]$InheritedObjectType
        )

        return [PSCustomObject]@{
            TargetObject        = $TargetObject
            ObjectTypeGuid      = $ObjectTypeGuid
            InheritedObjectType = $InheritedObjectType
        }
    }

    Function NewGroupEntry {
        param(
            [string]$Name,
            [object[]]$MatchingEntries
        )

        return [PSCustomObject]@{
            Name     = $Name
            Sid      = $null
            AceEntry = $MatchingEntries
        }
    }

    # Computer Class GUID
    $computerClassGUID = "bf967a86-0de6-11d0-a285-00aa003049e2"

    # userCertificate GUID
    $userCertificateGUID = "bf967a7f-0de6-11d0-a285-00aa003049e2"

    # managedBy GUID
    $managedByGUID = "0296c120-40da-11d1-a9c0-0000f80367c1"

    $writePropertyRight = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
    $denyType = [System.Security.AccessControl.AccessControlType]::Deny
    $inheritanceAll = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All

    $groupLists = @(
        (NewGroupEntry "Exchange Servers" @(
            (NewMatchingEntry -TargetObject "Domain" -ObjectTypeGuid $userCertificateGUID -InheritedObjectType $computerClassGUID)
        )),

        (NewGroupEntry "Exchange Windows Permissions" @(
            (NewMatchingEntry -TargetObject "Domain" -ObjectTypeGuid $managedByGUID -InheritedObjectType $computerClassGUID)
        )))

    $returnedResults = New-Object 'System.Collections.Generic.List[object]'

    try {
        Write-Verbose "Getting the domain information"
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        Write-Verbose ("Detected: $($forest.Domains.Count) domain(s)")
        $rootDomain = $forest.RootDomain.GetDirectoryEntry()

        foreach ($group in $groupLists) {
            Write-Verbose "Trying to find: $($group.Name)"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($rootDomain, "(samAccountName=$($group.Name))")
            $results = $searcher.FindOne()

            if ($null -ne $results) {
                $results = $results.GetDirectoryEntry()
                $group.Sid = (New-Object System.Security.Principal.SecurityIdentifier($results.objectSid.Value, 0)).Value
                Write-Verbose "Found Results Set Sid: $($group.Sid)"
            }
        }
    } catch {
        Write-Verbose "Failed collecting domain information"
        Invoke-CatchActions
    }

    foreach ($domain in $forest.Domains) {

        $domainName = $domain.Name
        try {
            $domainDN = $domain.GetDirectoryEntry().distinguishedName
        } catch {
            Write-Verbose "Domain: $domainName - seems to be offline and will be skipped"
            Invoke-CatchActions
            continue
        }
        $adminSdHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
        $prepareDomainInfo = Get-ExchangeDomainConfigVersion -Domain $domainName

        if ($prepareDomainInfo.DomainPreparedForExchange) {
            Write-Verbose "Working on Domain: $domainName"
            Write-Verbose "MESO object version is: $($prepareDomainInfo.ObjectVersion)"
            Write-Verbose "DomainDN: $domainDN"

            try {
                $domainAcl = Get-ActiveDirectoryAcl $domainDN.ToString()
                $adminSdHolderAcl = Get-ActiveDirectoryAcl $adminSdHolderDN

                foreach ($group in $groupLists) {
                    Write-Verbose "Looking Ace Entries for the group: $($group.Name)"

                    foreach ($entry in $group.AceEntry) {
                        Write-Verbose "Trying to find the entry GUID: $($entry.ObjectTypeGuid)"
                        if ($entry.TargetObject -eq "AdminSDHolder") {
                            $objectAcl = $adminSdHolderAcl
                            $objectDN = $adminSdHolderDN
                        } else {
                            $objectAcl = $domainAcl
                            $objectDN = $domainDN
                        }
                        Write-Verbose "ObjectDN: $objectDN"

                        # We need to pass an IdentityReference object to the constructor
                        $groupIdentityRef = New-Object System.Security.Principal.SecurityIdentifier($group.Sid)

                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($groupIdentityRef, $writePropertyRight, $denyType, $entry.ObjectTypeGuid, $inheritanceAll, $entry.InheritedObjectType)

                        $checkAce = $objectAcl.Access.Where({
                                    ($_.ActiveDirectoryRights -eq $ace.ActiveDirectoryRights) -and
                                    ($_.InheritanceType -eq $ace.InheritanceType) -and
                                    ($_.ObjectType -eq $ace.ObjectType) -and
                                    ($_.InheritedObjectType -eq $ace.InheritedObjectType) -and
                                    ($_.ObjectFlags -eq $ace.ObjectFlags) -and
                                    ($_.AccessControlType -eq $ace.AccessControlType) -and
                                    ($_.IsInherited -eq $ace.IsInherited) -and
                                    ($_.InheritanceFlags -eq $ace.InheritanceFlags) -and
                                    ($_.PropagationFlags -eq $ace.PropagationFlags) -and
                                    ($_.IdentityReference -eq $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]))
                            })

                        $checkPass = $checkAce.Count -gt 0
                        Write-Verbose "Ace Result Check Passed: $checkPass"

                        $returnedResults.Add([PSCustomObject]@{
                                DomainName = $domainName
                                ObjectDN   = $objectDN
                                ObjectAcl  = $objectAcl
                                CheckPass  = $checkPass
                            })
                    }
                }
            } catch {
                Write-Verbose "Failed while getting ACE information"
                Invoke-CatchActions
            }
        } else {
            Write-Verbose "Domain: $domainName will be skipped because it is not configured to hold Exchange-related objects"
        }
    }
    return $returnedResults
}
