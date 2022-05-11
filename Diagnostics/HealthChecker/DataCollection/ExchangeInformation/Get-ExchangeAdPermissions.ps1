# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Invoke-CatchActions.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ActiveDirectoryAcl.ps1

Function Get-ExchangeAdPermissions {
    [CmdletBinding()]
    param()

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    Function NewMatchingEntry {
        param(
            [string]$ObjectTypeGuid,
            [bool]$AdminSdHolder,
            [bool]$ComputerClass,
            [bool]$RootOnly
        )

        return [PSCustomObject]@{
            ObjectTypeGuid = $ObjectTypeGuid
            AdminSdHolder  = $AdminSdHolder
            ComputerClass  = $ComputerClass
            RootOnly       = $RootOnly
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

    # Alt-Scurity-Identities GUID
    $altSecIdentitySchemaGUID = "00fbf30c-91fe-11d1-aebc-0000f80367c1"

    # Computer Class SID
    $computerClassSID = "bf967a86-0de6-11d0-a285-00aa003049e2"

    # userCertificate SID
    $userCertificateSID = "bf967a7f-0de6-11d0-a285-00aa003049e2"

    # managedBy SID
    $managedBySID = "0296c120-40da-11d1-a9c0-0000f80367c1"

    $writePropertyRight = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
    $denyType = [System.Security.AccessControl.AccessControlType]::Deny
    $inheritanceAll = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All

    $groupLists = @(
        (NewGroupEntry "Exchange Trusted Subsystem" @(
            (NewMatchingEntry -ObjectTypeGuid $altSecIdentitySchemaGUID -AdminSdHolder $false -ComputerClass $true -RootOnly $false),
            (NewMatchingEntry -ObjectTypeGuid $altSecIdentitySchemaGUID -AdminSdHolder $true -ComputerClass $true -RootOnly $false)
        )),

        (NewGroupEntry "Exchange Servers" @(
            (NewMatchingEntry -ObjectTypeGuid $userCertificateSID -AdminSdHolder $false -ComputerClass $true -RootOnly $false),
            (NewMatchingEntry -ObjectTypeGuid $userCertificateSID -AdminSdHolder $true -ComputerClass $true -RootOnly $false)
        )),

        (NewGroupEntry "Exchange Windows Permissions" @(
            (NewMatchingEntry -ObjectTypeGuid $managedBySID -AdminSdHolder $false -ComputerClass $true -RootOnly $false)
        )))

    $returnedResults = New-Object 'System.Collections.Generic.List[object]'

    try {
        Write-Verbose "Getting the domain information"
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        Write-Verbose ("Detected: $($forest.Domains.Count) domain(s)")
        $rootDomain = $forest.RootDomain.GetDirectoryEntry()
        $rootDomainName = $forest.RootDomain.forest.Name

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
        $domainDN = $domain.GetDirectoryEntry().distinguishedName
        $adminSdHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"

        Write-Verbose "Working on Domain: $domainName"
        Write-Verbose "DomainDN: $domainDN"

        try {
            $domainAcl = Get-ActiveDirectoryAcl $domainDN.ToString()
            $adminSdHolderAcl = Get-ActiveDirectoryAcl $adminSdHolderDN

            foreach ($group in $groupLists) {

                Write-Verbose "Looking Ace Entries for the group: $($group.Name)"
                foreach ($entry in $group.AceEntry) {

                    if ((($entry.RootOnly) -and ($domainName -eq $rootDomainName)) -or
                        ($entry.RootOnly -eq $false)) {
                        Write-Verbose "Trying to find the entry GUID: $($entry.ObjectTypeGuid)"
                        if ($entry.AdminSdHolder) {
                            $objectAcl = $adminSdHolderAcl
                            $objectDN = $adminSdHolderDN
                        } else {
                            $objectAcl = $domainAcl
                            $objectDN = $domainDN
                        }
                        Write-Verbose "ObjectDN: $objectDN"

                        # We need to pass an IdentityReference object to the constructor
                        if ($entry.ComputerClass) {
                            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule([System.Security.Principal.SecurityIdentifier]::new($group.Sid), $writePropertyRight, $denyType, $entry.ObjectTypeGuid, $inheritanceAll, $computerClassSID)
                        } else {
                            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule([System.Security.Principal.SecurityIdentifier]::new($group.Sid), $writePropertyRight, $denyType, $entry.ObjectTypeGuid, $inheritanceAll)
                        }

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
                    } else {
                        Write-Verbose "ACE entry: $($entry.ObjectTypeGuid) is root-exclusive and will be skipped for domain: $($domainName)"
                    }
                }
            }
        } catch {
            Write-Verbose "Failed while getting ACE information"
            Invoke-CatchActions
        }
    }
    return $returnedResults
}
