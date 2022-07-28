# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeDomainConfigVersion.ps1
. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ActiveDirectoryAcl.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeOtherWellKnownObjects.ps1

function Get-ExchangeAdPermissions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [HealthChecker.ExchangeMajorVersion]
        $ExchangeVersion,
        [Parameter(Mandatory = $true)]
        [HealthChecker.OSServerVersion]
        $OSVersion
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    function NewMatchingEntry {
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

    function NewGroupEntry {
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
        $otherWellKnownObjects = Get-ExchangeOtherWellKnownObjects

        foreach ($group in $groupLists) {
            Write-Verbose "Trying to find: $($group.Name)"
            $wkObject = $otherWellKnownObjects | Where-Object { $_.WellKnownName -eq $group.Name }
            if ($null -ne $wkObject) {
                Write-Verbose "Found DN in otherWellKnownObjects: $($wkObject.DistinguishedName)"
                $entry = [ADSI]("LDAP://$($wkObject.DistinguishedName)")
                $group.Sid = (New-Object System.Security.Principal.SecurityIdentifier($entry.objectSid.Value, 0)).Value
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
                try {
                    # Where() method became available with PowerShell 4.0 (default PS on Server 2012 R2),
                    # throw to initiate objectVersion (Default) testing, as we can't use Where() to check ACE below
                    if ($OSVersion -le [HealthChecker.OSServerVersion]::Windows2012) {
                        throw "Legacy server OS detected, fallback to 'objectVersion (Default)' validation initiated"
                    }
                    $domainAcl = Get-ActiveDirectoryAcl $domainDN.ToString()
                    $adminSdHolderAcl = Get-ActiveDirectoryAcl $adminSdHolderDN

                    if ($null -eq $domainAcl -or
                        $null -eq $domainAcl.Access -or
                        $null -eq $adminSdHolderAcl -or
                        $null -eq $adminSdHolderAcl.Access) {
                        throw "Failed to get required ACL information. Fallback to 'objectVersion (Default)' validation initiated."
                    }
                } catch {
                    Invoke-CatchActions
                    $objectVersionTestingValue = 13243
                    if ($ExchangeVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013) {
                        $objectVersionTestingValue = 13238
                    }

                    $returnedResults.Add([PSCustomObject]@{
                            DomainName = $domainName
                            ObjectDN   = $null
                            ObjectAcl  = $null
                            CheckPass  = ($prepareDomainInfo.ObjectVersion -ge $objectVersionTestingValue)
                        })
                    continue
                }

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
