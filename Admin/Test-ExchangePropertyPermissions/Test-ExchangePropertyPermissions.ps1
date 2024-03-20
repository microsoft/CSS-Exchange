# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]
    $TargetObjectDN,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]
    $ComputerAccountDN,

    [Parameter(Mandatory = $false, Position = 2)]
    [string]
    $DomainController,

    [Parameter(Mandatory = $false, Position = 3)]
    [switch]
    $SaveReport,

    [Parameter(Mandatory = $false, Position = 3)]
    [switch]
    $OutputDebugInfo
)

begin {
    . $PSScriptRoot\..\..\Shared\Out-Columns.ps1
    . $PSScriptRoot\..\..\Shared\ActiveDirectoryFunctions\Get-ActiveDirectoryAcl.ps1
    . $PSScriptRoot\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeADSplitPermissionsEnabled.ps1
    . $PSScriptRoot\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeOtherWellKnownObjects.ps1
    . $PSScriptRoot\..\..\Shared\ActiveDirectoryFunctions\Get-ObjectTypeDisplayName.ps1
    . $PSScriptRoot\..\..\Shared\ActiveDirectoryFunctions\Get-TokenGroupsGlobalAndUniversal.ps1
    . $PSScriptRoot\Get-PropertySetInfo.ps1
    . $PSScriptRoot\Test-ExchangeSchema.ps1

    $requiredWellKnownGroupsInToken = "Exchange Trusted Subsystem", "Exchange Servers"

    $report = [PSCustomObject]@{
        TargetObjectDN    = $TargetObjectDN
        ComputerAccountDN = $ComputerAccountDN
        DomainController  = $DomainController
        RequiredInToken   = @()
        Token             = $null
        ACL               = $null
        ProblemsFound     = @()
    }
}

process {
    if (-not (Test-ExchangeSchema)) {
        Write-Warning "Schema validation failed. Exiting."
        return
    }

    if (Get-ExchangeADSplitPermissionsEnabled) {
        Write-Host "Split permissions is enabled. In this scenario, it is expected that the Exchange server
            computer account does not have write permission to many recipient attributes. The script will
            report these as problems, although they may be normal for this configuration."
    }

    $token = Get-TokenGroupsGlobalAndUniversal -DistinguishedName $ComputerAccountDN
    $report.Token = $token
    Write-Host "Token groups: $ComputerAccountDN"
    $token | Out-Columns

    $wellKnownObjects = Get-ExchangeOtherWellKnownObjects
    foreach ($wellKnownName in $requiredWellKnownGroupsInToken) {
        $groupDN = ($wellKnownObjects | Where-Object { $_.WellKnownName -eq $wellKnownName }).DistinguishedName
        $objectSidBytes = ([ADSI]("LDAP://$groupDN")).Properties["objectSID"][0]
        $objectSid = New-Object System.Security.Principal.SecurityIdentifier($objectSidBytes, 0)
        $report.RequiredInToken += [PSCustomObject]@{
            WellKnownName     = $wellKnownName
            DistinguishedName = $groupDN
            ObjectSid         = $objectSid.ToString()
        }

        $matchFound = $token | Where-Object { $_.SID -eq $objectSid.ToString() }
        if ($null -eq $matchFound) {
            $report.ProblemsFound += "The group $wellKnownName is not in the token."
        }
    }

    $params = @{
        DistinguishedName = $TargetObjectDN
    }

    if (-not [string]::IsNullOrEmpty($DomainController)) {
        $params.DomainController = $DomainController
    }

    $acl = Get-ActiveDirectoryAcl @params
    $objectTypeCache = @{}
    $displayAces = @()
    for ($i = 0; $i -lt $acl.Access.Count; $i++) {
        $ace = $acl.Access[$i]
        if ($ace.ObjectType -ne [Guid]::Empty) {
            if ($null -ne $objectTypeCache[$ace.ObjectType]) {
                $ace | Add-Member -NotePropertyName ObjectTypeDisplay -NotePropertyValue $objectTypeCache[$ace.ObjectType]
            } else {
                $objectTypeDisplay = Get-ObjectTypeDisplayName -ObjectType $ace.ObjectType
                $objectTypeCache[$ace.ObjectType] = $objectTypeDisplay
                $ace | Add-Member -NotePropertyName ObjectTypeDisplay -NotePropertyValue $objectTypeDisplay
            }
        }

        if ($ace.InheritedObjectType -ne [Guid]::Empty) {
            if ($null -ne $objectTypeCache[$ace.InheritedObjectType]) {
                $ace | Add-Member -NotePropertyName InheritedObjectTypeDisplay -NotePropertyValue $objectTypeCache[$ace.InheritedObjectType]
            } else {
                $objectTypeDisplay = Get-ObjectTypeDisplayName -ObjectType $ace.InheritedObjectType
                $objectTypeCache[$ace.InheritedObjectType] = $objectTypeDisplay
                $ace | Add-Member -NotePropertyName InheritedObjectTypeDisplay -NotePropertyValue $objectTypeDisplay
            }
        }

        $ace | Add-Member -MemberType NoteProperty -Name "Index" -Value $i
        $displayAces += $ace
    }

    $report.ACL = $displayAces
    Write-Host "ACL: $TargetObjectDN"
    $displayAces | Where-Object { $_.PropagationFlags -ne "InheritOnly" } | Out-Columns -Properties Index, IdentityReference, AccessControlType, ActiveDirectoryRights, ObjectTypeDisplay, IsInherited

    $propertySetInfo = Get-PropertySetInfo
    $attributeCount = $propertySetInfo.MemberAttributes.Count
    $progressCount = 0
    $sw = New-Object System.Diagnostics.Stopwatch
    $sw.Start()
    $schemaPath = ([ADSI]("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")).Properties["schemaNamingContext"][0]
    $identityReferenceCache = @{}
    foreach ($propertySet in $propertySetInfo) {
        foreach ($attributeName in $propertySet.MemberAttributes) {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress -Activity "Checking permissions" -PercentComplete $((($progressCount * 100) / $attributeCount))
            }

            $attributeSchemaEntry = [ADSI]("LDAP://CN=$attributeName,$schemaPath")
            if ($attributeSchemaEntry.Properties["attributeSecurityGuid"].Count -lt 1) {
                # This schema validation failure should be extremely rare, but we have seen a few
                # cases in lab/dev/test environments, such as when ADSchemaAnalyzer has been used to
                # copy schema between forests.
                $report.ProblemsFound += "The attribute $attributeName is not in the $($propertySet.Name) property set."
                continue
            }

            $schemaIdGuid = New-Object Guid(, $attributeSchemaEntry.Properties["schemaIDGuid"][0])

            # We need to hit a write allow ACE for a SID in the token on one of the following:
            #   - The rightsGuid from the property set
            #   - The schemaIdGuid from the attributeSchemaEntry
            # We must hit the allow before we hit a deny on the same thing.

            $found = $false
            $problemAceIndex = $null
            for ($i = 0; $i -lt $displayAces.Count; $i++) {
                $ace = $displayAces[$i]
                if ($ace.PropagationFlags -eq "InheritOnly") {
                    continue
                }

                $sidToFind = $null
                if ($null -eq $ace.IdentityReference.SID) {
                    if ($null -ne $identityReferenceCache[$ace.IdentityReference.Value]) {
                        $sidToFind = $identityReferenceCache[$ace.IdentityReference.Value]
                    } else {
                        $sidToFind = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        $identityReferenceCache[$ace.IdentityReference.Value] = $sidToFind
                    }
                } else {
                    $sidToFind = $ace.IdentityReference.SID
                }

                $matchingSid = $token | Where-Object { $_.SID -eq $sidToFind.ToString() }
                if ($null -ne $matchingSid) {
                    # The ACE affects this token.
                    # Does it affect this property?
                    if ($ace.ObjectType -eq $propertySet.RightsGuid -or $ace.ObjectType -eq $schemaIdGuid -or $ace.ObjectType -eq [Guid]::Empty) {
                        if ($ace.ActiveDirectoryRights -contains "WriteProperty" -or $ace.ActiveDirectoryRights -contains "GenericAll") {
                            if ($ace.AccessControlType -eq "Allow") {
                                $found = $true
                                break
                            } else {
                                $problemAceIndex = $i
                                break
                            }
                        }
                    }
                }
            }

            if (-not $found) {
                if ($null -ne $problemAceIndex) {
                    $report.ProblemsFound += "The property $attributeName is denied Write by ACE $problemAceIndex."
                } else {
                    $report.ProblemsFound += "The property $attributeName is not allowed Write by any ACE."
                }
            }
        }
    }

    if ($report.ProblemsFound.Count -gt 0) {
        foreach ($problem in $report.ProblemsFound) {
            Write-Warning $problem
        }
    } else {
        Write-Host "No problems found."
    }

    if ($SaveReport) {
        $reportPath = $PSScriptRoot + "\" + "PermissionReport-$([DateTime]::Now.ToString("yyMMddHHmmss")).xml"
        $report | Export-Clixml $reportPath
        Write-Host "Report saved to $reportPath"
    }

    if ($OutputDebugInfo) {
        $debugInfo = @{
            ACL                    = $acl
            DisplayAces            = $displayAces
            IdentityReferenceCache = $identityReferenceCache
            Token                  = $token
            TargetObjectDN         = $TargetObjectDN
            Report                 = $report
        }

        $debugInfoPath = Join-Path $PSScriptRoot "DebugInfo.xml"
        $debugInfo | Export-Clixml -Path $debugInfoPath
        Write-Host "Debug info saved to $debugInfoPath"
    }
}
