# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ObjectTypeDisplayName {
    [CmdletBinding()]
    param (
        [Parameter()]
        [Guid]
        $ObjectType
    )

    $rootDSE = [ADSI]"LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE"
    $extendedRightsContainer = [ADSI]"LDAP://$("CN=Extended-Rights," + $rootDSE.ConfigurationNamingContext)"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($extendedRightsContainer, "(&(rightsGuid=$ObjectType))", "displayName")
    $result = $searcher.FindOne()

    if ($null -ne $result) {
        $result.Properties["displayName"][0]
        return
    }

    $schemaContainer = [ADSI]"LDAP://$("CN=Schema," + $rootDSE.ConfigurationNamingContext)"
    $objectTypeBytes = [string]::Join("", ($ObjectType.ToByteArray() | ForEach-Object { ("\" + $_.ToString("X")) }))
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($schemaContainer, "(&(schemaIdGuid=$objectTypeBytes))", "lDAPDisplayName")
    $result = $searcher.FindOne()
    if ($null -ne $result) {
        $result.Properties["lDAPDisplayName"][0]
        return
    }

    throw "ObjectType $ObjectType not found"
}
