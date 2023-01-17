# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ActiveDirectoryAcl {
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.ActiveDirectorySecurity])]
    param (
        [Parameter()]
        [string]
        $DistinguishedName
    )

    $adEntry = [ADSI]("LDAP://$($DistinguishedName)")
    $sdFinder = New-Object System.DirectoryServices.DirectorySearcher($adEntry, "(objectClass=*)", [string[]]("distinguishedName", "ntSecurityDescriptor"), [System.DirectoryServices.SearchScope]::Base)
    $sdResult = $sdFinder.FindOne()
    $ntSdProp = $sdResult.Properties["ntSecurityDescriptor"][0]
    $adSec = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $adSec.SetSecurityDescriptorBinaryForm($ntSdProp)
    return $adSec
}
