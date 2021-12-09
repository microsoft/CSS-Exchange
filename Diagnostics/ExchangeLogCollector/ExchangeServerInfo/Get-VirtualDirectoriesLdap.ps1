# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-VirtualDirectoriesLdap {

    $authTypeEnum = @"
    namespace AuthMethods
    {
        using System;
        [Flags]
        public enum AuthenticationMethodFlags
        {
            None = 0,
            Basic = 1,
            Ntlm = 2,
            Fba = 4,
            Digest = 8,
            WindowsIntegrated = 16,
            LiveIdFba = 32,
            LiveIdBasic = 64,
            WSSecurity = 128,
            Certificate = 256,
            NegoEx = 512,
            // Exchange 2013
            OAuth = 1024,
            Adfs = 2048,
            Kerberos = 4096,
            Negotiate = 8192,
            LiveIdNegotiate = 16384,
        }
    }
"@

    Write-ScriptHost -WriteString "Collecting Virtual Directory Information..." -ShowServer $false
    Add-Type -TypeDefinition $authTypeEnum -Language CSharp

    $objRootDSE = [ADSI]"LDAP://rootDSE"
    $strConfigurationNC = $objRootDSE.configurationNamingContext
    $objConfigurationNC = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$strConfigurationNC")
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.filter = "(&(objectClass=msExchVirtualDirectory)(!objectClass=container))"
    $searcher.SearchRoot = $objConfigurationNC
    $searcher.CacheResults = $false
    $searcher.SearchScope = "Subtree"
    $searcher.PageSize = 1000

    # Get all the results
    $colResults = $searcher.FindAll()
    $objects = @()

    # Loop through the results and
    foreach ($objResult in $colResults) {
        $objItem = $objResult.getDirectoryEntry()
        $objProps = $objItem.Properties

        $place = $objResult.Path.IndexOf("CN=Protocols,CN=")
        $ServerDN = [ADSI]("LDAP://" + $objResult.Path.SubString($place, ($objResult.Path.Length - $place)).Replace("CN=Protocols,", ""))
        [string]$Site = $serverDN.Properties.msExchServerSite.ToString().Split(",")[0].Replace("CN=", "")
        [string]$server = $serverDN.Properties.adminDisplayName.ToString()
        [string]$version = $serverDN.Properties.serialNumber.ToString()

        $obj = New-Object PSObject
        $obj | Add-Member -MemberType NoteProperty -Name Server -Value $server
        $obj | Add-Member -MemberType NoteProperty -Name Version -Value $version
        $obj | Add-Member -MemberType NoteProperty -Name Site -Value $Site
        [string]$var = $objProps.DistinguishedName.ToString().Split(",")[0].Replace("CN=", "")
        $obj | Add-Member -MemberType NoteProperty -Name VirtualDirectory -Value $var
        [string]$var = $objProps.msExchInternalHostName
        $obj | Add-Member -MemberType NoteProperty -Name InternalURL -Value $var

        if (-not [string]::IsNullOrEmpty($objProps.msExchInternalAuthenticationMethods)) {
            $obj | Add-Member -MemberType NoteProperty -Name InternalAuthenticationMethods -Value ([AuthMethods.AuthenticationMethodFlags]$objProps.msExchInternalAuthenticationMethods)
        } else {
            $obj | Add-Member -MemberType NoteProperty -Name InternalAuthenticationMethods -Value $null
        }

        [string]$var = $objProps.msExchExternalHostName
        $obj | Add-Member -MemberType NoteProperty -Name ExternalURL -Value $var

        if (-not [string]::IsNullOrEmpty($objProps.msExchExternalAuthenticationMethods)) {
            $obj | Add-Member -MemberType NoteProperty -Name ExternalAuthenticationMethods -Value ([AuthMethods.AuthenticationMethodFlags]$objProps.msExchExternalAuthenticationMethods)
        } else {
            $obj | Add-Member -MemberType NoteProperty -Name ExternalAuthenticationMethods -Value $null
        }

        if (-not [string]::IsNullOrEmpty($objProps.msExch2003Url)) {
            [string]$var = $objProps.msExch2003Url
            $obj | Add-Member -MemberType NoteProperty -Name Exchange2003URL  -Value $var
        } else {
            $obj | Add-Member -MemberType NoteProperty -Name Exchange2003URL -Value $null
        }

        [Array]$objects += $obj
    }

    return $objects
}
