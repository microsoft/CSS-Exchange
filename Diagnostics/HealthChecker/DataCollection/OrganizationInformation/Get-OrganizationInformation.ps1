# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeAdSchemaInformation.ps1
. $PSScriptRoot\Get-ExchangeDomainsAclPermissions.ps1
. $PSScriptRoot\Get-ExchangeWellKnownSecurityGroups.ps1
. $PSScriptRoot\Get-SecurityCve-2021-34470.ps1
. $PSScriptRoot\Get-SecurityCve-2022-21978.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeADSplitPermissionsEnabled.ps1
function Get-OrganizationInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$EdgeServer
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $organizationConfig = $null
        $domainsAclPermissions = $null
        $wellKnownSecurityGroups = $null
        $adSchemaInformation = $null
        $getHybridConfiguration = $null
        $enableDownloadDomains = "Unknown" # Set to unknown by default.
        $getAcceptedDomain = $null
        $mapiHttpEnabled = $false
        $securityResults = $null
        $isSplitADPermissions = $false
        $adSiteCount = 0
        $getSettingOverride = $null
    } process {
        try {
            $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
        } catch {
            Write-Yellow "Failed to run Get-OrganizationConfig."
            Invoke-CatchActions
        }

        # Pull out information from OrganizationConfig
        # This is done incase Get-OrganizationConfig and we set a true boolean value of false
        if ($null -ne $organizationConfig) {
            $mapiHttpEnabled = $organizationConfig.MapiHttpEnabled
            # Enabled Download Domains will not be there if running EMS from Exchange 2013.
            # By default, EnableDownloadDomains is set to Unknown in case this is run on 2013 server.
            if ($null -ne $organizationConfig.EnableDownloadDomains) {
                $enableDownloadDomains = $organizationConfig.EnableDownloadDomains
            } else {
                Write-Verbose "No EnableDownloadDomains detected on Get-OrganizationConfig"
            }
        } else {
            Write-Verbose "MAPI HTTP Enabled and Download Domains Enabled results not accurate"
        }

        try {
            $getAcceptedDomain = Get-AcceptedDomain -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to run Get-AcceptedDomain"
            $getAcceptedDomain = "Unknown"
            Invoke-CatchActions
        }

        # NO Edge Server Collection
        if (-not ($EdgeServer)) {

            $adSchemaInformation = Get-ExchangeAdSchemaInformation
            $domainsAclPermissions = Get-ExchangeDomainsAclPermissions
            $wellKnownSecurityGroups = Get-ExchangeWellKnownSecurityGroups
            $isSplitADPermissions = Get-ExchangeADSplitPermissionsEnabled -CatchActionFunction ${Function:Invoke-CatchActions}

            try {
                $getIrmConfiguration = Get-IRMConfiguration -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to get the IRM Configuration"
                Invoke-CatchActions
            }

            try {
                $getDdgPublicFolders = @(Get-DynamicDistributionGroup "PublicFolderMailboxes*" -IncludeSystemObjects -ErrorAction "Stop")
            } catch {
                Write-Verbose "Failed to get the dynamic distribution group for public folder mailboxes."
                Invoke-CatchActions
            }

            try {
                $rootDSE = [ADSI]("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")
                $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher
                $directorySearcher.SearchScope = "Subtree"
                $directorySearcher.SearchRoot = [ADSI]("LDAP://" + $rootDSE.configurationNamingContext.ToString())
                $directorySearcher.Filter = "(objectCategory=site)"
                $directorySearcher.PageSize = 100
                $adSiteCount = ($directorySearcher.FindAll()).Count
            } catch {
                Write-Verbose "Failed to collect AD Site Count information"
                Invoke-CatchActions
            }

            $schemaRangeUpper = (
                ($adSchemaInformation.msExchSchemaVersionPt.Properties["RangeUpper"])[0]).ToInt32([System.Globalization.NumberFormatInfo]::InvariantInfo)

            if ($schemaRangeUpper -lt 15323) {
                $schemaLevel = "2013"
            } elseif ($schemaRangeUpper -lt 17000) {
                $schemaLevel = "2016"
            } else {
                $schemaLevel = "2019"
            }

            $cve21978Params = @{
                DomainsAcls                     = $domainsAclPermissions
                ExchangeWellKnownSecurityGroups = $wellKnownSecurityGroups
                ExchangeSchemaLevel             = $schemaLevel
                SplitADPermissions              = $isSplitADPermissions
            }

            $cve34470Params = @{
                MsExchStorageGroup = $adSchemaInformation.MsExchStorageGroup
            }

            $securityResults = [PSCustomObject]@{
                CVE202221978 = (Get-SecurityCve-2022-21978 @cve21978Params)
                CVE202134470 = (Get-SecurityCve-2021-34470 @cve34470Params)
            }

            try {
                $getHybridConfiguration = Get-HybridConfiguration -ErrorAction Stop
            } catch {
                Write-Yellow "Failed to run Get-HybridConfiguration"
                Invoke-CatchActions
            }

            try {
                $getSettingOverride = Get-SettingOverride -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to run Get-SettingOverride"
                $getSettingOverride = "Unknown"
                Invoke-CatchActions
            }
        }
    } end {
        return [PSCustomObject]@{
            GetOrganizationConfig             = $organizationConfig
            DomainsAclPermissions             = $domainsAclPermissions
            WellKnownSecurityGroups           = $wellKnownSecurityGroups
            AdSchemaInformation               = $adSchemaInformation
            GetHybridConfiguration            = $getHybridConfiguration
            EnableDownloadDomains             = $enableDownloadDomains
            GetAcceptedDomain                 = $getAcceptedDomain
            MapiHttpEnabled                   = $mapiHttpEnabled
            SecurityResults                   = $securityResults
            IsSplitADPermissions              = $isSplitADPermissions
            ADSiteCount                       = $adSiteCount
            GetSettingOverride                = $getSettingOverride
            GetDynamicDgPublicFolderMailboxes = $getDdgPublicFolders
            GetIrmConfiguration               = $getIrmConfiguration
        }
    }
}
