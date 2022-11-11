# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeAdSchemaInformation.ps1
. $PSScriptRoot\Get-ExchangeDomainsAclPermissions.ps1
. $PSScriptRoot\Get-ExchangeWellKnownSecurityGroups.ps1
. $PSScriptRoot\Get-SecurityCve-2022-21978.ps1
function Get-OrganizationInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$EdgeServer
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        [HealthChecker.OrganizationInformation]$orgInfo = New-Object -TypeName HealthChecker.OrganizationInformation
    } process {
        try {
            $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
            $orgInfo.GetOrganizationConfig = $organizationConfig
        } catch {
            Write-Yellow "Failed to run Get-OrganizationConfig."
            Invoke-CatchActions
        }

        # Pull out information from OrganizationConfig
        # This is done incase Get-OrganizationConfig and we set a true boolean value of false
        if ($null -ne $organizationConfig) {
            $orgInfo.MapiHttpEnabled = $organizationConfig.MapiHttpEnabled
            # Enabled Download Domains will not be there if running EMS from Exchange 2013.
            # TODO: Address this. Need to determine if higher than Exchange 2013 exchange has been installed and that we shouldn't be running HC from that session.
            if ($null -ne $organizationConfig.EnableDownloadDomains) {
                $orgInfo.EnableDownloadDomains = $organizationConfig.EnableDownloadDomains
            } else {
                Write-Verbose "No EnableDownloadDomains detected on Get-OrganizationConfig"
            }
        } else {
            Write-Verbose "MAPI HTTP Enabled and Download Domains Enabled results not accurate"
        }

        try {
            $orgInfo.WildCardAcceptedDomain = Get-AcceptedDomain -ErrorAction Stop | Where-Object { $_.DomainName.ToString() -eq "*" }
        } catch {
            Write-Verbose "Failed to run Get-AcceptedDomain"
            $orgInfo.WildCardAcceptedDomain = "Unknown"
            Invoke-CatchActions
        }

        #TODO: Move and Update AMSIConfiguration here. Need to do a global Get-SettingOverride instead of a filter like what is in Get-ExchangeAMSIConfigurationState
        #TODO: Handle Get-ExchangeEmergencyMitigationServiceState
        # NO Edge Server Collection
        if (-not ($EdgeServer)) {

            $orgInfo.AdSchemaInformation = Get-ExchangeAdSchemaInformation
            $orgInfo.DomainsAclPermissions = Get-ExchangeDomainsAclPermissions
            $orgInfo.WellKnownSecurityGroups = Get-ExchangeWellKnownSecurityGroups

            $schemaRangeUpper = (($orgInfo.AdSchemaInformation.msExchSchemaVersionPt.Properties["RangeUpper"])[0]).ToInt32([System.Globalization.NumberFormatInfo]::InvariantInfo)

            if ($schemaRangeUpper -lt 15323) {
                $schemaLevel = "2013"
            } elseif ($schemaRangeUpper -lt 17000) {
                $schemaLevel = "2016"
            } else {
                $schemaLevel = "2019"
            }

            $cve21978Params = @{
                DomainsAcls                     = $orgInfo.DomainsAclPermissions
                ExchangeWellKnownSecurityGroups = $orgInfo.WellKnownSecurityGroups
                ExchangeSchemaLevel             = $schemaLevel
            }

            $orgInfo.SecurityResults = [PSCustomObject]@{
                CVE202221978 = (Get-SecurityCve-2022-21978 @cve21978Params)
            }

            try {
                $orgInfo.GetHybridConfiguration = Get-HybridConfiguration -ErrorAction Stop
            } catch {
                Write-Yellow "Failed to run Get-HybridConfiguration"
                Invoke-CatchActions
            }
        }
    } end {
        return $orgInfo
    }
}
