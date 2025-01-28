# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Add-JobOrganizationInformation {
    [CmdletBinding()]
    param()
    process {
        <#
            Non Default Script Block Dependencies

        #>
        function Invoke-JobOrganizationInformation {
            [CmdletBinding()]
            param()
            begin {

                # Build Process to add functions.
                . $PSScriptRoot\Get-ExchangeAdSchemaInformation.ps1
                . $PSScriptRoot\Get-ExchangeDomainsAclPermissions.ps1
                . $PSScriptRoot\Get-ExchangeWellKnownSecurityGroups.ps1

                Invoke-DefaultConnectExchangeShell
                $enableDownloadDomains = "Unknown" # Set to unknown by default.
                $mapiHttpEnabled = $false
            }
            process {
                try {
                    $getOrganizationConfig = Get-OrganizationConfig -ErrorAction Stop
                } catch {
                    Write-Warning "Failed to run Get-OrganizationConfig."
                    Invoke-CatchActions
                }

                # Pull out information from OrganizationConfig
                # This is done incase Get-OrganizationConfig and we set a true boolean value of false
                if ($null -ne $getOrganizationConfig) {
                    $mapiHttpEnabled = $getOrganizationConfig.MapiHttpEnabled
                    # Enabled Download Domains will not be there if running EMS from Exchange 2013.
                    # By default, EnableDownloadDomains is set to Unknown in case this is run on 2013 server.
                    if ($null -ne $getOrganizationConfig.EnableDownloadDomains) {
                        $enableDownloadDomains = $getOrganizationConfig.EnableDownloadDomains
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

                if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\EdgeTransportRole')) {
                    $adSchemaInformation = Get-ExchangeAdSchemaInformation
                    $domainsAclPermissions = Get-ExchangeDomainsAclPermissions
                    $wellKnownSecurityGroups = Get-ExchangeWellKnownSecurityGroups
                }
            } end {
                Write-Verbose "Completed: $($MyInvocation.MyCommand)"
                [PSCustomObject]@{
                    GetOrganizationConfig             = $getOrganizationConfig
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
                    GetGlobalMonitoringOverride       = $globalMonitoringOverride
                }
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    }
}
