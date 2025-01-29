# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-DefaultConnectExchangeShell.ps1
. $PSScriptRoot\..\..\..\..\Shared\JobManagement\Add-JobQueue.ps1

function Add-JobOrganizationInformation {
    [CmdletBinding()]
    param()
    process {
        <#
            Non Default Script Block Dependencies
                Invoke-DefaultConnectExchangeShell
                Get-MonitoringOverride
        #>
        function Invoke-JobOrganizationInformation {
            [CmdletBinding()]
            param()
            begin {

                # Build Process to add functions.
                . $PSScriptRoot\Get-ExchangeAdSchemaInformation.ps1
                . $PSScriptRoot\Get-ExchangeDomainsAclPermissions.ps1
                . $PSScriptRoot\Get-ExchangeWellKnownSecurityGroups.ps1
                . $PSScriptRoot\Get-SecurityCve-2021-34470.ps1
                . $PSScriptRoot\Get-SecurityCve-2022-21978.ps1
                . $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeADSplitPermissionsEnabled.ps1

                if ($PSSenderInfo) {
                    $Script:ErrorsExcluded = @()
                }

                Invoke-DefaultConnectExchangeShell
                $getOrganizationConfig = $null
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
                $jobHandledErrors = $null
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
                    Get-ExchangeAdSchemaInformation | Invoke-RemotePipelineHandler -Result ([ref]$adSchemaInformation)
                    Get-ExchangeDomainsAclPermissions | Invoke-RemotePipelineHandler -Result ([ref]$domainsAclPermissions)
                    Get-ExchangeWellKnownSecurityGroups | Invoke-RemotePipelineHandler -Result ([ref]$wellKnownSecurityGroups)
                    Get-ExchangeADSplitPermissionsEnabled -CatchActionFunction ${Function:Invoke-CatchActions} | Invoke-RemotePipelineHandler -Result ([ref]$isSplitADPermissions)

                    # Exchange Cmdlets
                    try {
                        $getIrmConfiguration = Get-IRMConfiguration -ErrorAction Stop
                    } catch {
                        Write-Verbose "Failed to get the IRM Configuration"
                        Invoke-CatchActions
                    }

                    try {
                        # It was reported that this isn't getting thrown to the catch action when failing. As a quick fix, handling this by looping over errors.
                        $currentErrors = $Error.Count
                        $getDdgPublicFolders = @(Get-DynamicDistributionGroup "PublicFolderMailboxes*" -IncludeSystemObjects -ErrorAction "Stop")
                        Invoke-CatchActionErrorLoop $currentErrors ${Function:Invoke-CatchActions}
                    } catch {
                        Write-Verbose "Failed to get the dynamic distribution group for public folder mailboxes."
                        Invoke-CatchActions
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

                    [array]$globalMonitoringOverride = Get-MonitoringOverride

                    # AD Queries
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
                }

                if ($PSSenderInfo) {
                    $jobHandledErrors = $Script:ErrorsExcluded
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
                    RemoteJob                         = $true -eq $PSSenderInfo
                    JobHandledErrors                  = $jobHandledErrors
                }
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $scriptBlock = Get-HCDefaultSBInjection -PrimaryScriptBlock ${Function:Invoke-JobOrganizationInformation} -IncludeScriptBlock @(${Function:Get-MonitoringOverride}, ${Function:Invoke-DefaultConnectExchangeShell})
        $params = @{
            JobCommand   = "Start-Job"
            JobParameter = @{
                ScriptBlock = $scriptBlock
            }
            JobId        = "0df92d89-fbe2-44f5-b17c-ed32f94cf948-OrganizationInformation"
        }
        Add-JobQueue @params
    }
}
