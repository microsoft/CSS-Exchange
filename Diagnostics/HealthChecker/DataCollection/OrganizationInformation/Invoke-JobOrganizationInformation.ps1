# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    This is the main function script block that will be executed to collect data about the organization from within
    EMS and Active Directory via LDAP.
    This function must be executed only within the main PowerShell session or within Start-Job
    This will return an object to the pipeline of the results.
#>
function Invoke-JobOrganizationInformation {
    [CmdletBinding()]
    param()
    begin {

        # Extract for Pester Testing - Start
        # Build Process to add functions.
        . $PSScriptRoot\Get-ExchangeAdSchemaInformation.ps1
        . $PSScriptRoot\Get-ExchangeDomainsAclPermissions.ps1
        . $PSScriptRoot\Get-ExchangeWellKnownSecurityGroups.ps1
        . $PSScriptRoot\Get-SecurityCve-2021-34470.ps1
        . $PSScriptRoot\Get-SecurityCve-2022-21978.ps1
        . $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeADSplitPermissionsEnabled.ps1
        # Extract for Pester Testing - End

        if ($PSSenderInfo) {
            $Script:ErrorsExcluded = @()
        }

        $jobStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Invoke-DefaultConnectExchangeShell
        $getOrganizationConfig = $null
        $domainsAclPermissions = $null
        $wellKnownSecurityGroups = $null
        $adSchemaInformation = $null
        $getHybridConfiguration = $null
        $getPartnerApplication = $null
        $enableDownloadDomains = "Unknown" # Set to unknown by default.
        $acceptedDomainObj = $null
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

        try {
            $getSendConnectorRaw = Get-SendConnector -ErrorAction Stop
            $getSendConnector = New-Object System.Collections.Generic.List[object]

            # We need pull out the information about AuthenticationCredential to allow the data to be exported and imported
            foreach ($sendConnectorRaw in $getSendConnectorRaw) {
                $sendConnector = $sendConnectorRaw | Select-Object -Property * -ExcludeProperty AuthenticationCredential

                if ($null -ne $sendConnectorRaw.AuthenticationCredential -and
                    $null -ne $sendConnectorRaw.AuthenticationCredential.UserName) {
                    $sendConnector | Add-Member -MemberType NoteProperty -Name AuthenticationCredential -Value ([PSCustomObject]@{
                            UserName = ($sendConnectorRaw.AuthenticationCredential.UserName)
                        })
                }
                $getSendConnector.Add($sendConnector)
            }
        } catch {
            Write-Verbose "Failed to run Get-SendConnector"
            Invoke-CatchActions
        }

        # Pull out information from OrganizationConfig
        # This is done in case Get-OrganizationConfig and we set a true boolean value of false
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
            $getAcceptedDomainData = Get-AcceptedDomain -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to run Get-AcceptedDomain"
            $acceptedDomainObj = "Unknown"
            Invoke-CatchActions
        }

        #Process AcceptedDomains because of large hosting environments this can bloat the information.
        if ($null -eq $acceptedDomainObj) {
            # WildCard Domain issues
            $wildCardAcceptedDomain = $getAcceptedDomainData | Where-Object { $_.DomainName.ToString() -eq "*" }

            $acceptedDomainObj = [PSCustomObject]@{
                WildCardAcceptedDomain = $wildCardAcceptedDomain
            }
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
                $getAuthConfig = Get-AuthConfig -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to get the Auth Config"
                Invoke-CatchActions
            }

            try {
                $getAuthServer = Get-AuthServer -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to run Auth Server"
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
                $getPartnerApplication = Get-PartnerApplication -ErrorAction Stop
            } catch {
                Write-Yellow "Failed to run Get-PartnerApplication"
                Invoke-CatchActions
            }

            try {
                $getSettingOverride = Get-SettingOverride -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to run Get-SettingOverride"
                $getSettingOverride = "Unknown"
                Invoke-CatchActions
            }

            try {
                if ($null -ne $getOrganizationConfig -and $null -ne $getOrganizationConfig.RootPublicFolderMailbox) {
                    [string]$guid = $getOrganizationConfig.RootPublicFolderMailbox
                    Write-Verbose "Trying to collect root public folder mailbox information - $guid"
                    $getMailboxRootPF = Get-Mailbox -PublicFolder $guid -ErrorAction Stop
                    $rootPublicFolderMailbox = [PSCustomObject]@{
                        Name                           = $getMailboxRootPF.Name
                        ExchangeGuid                   = $getMailboxRootPF.ExchangeGuid
                        IsExcludedFromServingHierarchy = $getMailboxRootPF.IsExcludedFromServingHierarchy
                        IsHierarchyReady               = $getMailboxRootPF.IsHierarchyReady
                        IsHierarchySyncEnabled         = $getMailboxRootPF.IsHierarchySyncEnabled
                    }
                }
            } catch {
                Write-Verbose "Failed to get the public folder mailbox. Inner Exception: $_"
                Invoke-CatchActions
            }

            [array]$globalMonitoringOverride = Get-MonitoringOverride -CatchActionFunction ${Function:Invoke-CatchActions}

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

            # Domain Trusts information
            try {
                $trustedDomainResults = New-Object System.Collections.Generic.List[object]
                $globalCatalog = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest.FindGlobalCatalog()).Name
                $entry = [ADSI]("GC://$globalCatalog")
                $filter = "(objectClass=trustedDomain)"
                $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($entry, $filter)
                $allGCResults = $directorySearcher.FindAll()
                foreach ($gcResult in $allGCResults) {
                    # Only keep what appears to be useful properties.
                    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
                    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/36565693-b5e4-4f37-b0a8-c1b12138e18e
                    $trustObject = [PSCustomObject]@{
                        DistinguishedName        = [string]($gcResult.Properties["DistinguishedName"])
                        TrustDirection           = [int]($gcResult.Properties["TrustDirection"][0])
                        TrustAttributes          = [int]($gcResult.Properties["TrustAttributes"][0])
                        TrustPartner             = [string]($gcResult.Properties["TrustPartner"])
                        TrustType                = [int]($gcResult.Properties["TrustType"][0])
                        WhenChanged              = [DateTime]($gcResult.Properties["WhenChanged"][0])
                        SupportedEncryptionTypes = "Unknown"
                    }

                    try {
                        # msDS-SupportedEncryptionTypes is only available on the DC port vs GC. Need to lookup each one manually.
                        $singleEntry = [ADSI]("LDAP://$($trustObject.DistinguishedName)")
                        $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($singleEntry)
                        $results = $directorySearcher.FindOne()
                        # Do not define type here.
                        $trustObject.SupportedEncryptionTypes = ($results.Properties["msDS-SupportedEncryptionTypes"][0])
                    } catch {
                        Write-Verbose "Failed to find $($trustObject.DistinguishedName) msDS-SupportedEncryptionTypes value."
                        Invoke-CatchActions
                    }
                    $trustedDomainResults.Add($trustObject)
                }
            } catch {
                Write-Verbose "Failed to collect Domain Trusts information. Inner Exception $_"
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

            $CVE202221978Results = $null
            $CVE202134470Results = $null
            Get-SecurityCve-2022-21978 @cve21978Params | Invoke-RemotePipelineHandler -Result ([ref]$CVE202221978Results)
            Get-SecurityCve-2021-34470 @cve34470Params | Invoke-RemotePipelineHandler -Result ([ref]$CVE202134470Results)

            $securityResults = [PSCustomObject]@{
                CVE202221978 = $CVE202221978Results
                CVE202134470 = $CVE202134470Results
            }
        }

        if ($PSSenderInfo) {
            $jobHandledErrors = $Script:ErrorsExcluded
            $allErrors = $Error
        }
    } end {
        Write-Verbose "Completed: $($MyInvocation.MyCommand) and took $($jobStopWatch.Elapsed.TotalSeconds) seconds"
        [PSCustomObject]@{
            GetOrganizationConfig             = $getOrganizationConfig
            DomainsAclPermissions             = $domainsAclPermissions
            WellKnownSecurityGroups           = $wellKnownSecurityGroups
            AdSchemaInformation               = $adSchemaInformation
            GetHybridConfiguration            = $getHybridConfiguration
            GetPartnerApplication             = $getPartnerApplication
            EnableDownloadDomains             = $enableDownloadDomains
            AcceptedDomain                    = $acceptedDomainObj
            MapiHttpEnabled                   = $mapiHttpEnabled
            SecurityResults                   = $securityResults
            IsSplitADPermissions              = $isSplitADPermissions
            ADSiteCount                       = $adSiteCount
            GetSettingOverride                = $getSettingOverride
            GetDynamicDgPublicFolderMailboxes = $getDdgPublicFolders
            GetIrmConfiguration               = $getIrmConfiguration
            GetGlobalMonitoringOverride       = $globalMonitoringOverride
            GetAuthConfig                     = $getAuthConfig
            GetAuthServer                     = $getAuthServer
            GetSendConnector                  = $getSendConnector
            TrustedDomain                     = $trustedDomainResults
            RootPublicFolderMailbox           = $rootPublicFolderMailbox
            RemoteJob                         = $true -eq $PSSenderInfo
            JobHandledErrors                  = $jobHandledErrors
            AllErrors                         = $allErrors
        }
    }
}
