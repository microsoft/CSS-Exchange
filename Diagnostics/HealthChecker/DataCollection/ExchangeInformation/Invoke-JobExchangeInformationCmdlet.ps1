# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    This is the main function script block that will be executed to collect data about the Exchange Server from both
    EMS and Active Directory via LDAP.
    This function must be executed only within the main PowerShell session or within Start-Job
    This will return objects to the pipeline for each server.
#>
function Invoke-JobExchangeInformationCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServerName
    )
    begin {
        # Extract for Pester Testing - Start
        # Build Process to add functions.
        . $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeDiagnosticInformation.ps1
        . $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeSettingOverride.ps1
        . $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeWebSitesFromAd.ps1
        . $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-GlobalCatalogServer.ps1
        . $PSScriptRoot\..\..\..\..\Shared\CertificateFunctions\Get-ExchangeServerCertificateInformation.ps1
        . $PSScriptRoot\Get-ExchangeVirtualDirectories.ps1
        . $PSScriptRoot\Get-ExchangeServerMaintenanceState.ps1

        function GetExchangeServerADInformation {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [object]$GetExchangeServer
            )
            $adPrincipalGroupMembership = New-Object System.Collections.Generic.List[object]
            $computerObject = $null
            try {
                Write-Verbose "Trying to find the computer membership"
                [string]$adSiteRaw = $GetExchangeServer.Site
                $adSite = $adSiteRaw.Substring($adSiteRaw.IndexOf("/Sites/") + 7)
                Write-Verbose "Found the Computer Site: $adSite"
                $globalCatalog = $null
                Get-GlobalCatalogServer -SiteName $adSite | Invoke-RemotePipelineHandler -Result ([ref]$globalCatalog)
                Write-Verbose "Got GC: $globalCatalog"
                $DomainDN = "DC=$($GetExchangeServer.OrganizationalUnit.Split("/")[0].Replace(".",",DC="))"
                Write-Verbose "Determined DomainDN to be: $DomainDN"
                $directoryEntry = [ADSI]("GC://$globalCatalog/$DomainDN")
                $searchFilter = "(&(objectCategory=computer)(objectClass=computer)(cn=$($getExchangeServer.Name)))"
                $properties = @("distinguishedName", "memberOf", "whenCreated", "whenChanged", "objectGUID", "objectSid", "servicePrincipalName", "msExchRMSComputerAccountsBL")
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry, $searchFilter, $properties)
                $computerSearchResults = $searcher.FindOne()
                Write-Verbose "Building Computer AD Object"
                $computerObjectSidBytes = $computerSearchResults.Properties["objectSid"][0]
                $computerObjectSid = New-Object System.Security.Principal.SecurityIdentifier($computerObjectSidBytes, 0)
                $computerObject = [PSCustomObject]@{
                    MemberOf                    = $computerSearchResults.Properties["memberOf"]
                    MSExchRmsComputerAccountsBl = $computerSearchResults.Properties["MsExchRmsComputerAccountsBl"]
                    WhenCreated                 = $computerSearchResults.Properties["WhenCreated"]
                    WhenChanged                 = $computerSearchResults.Properties["WhenChanged"]
                    DistinguishedName           = $computerSearchResults.Properties["DistinguishedName"]
                    ObjectGuid                  = ([System.Guid]::New($($computerSearchResults.Properties["objectGuid"])).Guid)
                    ServicePrincipalName        = $computerSearchResults.Properties["ServicePrincipalName"]
                    ObjectSid                   = $computerObjectSid
                }

                if ($null -ne $computerSearchResults) {
                    foreach ($dnEntry in $computerSearchResults.Properties["memberOf"]) {
                        $adEntry = [ADSI]"LDAP://$dnEntry"
                        $properties = @("distinguishedName", "name", "objectSid", "objectGUID")
                        $searcher = New-Object System.DirectoryServices.DirectorySearcher($adEntry, "(objectClass=*)", $properties)
                        $searchResults = $searcher.FindOne()
                        $objectSidBytes = $searchResults.Properties["objectSid"][0]
                        $objectSid = New-Object System.Security.Principal.SecurityIdentifier($objectSidBytes, 0)
                        $objectGuid = [System.Guid]::New($($searchResults.Properties["objectGUID"])).Guid
                        $adPrincipalGroupMembership.Add(([PSCustomObject]@{
                                    Name              = $searchResults.Properties["name"]
                                    DistinguishedName = $searchResults.Properties["distinguishedName"]
                                    ObjectGuid        = $objectGuid
                                    SID               = $objectSid
                                }))
                    }
                }
            } catch {
                Write-Verbose "Ran into issue trying to get computer membership information"
                Invoke-CatchActions
            }
            return [PSCustomObject]@{
                ComputerObject  = $computerObject
                GroupMembership = $adPrincipalGroupMembership
            }
        }
        # Extract for Pester Testing - End

        if ($PSSenderInfo) {
            $Script:ErrorsExcluded = @()
        }
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $jobStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        Invoke-DefaultConnectExchangeShell
        $resetErrors = $false
    }
    process {

        foreach ($Server in $ServerName) {
            if ($resetErrors) {
                # If we have a lot of errors, we don't want to have a lot of duplicates returned since we are in a loop.
                if ($PSSenderInfo) {
                    $Script:ErrorsExcluded = @()
                }
                $Error.Clear()
            }
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            Write-Verbose "Working on collecting information for $Server"
            $exchangeCertificateInformation = $null
            $exchangeConnectors = $null
            $serverMaintenance = $null
            $settingOverrides = $null
            $edgeTransportResourceThrottling = $null
            $serverMonitoringOverride = $null
            $getExchangeVirtualDirectories = $null

            $getExchangeServer = Get-ExchangeServer -Identity $Server
            Get-ExchangeServerCertificateInformation -Server $Server -CatchActionFunction ${Function:Invoke-CatchActions} | Invoke-RemotePipelineHandler -Result ([ref]$exchangeCertificateInformation)
            Get-ExchangeVirtualDirectories -Server $Server | Invoke-RemotePipelineHandler -Result ([ref]$getExchangeVirtualDirectories)

            try {
                $getReceiveConnectors = Get-ReceiveConnector -Server $Server -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to run Get-ReceiveConnectors"
                Invoke-CatchActions
            }

            if ($getExchangeServer.IsEdgeServer -eq $false) {

                try {
                    $getMailboxServer = (Get-MailboxServer -Identity $Server -ErrorAction Stop)
                } catch {
                    Write-Verbose "Failed to run Get-MailboxServer"
                    Invoke-CatchActions
                }
            }

            Get-ExchangeServerMaintenanceState -Server $Server -ComponentsToSkip "ForwardSyncDaemon", "ProvisioningRps" |
                Invoke-RemotePipelineHandler -Result ([ref]$serverMaintenance)
            Get-ExchangeSettingOverride -Server $Server -CatchActionFunction ${Function:Invoke-CatchActions} |
                Invoke-RemotePipelineHandler -Result ([ref]$settingOverrides)

            if (($getExchangeServer.IsMailboxServer) -or
                ($getExchangeServer.IsEdgeServer)) {
                try {
                    $exchangeServicesNotRunning = @()
                    $testServiceHealthResults = Test-ServiceHealth -Server $Server -ErrorAction Stop
                    foreach ($notRunningService in $testServiceHealthResults.ServicesNotRunning) {
                        if ($exchangeServicesNotRunning -notcontains $notRunningService) {
                            $exchangeServicesNotRunning += $notRunningService
                        }
                    }
                } catch {
                    Write-Verbose "Failed to run Test-ServiceHealth"
                    Invoke-CatchActions
                }

                try {
                    $getTransportService = Get-TransportService -Identity $Server -ErrorAction Stop
                } catch {
                    Write-Verbose "Failed to run Get-TransportService"
                    Invoke-CatchActions
                }
            }

            Write-Verbose "Getting Exchange Diagnostic Information for EdgeTransport"
            $params = @{
                Server    = $Server
                Process   = "EdgeTransport"
                Component = "ResourceThrottling"
            }
            Get-ExchangeDiagnosticInformation @params -CatchActionFunction ${Function:Invoke-CatchActions} | Invoke-RemotePipelineHandler -Result ([ref]$edgeTransportResourceThrottling)
            Get-MonitoringOverride -Server $Server | Invoke-RemotePipelineHandler -Result ([ref]$serverMonitoringOverride)

            try {
                $exchangeWebSites = $null
                Get-ExchangeWebSitesFromAd -ComputerName $Server | Invoke-RemotePipelineHandler -Result ([ref]$exchangeWebSites)

                if ($exchangeWebSites.Count -gt 2) {
                    Write-Verbose "Multiple OWA/ECP virtual directories detected"
                }
                Write-Verbose "Exchange websites detected: $([string]::Join(", ", [array]$exchangeWebSites))"
            } catch {
                Write-Verbose "Failed to get the Exchange Web Sites from Ad."
                $exchangeWebSites = $null
                Invoke-CatchActions
            }

            $getExchangeServerADInformation = $null
            GetExchangeServerADInformation -GetExchangeServer $getExchangeServer | Invoke-RemotePipelineHandler -Result ([ref]$getExchangeServerADInformation)

            if ($PSSenderInfo) {
                $jobHandledErrors = $Script:ErrorsExcluded
            }

            Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to complete processing server."
            # Place the object on the pipeline
            [PSCustomObject]@{
                ServerObjectId                  = $Server
                GetExchangeServer               = $getExchangeServer
                VirtualDirectories              = $getExchangeVirtualDirectories
                GetMailboxServer                = $getMailboxServer
                GetReceiveConnector             = $getReceiveConnectors
                ExchangeConnectors              = $exchangeConnectors
                ExchangeServicesNotRunning      = [array]$exchangeServicesNotRunning
                GetTransportService             = $getTransportService
                ServerMaintenance               = $serverMaintenance
                EdgeTransportResourceThrottling = $edgeTransportResourceThrottling # If we want to checkout other diagnosticInfo, we should create a new object here.iisSettings
                SettingOverrides                = $settingOverrides
                GetServerMonitoringOverride     = $serverMonitoringOverride
                ExchangeCertificateInformation  = $exchangeCertificateInformation
                ExchangeWebSiteNames            = $exchangeWebSites
                ADObject                        = $getExchangeServerADInformation
                RemoteJob                       = $true -eq $PSSenderInfo
                JobHandledErrors                = $jobHandledErrors
                AllErrors                       = $Error
            }
            $resetErrors = $true
        }
    }
    end {
        Write-Verbose "Completed: $($MyInvocation.MyCommand) and took $($jobStopWatch.Elapsed.TotalSeconds) seconds"
    }
}
