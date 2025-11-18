# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Analyzer\Get-ExchangeConnectorCustomObject.ps1
. $PSScriptRoot\..\Analyzer\Security\Get-ExchangeCertificateCustomObject.ps1
. $PSScriptRoot\..\..\..\Shared\CertificateFunctions\ConvertTo-ExchangeCertificate.ps1
. $PSScriptRoot\..\..\..\Shared\IISFunctions\ExtendedProtection\Get-ExtendedProtectionConfigurationResult.ps1

<#
.DESCRIPTION
    This function is to create a single object from all the different jobs that was sent out to the server to collect information.
    Because some of the data structures require information from different jobs, we need create them here to be in a similar data structure as before
    within the analyzer selection.
#>
function Get-HealthCheckerDataObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$OrganizationInformationResult,

        [Parameter(Mandatory = $true)]
        [object]$ExchangeCmdletResult,

        [Parameter(Mandatory = $true)]
        [object]$ExchangeLocalResult,

        [Parameter(Mandatory = $true)]
        [object]$HardwareInformationResult,

        [Parameter(Mandatory = $true)]
        [object]$OSInformationResult,

        [Parameter(Mandatory = $true)]
        [DateTime]$GenerationTime
    )
    process {

        if ($null -ne $ExchangeCmdletResult.ExchangeCertificateInformation) {
            $certs = ($ExchangeCmdletResult.ExchangeCertificateInformation.Certificates | ConvertTo-ExchangeCertificate -CatchActionFunction ${Function:Invoke-CatchActions})
            $certCustomParams = @{
                InternalTransportCertificateThumbprint = $ExchangeCmdletResult.ExchangeCertificateInformation.InternalCertificateThumbprint
                AuthConfig                             = $OrganizationInformationResult.GetAuthConfig
            }

            $exchangeCertificateInformation = [PSCustomObject]@{
                Certificates                  = $certs
                InternalCertificateThumbprint = $ExchangeCmdletResult.ExchangeCertificateInformation.InternalCertificateThumbprint
                CustomCertificates            = ($certs | Get-ExchangeCertificateCustomObject @certCustomParams)
            }

            [array]$connector = $OrganizationInformationResult.GetSendConnector
            [array]$connector += $ExchangeCmdletResult.GetReceiveConnector
            $customConnectorParams = @{
                Connector   = $connector
                Certificate = $certs
            }

            $exchangeCustomConnector = Get-ExchangeConnectorCustomObject @customConnectorParams
        }

        if (-not $ExchangeCmdletResult.GetExchangeServer.IsEdgeServer) {
            # Adjust the IIS information.
            # We need to Adjust the IIS information to remove the non Exchange IIS sites that we determined from AD and locally on the server.
            $iisSettings = $ExchangeLocalResult.IISSettings
            $webSites = New-Object System.Collections.Generic.List[object]
            $nonExchangeWebSites = New-Object System.Collections.Generic.List[object]

            if ($null -ne $iisSettings.IISWebSite) {
                $iisSettings.IISWebSite |
                    ForEach-Object {
                        $site = $_
                        $currentCount = $webSites.Count
                        foreach ($name in $ExchangeCmdletResult.ExchangeWebSiteNames) {
                            if ($name -eq $site.Name) {
                                $webSites.Add($site)
                            }
                        }

                        if ($currentCount -eq $webSites.Count) {
                            $nonExchangeWebSites.Add($site)
                        }
                    }

                if ($webSites.Count -gt 0) {
                    $iisSettings.IISWebSite = $webSites
                    $iisSettings | Add-Member -Name "NonExchangeWebSites" -MemberType NoteProperty -Value $nonExchangeWebSites
                } else {
                    Write-Verbose "No IIS Web Sites were found that matched the ExchangeWebSiteNames so we are placing all the sites in the main container."
                    $iisSettings.IISWebSite = $nonExchangeWebSites
                }
            }

            $extendedProtectionConfig = $null

            try {
                $getExtendedProtectionConfigurationResultsParams = @{
                    ApplicationHostConfig = [xml]$iisSettings.ApplicationHostConfig
                    ExSetupVersion        = $ExchangeLocalResult.BuildInformation.VersionInformation.BuildVersion
                    CatchActionFunction   = ${Function:Invoke-CatchActions}
                }
                $extendedProtectionConfig = Get-ExtendedProtectionConfigurationResult @getExtendedProtectionConfigurationResultsParams
            } catch {
                Invoke-CatchActions
            }
        } else {
            Write-Verbose "Processing an Edge Server, so not processing IIS Settings"
            $iisSettings = $null
        }

        $hcObject = [PSCustomObject]@{
            GenerationTime          = $GenerationTime
            HealthCheckerVersion    = $Script:BuildVersion
            ServerName              = $ExchangeCmdletResult.ServerObjectId
            OrganizationInformation = $OrganizationInformationResult
            HardwareInformation     = $HardwareInformationResult
            OSInformation           = $OSInformationResult
            ExchangeInformation     = [PSCustomObject]@{
                EdgeTransportResourceThrottling          = $ExchangeCmdletResult.EdgeTransportResourceThrottling
                ExchangeServicesNotRunning               = $ExchangeCmdletResult.ExchangeServicesNotRunning
                GetExchangeServer                        = $ExchangeCmdletResult.GetExchangeServer
                GetMailboxServer                         = $ExchangeCmdletResult.GetMailboxServer
                GetServerMonitoringOverride              = $ExchangeCmdletResult.GetServerMonitoringOverride
                GetTransportService                      = $ExchangeCmdletResult.GetTransportService
                GetReceiveConnector                      = $ExchangeCmdletResult.GetReceiveConnector
                ServerMaintenance                        = $ExchangeCmdletResult.ServerMaintenance
                SettingOverrides                         = $ExchangeCmdletResult.SettingOverrides
                VirtualDirectories                       = $ExchangeCmdletResult.VirtualDirectories
                ExchangeCertificateInformation           = $exchangeCertificateInformation
                ADComputerObject                         = [PSCustomObject]@{
                    ADObject          = $ExchangeCmdletResult.ADObject.ComputerObject
                    ADGroupMembership = $ExchangeCmdletResult.ADObject.GroupMembership
                    LocalGroupMember  = $ExchangeLocalResult.LocalGroupMember
                }
                AES256CBCInformation                     = $ExchangeLocalResult.AES256CBCInformation
                ApplicationConfigFileStatus              = $ExchangeLocalResult.ApplicationConfigFileStatus
                ApplicationPools                         = $ExchangeLocalResult.ApplicationPools
                BuildInformation                         = $ExchangeLocalResult.BuildInformation
                DependentServices                        = $ExchangeLocalResult.DependentServices
                ExchangeEmergencyMitigationServiceResult = $ExchangeLocalResult.ExchangeEmergencyMitigationServiceResult
                ExchangeFeatureFlightingServiceResult    = $ExchangeLocalResult.ExchangeFeatureFlightingServiceResult
                ExtendedProtectionConfig                 = $extendedProtectionConfig
                FileContentInformation                   = $ExchangeLocalResult.FileContentInformation
                FIPFSUpdateIssue                         = $ExchangeLocalResult.FIPFSUpdateIssue
                IanaTimeZoneMappingsRaw                  = $ExchangeLocalResult.IanaTimeZoneMappingsRaw
                IISSettings                              = $iisSettings
                RegistryValues                           = $ExchangeLocalResult.RegistryValues
                ExchangeCustomConnector                  = $exchangeCustomConnector
            }
        }

        return $hcObject
    }
}
