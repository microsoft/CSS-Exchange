# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Analyzer\Get-ExchangeConnectorCustomObject.ps1
. $PSScriptRoot\..\Analyzer\Security\Get-ExchangeCertificateCustomObject.ps1
. $PSScriptRoot\..\..\..\Shared\CertificateFunctions\ConvertTo-ExchangeCertificate.ps1

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
                InternalTransportCertificate = $ExchangeCmdletResult.ExchangeCertificateInformation.InternalCertificate
                AuthConfig                   = $OrganizationInformationResult.GetAuthConfig
            }

            $exchangeCertificateInformation = [PSCustomObject]@{
                Certificates        = $certs
                InternalCertificate = $ExchangeCmdletResult.ExchangeCertificateInformation.InternalCertificate
                CustomCertificates  = ($certs | Get-ExchangeCertificateCustomObject @certCustomParams)
            }

            [array]$connector = $OrganizationInformationResult.GetSendConnector
            [array]$connector += $ExchangeCmdletResult.GetReceiveConnector
            $customConnectorParams = @{
                Connector   = $connector
                Certificate = $certs
            }

            $exchangeCustomConnector = Get-ExchangeConnectorCustomObject @customConnectorParams
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
                ComputerMembership                       = [PSCustomObject]@{
                    ADGroupMembership = $ExchangeCmdletResult.ComputerMembership.ADGroupMembership
                    LocalGroupMember  = $ExchangeLocalResult.ComputerMembership.LocalGroupMember
                }
                AES256CBCInformation                     = $ExchangeLocalResult.AES256CBCInformation
                ApplicationConfigFileStatus              = $ExchangeLocalResult.ApplicationConfigFileStatus
                ApplicationPools                         = $ExchangeLocalResult.ApplicationPools
                BuildInformation                         = $ExchangeLocalResult.BuildInformation
                DependentServices                        = $ExchangeLocalResult.DependentServices
                ExchangeEmergencyMitigationServiceResult = $ExchangeLocalResult.ExchangeEmergencyMitigationServiceResult
                ExchangeFeatureFlightingServiceResult    = $ExchangeLocalResult.ExchangeFeatureFlightingServiceResult
                ExtendedProtectionConfig                 = $ExchangeLocalResult.ExtendedProtectionConfig
                FileContentInformation                   = $ExchangeLocalResult.FileContentInformation
                FIPFSUpdateIssue                         = $ExchangeLocalResult.FIPFSUpdateIssue
                IanaTimeZoneMappingsRaw                  = $ExchangeLocalResult.IanaTimeZoneMappingsRaw
                IISSettings                              = $ExchangeLocalResult.IISSettings
                RegistryValues                           = $ExchangeLocalResult.RegistryValues
                ExchangeCustomConnector                  = $exchangeCustomConnector
            }
        }

        return $hcObject
    }
}
