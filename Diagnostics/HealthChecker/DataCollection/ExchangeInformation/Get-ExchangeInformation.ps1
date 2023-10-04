# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-ExtendedProtectionConfiguration.ps1
. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeBuildVersionInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeSettingOverride.ps1
. $PSScriptRoot\IISInformation\Get-ExchangeAppPoolsInformation.ps1
. $PSScriptRoot\IISInformation\Get-ExchangeServerIISSettings.ps1
. $PSScriptRoot\Get-ExchangeAES256CBCDetails.ps1
. $PSScriptRoot\Get-ExchangeApplicationConfigurationFileValidation.ps1
. $PSScriptRoot\Get-ExchangeConnectors.ps1
. $PSScriptRoot\Get-ExchangeDependentServices.ps1
. $PSScriptRoot\Get-ExchangeRegistryValues.ps1
. $PSScriptRoot\Get-ExchangeServerCertificates.ps1
. $PSScriptRoot\Get-ExchangeServerMaintenanceState.ps1
. $PSScriptRoot\Get-ExchangeUpdates.ps1
. $PSScriptRoot\Get-ExchangeVirtualDirectories.ps1
. $PSScriptRoot\Get-ExSetupDetails.ps1
. $PSScriptRoot\Get-FIPFSScanEngineVersionState.ps1
. $PSScriptRoot\Get-ServerRole.ps1
function Get-ExchangeInformation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $params = @{
            ComputerName           = $Server
            ScriptBlock            = { [environment]::OSVersion.Version -ge "10.0.0.0" }
            ScriptBlockDescription = "Windows 2016 or Greater Check"
            CatchActionFunction    = ${Function:Invoke-CatchActions}
        }
        $windows2016OrGreater = Invoke-ScriptBlockHandler @params
        $getExchangeServer = (Get-ExchangeServer -Identity $Server -Status)
        $exchangeCertificates = Get-ExchangeServerCertificates -Server $Server
        $exSetupDetails = Get-ExSetupDetails -Server $Server
        $versionInformation = (Get-ExchangeBuildVersionInformation -FileVersion ($exSetupDetails.FileVersion))

        $buildInformation = [PSCustomObject]@{
            ServerRole         = (Get-ServerRole -ExchangeServerObj $getExchangeServer)
            MajorVersion       = $versionInformation.MajorVersion
            CU                 = $versionInformation.CU
            ExchangeSetup      = $exSetupDetails
            VersionInformation = $versionInformation
            KBsInstalled       = [array](Get-ExchangeUpdates -Server $Server -ExchangeMajorVersion $versionInformation.MajorVersion)
        }

        $dependentServices = (Get-ExchangeDependentServices -MachineName $Server)

        try {
            $getMailboxServer = (Get-MailboxServer -Identity $Server -ErrorAction Stop)
        } catch {
            Write-Verbose "Failed to run Get-MailboxServer"
            Invoke-CatchActions
        }

        $getExchangeVirtualDirectories = Get-ExchangeVirtualDirectories -Server $Server

        $registryValues = Get-ExchangeRegistryValues -MachineName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $serverExchangeBinDirectory = [System.Io.Path]::Combine($registryValues.MsiInstallPath, "Bin\")
        Write-Verbose "Found Exchange Bin: $serverExchangeBinDirectory"

        if ($getExchangeServer.IsEdgeServer -eq $false) {
            $applicationPools = Get-ExchangeAppPoolsInformation -Server $Server

            Write-Verbose "Query Exchange Connector settings via 'Get-ExchangeConnectors'"
            $exchangeConnectors = Get-ExchangeConnectors -ComputerName $Server -CertificateObject $exchangeCertificates

            $exchangeServerIISParams = @{
                ComputerName        = $Server
                IsLegacyOS          = ($windows2016OrGreater -eq $false)
                CatchActionFunction = ${Function:Invoke-CatchActions}
            }

            Write-Verbose "Trying to query Exchange Server IIS settings"
            $iisSettings = Get-ExchangeServerIISSettings @exchangeServerIISParams

            Write-Verbose "Query extended protection configuration for multiple CVEs testing"
            $getExtendedProtectionConfigurationParams = @{
                ComputerName        = $Server
                ExSetupVersion      = $buildInformation.ExchangeSetup.FileVersion
                CatchActionFunction = ${Function:Invoke-CatchActions}
            }

            try {
                if ($null -ne $iisSettings.ApplicationHostConfig) {
                    $getExtendedProtectionConfigurationParams.ApplicationHostConfig = [xml]$iisSettings.ApplicationHostConfig
                }
                Write-Verbose "Was able to convert the ApplicationHost.Config to XML"

                $extendedProtectionConfig = Get-ExtendedProtectionConfiguration @getExtendedProtectionConfigurationParams
            } catch {
                Write-Verbose "Failed to get the ExtendedProtectionConfig"
                Invoke-CatchActions
            }
        }

        $applicationConfigFileStatus = Get-ExchangeApplicationConfigurationFileValidation -ComputerName $Server -ConfigFileLocation ("{0}EdgeTransport.exe.config" -f $serverExchangeBinDirectory)
        $serverMaintenance = Get-ExchangeServerMaintenanceState -Server $Server -ComponentsToSkip "ForwardSyncDaemon", "ProvisioningRps"
        $settingOverrides = Get-ExchangeSettingOverride -Server $Server -CatchActionFunction ${Function:Invoke-CatchActions}

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
        }

        Write-Verbose "Checking if FIP-FS is affected by the pattern issue"
        $fipFsParams = @{
            ComputerName       = $Server
            ExSetupVersion     = $buildInformation.ExchangeSetup.FileVersion
            AffectedServerRole = $($getExchangeServer.IsMailboxServer -eq $true)
        }

        $FIPFSUpdateIssue = Get-FIPFSScanEngineVersionState @fipFsParams

        $eemsEndpointParams = @{
            ComputerName           = $Server
            ScriptBlockDescription = "Test EEMS pattern service connectivity"
            CatchActionFunction    = ${Function:Invoke-CatchActions}
            ArgumentList           = $getExchangeServer.InternetWebProxy
            ScriptBlock            = {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                if ($null -ne $args[0]) {
                    Write-Verbose "Proxy Server detected. Going to use: $($args[0])"
                    [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($args[0])
                    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                    [System.Net.WebRequest]::DefaultWebProxy.BypassProxyOnLocal = $true
                }
                Invoke-WebRequest -Method Get -Uri "https://officeclient.microsoft.com/GetExchangeMitigations" -UseBasicParsing
            }
        }
        $eemsEndpointResults = Invoke-ScriptBlockHandler @eemsEndpointParams

        Write-Verbose "Checking AES256-CBC information protection readiness and configuration"
        $aes256CbcParams = @{
            Server             = $Server
            VersionInformation = $versionInformation
        }
        $aes256CbcDetails = Get-ExchangeAES256CBCDetails @aes256CbcParams
    } end {

        Write-Verbose "Exiting: Get-ExchangeInformation"
        return [PSCustomObject]@{
            BuildInformation                         = $buildInformation
            GetExchangeServer                        = $getExchangeServer
            VirtualDirectories                       = $getExchangeVirtualDirectories
            GetMailboxServer                         = $getMailboxServer
            ExtendedProtectionConfig                 = $extendedProtectionConfig
            ExchangeConnectors                       = $exchangeConnectors
            ExchangeServicesNotRunning               = [array]$exchangeServicesNotRunning
            ApplicationPools                         = $applicationPools
            RegistryValues                           = $registryValues
            ServerMaintenance                        = $serverMaintenance
            ExchangeCertificates                     = [array]$exchangeCertificates
            ExchangeEmergencyMitigationServiceResult = $eemsEndpointResults
            ApplicationConfigFileStatus              = $applicationConfigFileStatus
            DependentServices                        = $dependentServices
            IISSettings                              = $iisSettings
            SettingOverrides                         = $settingOverrides
            FIPFSUpdateIssue                         = $FIPFSUpdateIssue
            AES256CBCInformation                     = $aes256CbcDetails
        }
    }
}
