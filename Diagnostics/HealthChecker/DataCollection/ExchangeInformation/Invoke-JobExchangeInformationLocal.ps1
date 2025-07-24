# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-JobExchangeInformationLocal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$GetExchangeServer
    )
    begin {
        # Extract for Pester Testing - Start
        # Build Process to add functions.
        . $PSScriptRoot\Get-ExchangeDependentServices.ps1
        . $PSScriptRoot\Get-ExchangeRegistryValues.ps1
        . $PSScriptRoot\Get-ExchangeAES256CBCDetails.ps1
        . $PSScriptRoot\Get-FIPFSScanEngineVersionState.ps1
        . $PSScriptRoot\Get-ExchangeUpdates.ps1
        . $PSScriptRoot\IISInformation\Get-ExchangeAppPoolsInformation.ps1
        . $PSScriptRoot\IISInformation\Get-ExchangeServerIISSettings.ps1
        . $PSScriptRoot\..\..\..\..\Shared\Get-ExSetupFileVersionInfo.ps1
        . $PSScriptRoot\..\..\..\..\Shared\Get-FileContentInformation.ps1
        # Extract for Pester Testing - End

        if ($PSSenderInfo) {
            $Script:ErrorsExcluded = @()
        }

        $dependentServices = $null
        $registryValues = $null
        $applicationPools = $null
        $iisSettings = $null
        $applicationConfigFileStatus = @{}
        $fileContentInformation = @{}
        $getFileContentInformation = $null
        $ianaTimeZoneMappingContent = $false
        $FIPFSUpdateIssue = $null
        $aes256CbcDetails = $null
        $eemsEndpointResults = $null
        $exSetupDetails = $null
        $versionInformation = $null
        $getExchangeUpdates = $null
        $jobStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
    process {
        $windows2016OrGreater = [environment]::OSVersion.Version -ge "10.0.0.0"
        Get-ExSetupFileVersionInfo -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$exSetupDetails)

        if ($null -eq $exSetupDetails) {
            # couldn't find ExSetup.exe this should be rare so we are just going to handle this by displaying the AdminDisplayVersion from Get-ExchangeServer
            Get-ExchangeBuildVersionInformation -AdminDisplayVersion $getExchangeServer.AdminDisplayVersion |
                Invoke-RemotePipelineHandler -Result ([ref]$versionInformation)
            $exSetupDetails = [PSCustomObject]@{
                FileVersion      = $versionInformation.BuildVersion.ToString()
                FileBuildPart    = $versionInformation.BuildVersion.Build
                FilePrivatePart  = $versionInformation.BuildVersion.Revision
                FileMajorPart    = $versionInformation.BuildVersion.Major
                FileMinorPart    = $versionInformation.BuildVersion.Minor
                FailedGetExSetup = $true
            }
        } else {
            Get-ExchangeBuildVersionInformation -FileVersion ($exSetupDetails.FileVersion) |
                Invoke-RemotePipelineHandler -Result ([ref]$versionInformation)
        }

        [string]$role = $GetExchangeServer.ServerRole
        Write-Verbose "Role: $role"

        if ($role -like "Mailbox,ClientAccess*") { $serverRole = "MultiRole" }
        elseif ($role -like "*ClientAccess*") { $serverRole = "ClientAccess" }
        elseif (-not ([string]::IsNullOrEmpty($role))) { $serverRole = $role }

        # Not an Exchange Cmdlet, but going to keep this here now.
        Get-ExchangeUpdates -ExchangeMajorVersion $versionInformation.MajorVersion | Invoke-RemotePipelineHandler -Result ([ref]$getExchangeUpdates)
        [array]$getExchangeUpdates = @($getExchangeUpdates)

        $buildInformation = [PSCustomObject]@{
            ServerRole         = $serverRole
            MajorVersion       = $versionInformation.MajorVersion
            CU                 = $versionInformation.CU
            ExchangeSetup      = $exSetupDetails
            VersionInformation = $versionInformation
            KBsInstalledInfo   = [array]$getExchangeUpdates
        }

        Get-ExchangeDependentServices | Invoke-RemotePipelineHandler -Result ([ref]$dependentServices)
        Get-ExchangeRegistryValues -CatchActionFunction ${Function:Invoke-CatchActions} | Invoke-RemotePipelineHandler -Result ([ref]$registryValues)
        $serverExchangeBinDirectory = [System.Io.Path]::Combine($registryValues.MsiInstallPath, "Bin\")
        Write-Verbose "Found Exchange Bin: $serverExchangeBinDirectory"

        if ($GetExchangeServer.IsEdgeServer -eq $false) {
            Get-ExchangeAppPoolsInformation | Invoke-RemotePipelineHandler -Result ([ref]$applicationPools)

            $exchangeServerIISParams = @{
                IsLegacyOS          = ($windows2016OrGreater -eq $false)
                CatchActionFunction = ${Function:Invoke-CatchActions}
            }
            Write-Verbose "Trying to query Exchange Server IIS settings"
            Get-ExchangeServerIISSettings @exchangeServerIISParams | Invoke-RemotePipelineHandler -Result ([ref]$iisSettings)

            try {
                $localGroupMember = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop
                $computerMembership = [PSCustomObject]@{
                    LocalGroupMember = $localGroupMember
                }
            } catch {
                Write-Verbose "Failed to run Get-LocalGroupMember. Inner Exception: $_"
            }
        }

        $configParams = @{
            ComputerName = $env:COMPUTERNAME
            FileLocation = @("$([System.IO.Path]::Combine($serverExchangeBinDirectory, "EdgeTransport.exe.config"))",
                "$([System.IO.Path]::Combine($serverExchangeBinDirectory, "Search\Ceres\Runtime\1.0\noderunner.exe.config"))",
                "$([System.IO.Path]::Combine($serverExchangeBinDirectory, "Monitoring\Config\AntiMalware.xml"))",
                "$([System.IO.Path]::Combine($serverExchangeBinDirectory, "IanaTimeZoneMappings.xml"))")
        }

        if ($GetExchangeServer.IsEdgeServer -eq $false -and
            (-not ([string]::IsNullOrEmpty($registryValues.FipFsDatabasePath)))) {
            $configParams.FileLocation += "$([System.IO.Path]::Combine($registryValues.FipFsDatabasePath, "Configuration.xml"))"
        }

        Get-FileContentInformation @configParams | Invoke-RemotePipelineHandler -Result ([ref]$getFileContentInformation)

        foreach ($key in $getFileContentInformation.Keys) {
            if ($key -like "*.exe.config") {
                $applicationConfigFileStatus.Add($key, $getFileContentInformation[$key])
            } elseif ($key -like "*IanaTimeZoneMappings.xml") {
                if (($getFileContentInformation[$key]).Present) {
                    Write-Verbose "IanaTimeZoneMappings.xml file exists"
                    $ianaTimeZoneMappingContent = ($getFileContentInformation[$key]).Content
                } else {
                    Write-Verbose "IanaTimeZoneMappings.xml doesn't exist"
                }
            } else {
                $fileContentInformation.Add($key, $getFileContentInformation[$key])
            }
        }

        Write-Verbose "Checking AES256-CBC information protection readiness and configuration"
        Get-ExchangeAES256CBCDetails -VersionInformation $versionInformation | Invoke-RemotePipelineHandler -Result ([ref]$aes256CbcDetails)

        Write-Verbose "Checking if FIP-FS is affected by the pattern issue"
        $fipFsParams = @{
            ExSetupVersion     = $buildInformation.ExchangeSetup.FileVersion
            AffectedServerRole = $($GetExchangeServer.IsMailboxServer -eq $true)
        }
        Get-FIPFSScanEngineVersionState @fipFsParams | Invoke-RemotePipelineHandler -Result ([ref]$FIPFSUpdateIssue)

        # Extract for Pester Testing - Start
        function Get-InvokeWebRequestResult {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$Uri
            )
            try {
                Write-Verbose "Trying to get endpoint Uri: $Uri"
                $results = Invoke-WebRequest -Method Get -Uri $Uri -UseBasicParsing
                Write-Verbose "Successfully got the results"
            } catch {
                Invoke-CatchActions
            }
            return $results
        }
        # Extract for Pester Testing - End

        try {
            $originalSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            if ($null -ne $GetExchangeServer.InternetWebProxy) {
                Write-Verbose "Proxy Server detected. Going to use: $($GetExchangeServer.InternetWebProxy)"
                [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($GetExchangeServer.InternetWebProxy)
                [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                [System.Net.WebRequest]::DefaultWebProxy.BypassProxyOnLocal = $true
            } else {
                Write-Verbose "No Proxy Server Detected."
            }

            Write-Verbose "Attempting to get the endpoints from the server"
            $eemsEndpointResults = Get-InvokeWebRequestResult -Uri "https://officeclient.microsoft.com/GetExchangeMitigations"
            $featureFlightingEndpointResults = Get-InvokeWebRequestResult -Uri "https://officeclient.microsoft.com/GetExchangeConfig"
        } catch {
            Invoke-CatchActions
        } finally {
            [Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol
        }

        if ($PSSenderInfo) {
            $jobHandledErrors = $Script:ErrorsExcluded
        }
    }
    end {
        Write-Verbose "Completed: $($MyInvocation.MyCommand) and took $($jobStopWatch.Elapsed.TotalSeconds) seconds"
        [PSCustomObject]@{
            BuildInformation                         = $buildInformation
            ApplicationPools                         = $applicationPools
            RegistryValues                           = $registryValues
            ExchangeEmergencyMitigationServiceResult = $eemsEndpointResults
            ExchangeFeatureFlightingServiceResult    = $featureFlightingEndpointResults
            ApplicationConfigFileStatus              = $applicationConfigFileStatus
            DependentServices                        = $dependentServices
            IISSettings                              = $iisSettings
            FIPFSUpdateIssue                         = $FIPFSUpdateIssue
            AES256CBCInformation                     = $aes256CbcDetails
            IanaTimeZoneMappingsRaw                  = $ianaTimeZoneMappingContent
            FileContentInformation                   = $fileContentInformation
            ComputerMembership                       = $computerMembership
            RemoteJob                                = $true -eq $PSSenderInfo
            JobHandledErrors                         = $jobHandledErrors
        }
    }
}
