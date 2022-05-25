# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

function Get-ExtendedProtectionConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]
        $ComputerName,
        [Parameter(Mandatory = $true)]
        [HealthChecker.ExchangeBuildInformation]
        $BuildInformationObject
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    function NewVDirMatchingEntry {
        param(
            [string]$vDir,
            [ValidateSet("Default Web Site", "Exchange Back End")]
            [string[]]$Type,
            [ValidateSet("None", "Allow", "Require")]
            [string]$FESetting,
            [ValidateSet("None", "Allow", "Require")]
            [string]$BESetting
        )

        $returnObject = [PSCustomObject]@{
            vDir      = $vDir
            Type      = $Type
            FESetting = $null
            BESetting = $null
        }

        if ($Type.Contains("Default Web Site")) {
            $returnObject.FESetting = $FESetting
        }

        if ($Type.Contains("Exchange Back End")) {
            $returnObject.BESetting = $BESetting
        }

        return $returnObject
    }

    function NewComputerGroupEntry {
        param(
            [string]$ComputerName
        )

        return [PSCustomObject]@{
            ComputerName             = $ComputerName
            ExtendedProtectionConfig = $null
        }
    }

    function IsExtendedProtectionSupportedOnThisExchangeBuild {
        [CmdletBinding()]
        [OutputType("System.Bool")]
        param(
            [string]$VersionNumber,
            [HealthChecker.ExchangeMajorVersion]$MajorVersion
        )

        [System.Version]$buildVersionNumber = $VersionNumber

        if ($MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013) {
            $exchangeVersionSupported = ($buildVersionNumber -ge "15.0.1497.36")
        } elseif ($MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) {
            switch ($buildVersionNumber.Build) {
                ({ $_ -ge 2507 }) { $exchangeVersionSupported = $buildVersionNumber -ge "15.1.2507.9"; break }
                ({ $_ -ge 2375 }) { $exchangeVersionSupported = $buildVersionNumber -ge "15.1.2375.28"; break }
                default { $exchangeVersionSupported = $false }
            }
        } else {
            switch ($buildVersionNumber.Build) {
                ({ $_ -ge 1118 }) { $exchangeVersionSupported = $buildVersionNumber -ge "15.2.1118.9"; break }
                ({ $_ -ge 986 }) { $exchangeVersionSupported = $buildVersionNumber -ge "15.2.986.26"; break }
                default { $exchangeVersionSupported = $false }
            }
        }

        return $exchangeVersionSupported
    }

    function GetApplicationHostConfig {
        [CmdletBinding()]
        [OutputType("System.Xml.XmlNode")]
        param()

        function LoadXml {
            param(
                [System.Xml.XmlNode]$Xml,
                [string]$ConfigPath
            )

            $Xml.Load($ConfigPath)
            return $Xml
        }

        $appHostConfigPath = "$($env:WINDIR)\System32\inetsrv\config\applicationHost.config"
        $appHostConfig = New-Object -TypeName Xml
        try {
            # Wrap load() method into a simple helper function to make this work in Pester unit testing
            $xmlLoaded = LoadXml -Xml $appHostConfig -ConfigPath $appHostConfigPath -ErrorAction Stop
        } catch {
            $xmlLoaded = $null
        }

        return $xmlLoaded
    }

    function GetExtendedProtectionConfiguration {
        [CmdletBinding()]
        [OutputType("System.Object")]
        param(
            [System.Xml.XmlNode]$Xml,
            [string]$vDirPath
        )

        $vDirIndex = [array]::IndexOf(($Xml.configuration.location.path).ToLower(), $vDirPath.ToLower())
        $rootSiteIndex = [array]::IndexOf(($Xml.configuration.location.path).ToLower(), ($vDirPath.Split("/")[0]).ToLower())

        $ep = $null
        if ($vDirIndex -ne -1) {
            $configNode = $Xml.configuration.location[$vDirIndex]
            $sslSettingsString = $configNode.'system.webServer'.security.access.sslflags

            if ([System.String]::IsNullOrEmpty($sslSettingsString)) {
                # Perform fallback to root site SSL settings if no SSL settings are available on vDir
                if ($rootSiteIndex -ne -1) {
                    $rootSiteConfigNode = $Xml.configuration.location[$rootSiteIndex]
                    $sslSettingsString = $rootSiteConfigNode.'system.webServer'.security.access.sslflags
                }
            }

            if ($null -ne $sslSettingsString) {
                [array]$sslFlags = ($sslSettingsString.Split(",").ToLower()).Trim()
            }

            $sslObject = [PSCustomObject]@{
                RequireSSL         = $false
                SSL128Bit          = $false
                ClientCertificates = "Unknown"
            }

            # SSL flags: https://docs.microsoft.com/iis/configuration/system.webserver/security/access#attributes
            if ($sslFlags.Contains("none")) {
                $sslObject.ClientCertificates = "Ignore"
            } else {
                if ($sslFlags.Contains("ssl")) { $sslObject.RequireSSL = $true }
                if ($sslFlags.Contains("ssl128")) { $sslObject.SSL128Bit = $true }
                if ($sslFlags.Contains("sslnegotiatecert")) {
                    $sslObject.ClientCertificates = "Accept"
                } elseif ($sslFlags.Contains("sslrequirecert")) {
                    $sslObject.ClientCertificates = "Require"
                } else {
                    $sslObject.ClientCertificates = "Ignore"
                }
            }

            $ep = $configNode.'system.webServer'.security.authentication.windowsAuthentication.extendedProtection.tokenChecking
            if ([System.String]::IsNullOrEmpty($ep)) {
                $ep = "None"
            }
        }

        return [PSCustomObject]@{
            ExtendedProtection = $ep
            SSLConfiguration   = $sslObject
            vDirExistsOnSystem = ($vDirIndex -ne -1)
        }
    }

    $extendedConfigurationSupportedValues = @("none", "allow", "require")
    $returnedResults = NewComputerGroupEntry -ComputerName $ComputerName
    $extendedProtectionResults = New-Object 'System.Collections.Generic.List[object]'

    if ([System.String]::IsNullOrEmpty($ComputerName)) {
        Write-Verbose "ComputerName was not set - calls will be executed against the local machine"
        $ComputerName = $env:COMPUTERNAME
    }

    Write-Verbose "Working on computer: $ComputerName"
    Write-Verbose "Testing if passed Exchange version number: $($BuildInformationObject.ExchangeSetup.FileVersion) supports extended protection"
    $isBuildSupportedParam = @{
        VersionNumber = $BuildInformationObject.ExchangeSetup.FileVersion
        MajorVersion  = $BuildInformationObject.MajorVersion
    }
    try {
        $BuildInformationObject.IsEPSupportedBuild = IsExtendedProtectionSupportedOnThisExchangeBuild @isBuildSupportedParam
    } catch {
        Invoke-CatchActions
        Write-Verbose "Unable to validate if Exchange build supports Extended Protection or not. Assuming that we don't support it."
    }

    # vDirs for which Extended Protection settings should validated
    $vDirLists = @(
        (NewVDirMatchingEntry -vDir "API" -Type "Default Web Site", "Exchange Back End" -FESetting "Require" -BESetting "Require")
        (NewVDirMatchingEntry -vDir "Autodiscover" -Type "Default Web Site", "Exchange Back End" -FESetting "None" -BESetting "None")
        (NewVDirMatchingEntry -vDir "ECP" -Type "Default Web Site", "Exchange Back End" -FESetting "Require" -BESetting "Require")
        (NewVDirMatchingEntry -vDir "EWS" -Type "Default Web Site", "Exchange Back End" -FESetting "Allow" -BESetting "Require")
        (NewVDirMatchingEntry -vDir "Microsoft-Server-ActiveSync" -Type "Default Web Site", "Exchange Back End" -FESetting "Require" -BESetting "Require")
        (NewVDirMatchingEntry -vDir "OAB" -Type "Default Web Site", "Exchange Back End" -FESetting "Require" -BESetting "Require")
        (NewVDirMatchingEntry -vDir "Powershell" -Type "Default Web Site", "Exchange Back End" -FESetting "Require" -BESetting "Require")
        (NewVDirMatchingEntry -vDir "OWA" -Type "Default Web Site", "Exchange Back End" -FESetting "Require" -BESetting "Require")
        (NewVDirMatchingEntry -vDir "RPC" -Type "Default Web Site", "Exchange Back End" -FESetting "Require" -BESetting "Require")
        (NewVDirMatchingEntry -vDir "MAPI" -Type "Default Web Site" -FESetting "Require")
        (NewVDirMatchingEntry -vDir "PushNotifications" -Type "Exchange Back End" -BESetting "Require")
        (NewVDirMatchingEntry -vDir "RPCWithCert" -Type "Exchange Back End" -BESetting "Require")
        (NewVDirMatchingEntry -vDir "MAPI/emsmdb" -Type "Exchange Back End" -BESetting "Require")
        (NewVDirMatchingEntry -vDir "MAPI/nspi" -Type "Exchange Back End" -BESetting "Require")
    )

    Write-Verbose "Trying to load: 'applicationHost.config' from: $ComputerName"
    $applicationHostConfigScriptBlockParam = @{
        ComputerName        = $ComputerName
        ScriptBlock         = ${Function:GetApplicationHostConfig}
        CatchActionFunction = ${Function:Invoke-CatchActions}
    }
    $applicationHostConfig = Invoke-ScriptBlockHandler @applicationHostConfigScriptBlockParam

    if ($null -ne $applicationHostConfig) {
        Write-Verbose "'applicationHost.config' was loaded successfully"
        foreach ($listEntry in $vDirLists) {
            Write-Verbose "Validating extended protection setting for: $($listEntry.vDir)"

            try {
                foreach ($type in $listEntry.Type) {
                    Write-Verbose "Validating extended protection settings for type: $type"
                    $expectedConfigValueBasedOnBuild = "None"
                    if ($BuildInformationObject.IsEPSupportedBuild) {
                        if ($type -eq "Default Web Site") {
                            $expectedConfigValueBasedOnBuild = if ($null -ne $listEntry.FESetting) { $listEntry.FESetting } else { "None" }
                        } else {
                            $expectedConfigValueBasedOnBuild = if ($null -ne $listEntry.BESetting) { $listEntry.BESetting } else { "None" }
                        }
                    }

                    $extendedConfiguration = GetExtendedProtectionConfiguration -Xml $applicationHostConfig -vDirPath "$type/$($listEntry.vDir)"

                    # Extended Protection is a windows security feature which blocks MiTM attacks.
                    # Supported server roles are: Mailbox and ClientAccess
                    # Possible configuration settings are:
                    # <None>: This value specifies that IIS will not perform channel-binding token checking.
                    # <Allow>: This value specifies that channel-binding token checking is enabled, but not required.
                    # <Require>: This value specifies that channel-binding token checking is required.
                    # https://docs.microsoft.com/iis/configuration/system.webserver/security/authentication/windowsauthentication/extendedprotection/
                    if ($extendedConfiguration.vDirExistsOnSystem) {
                        Write-Verbose "Configuration was successfully returned: $($extendedConfiguration.ExtendedProtection)"
                        Write-Verbose "Extended protection configuration value expected: $expectedConfigValueBasedOnBuild"
                        if ($expectedConfigValueBasedOnBuild -eq "None") {
                            $configSupported = ($extendedConfiguration.ExtendedProtection -eq $expectedConfigValueBasedOnBuild)
                        } else {
                            $configSupported = $extendedConfigurationSupportedValues.Contains(($extendedConfiguration.ExtendedProtection).ToLower())
                        }
                        Write-Verbose "Is current extended protection configuration supported? $configSupported"

                        $extendedProtectionResults.Add([PSCustomObject]@{
                                vDir               = $listEntry.vDir
                                Type               = $type
                                ExtendedProtection = $extendedConfiguration.ExtendedProtection
                                MaxSupportedValue  = $expectedConfigValueBasedOnBuild
                                CheckPass          = ($extendedConfiguration.ExtendedProtection -eq $expectedConfigValueBasedOnBuild)
                                SSLConfiguration   = $extendedConfiguration.SSLConfiguration
                                ConfigSupported    = $configSupported
                            })
                    } else {
                        Write-Verbose "Extended protection setting was not queried as the vDir or type doesn't exist on the target system"
                    }
                }
            } catch {
                Write-Verbose "Failed while processing: $($listEntry.vDir) in: $($listEntry.Type)"
                Invoke-CatchActions
            }
        }

        $returnedResults.ExtendedProtectionConfig = $extendedProtectionResults
    } else {
        Write-Verbose "Unable to load 'applicationHost.config' - Extended Protection check can't be performed."
    }
    return $returnedResults
}
