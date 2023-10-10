# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchActionError.ps1
. $PSScriptRoot\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\Write-ErrorInformation.ps1

function Get-ExtendedProtectionConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Xml.XmlNode]$ApplicationHostConfig,

        [Parameter(Mandatory = $false)]
        [System.Version]$ExSetupVersion,

        [Parameter(Mandatory = $false)]
        [bool]$IsMailboxServer = $true,

        [Parameter(Mandatory = $false)]
        [bool]$IsClientAccessServer = $true,

        [Parameter(Mandatory = $false)]
        [bool]$ExcludeEWS = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Exchange Back End/EWS")]
        [string[]]$SiteVDirLocations,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        function NewVirtualDirMatchingEntry {
            param(
                [Parameter(Mandatory = $true)]
                [string]$VirtualDirectory,
                [Parameter(Mandatory = $true)]
                [ValidateSet("Default Web Site", "Exchange Back End")]
                [string[]]$WebSite,
                [Parameter(Mandatory = $true)]
                [ValidateSet("None", "Allow", "Require")]
                [string[]]$ExtendedProtection,
                # Need to define this twice once for Default Web Site and Exchange Back End for the default values
                [Parameter(Mandatory = $false)]
                [string[]]$SslFlags = @("Ssl,Ssl128", "Ssl,Ssl128")
            )

            if ($WebSite.Count -ne $ExtendedProtection.Count) {
                throw "Argument count mismatch on $VirtualDirectory"
            }

            for ($i = 0; $i -lt $WebSite.Count; $i++) {
                # special conditions for Exchange 2013
                # powershell is on front and back so skip over those
                if ($IsExchange2013 -and $virtualDirectory -ne "Powershell") {
                    # No API virtual directory
                    if ($virtualDirectory -eq "API") { return }
                    if ($IsClientAccessServer -eq $false -and $WebSite[$i] -eq "Default Web Site") { continue }
                    if ($IsMailboxServer -eq $false -and $WebSite[$i] -eq "Exchange Back End") { continue }
                }
                # Set EWS VDir to None for known issues
                if ($ExcludeEWS -and $virtualDirectory -eq "EWS") { $ExtendedProtection[$i] = "None" }

                if ($null -ne $SiteVDirLocations -and
                    $SiteVDirLocations.Count -gt 0) {
                    foreach ($SiteVDirLocation in $SiteVDirLocations) {
                        if ($SiteVDirLocation -eq "$($WebSite[$i])/$virtualDirectory") {
                            Write-Verbose "Set Extended Protection to None because of restriction override '$($WebSite[$i])\$virtualDirectory'"
                            $ExtendedProtection[$i] = "None"
                            break;
                        }
                    }
                }

                [PSCustomObject]@{
                    VirtualDirectory   = $virtualDirectory
                    WebSite            = $WebSite[$i]
                    ExtendedProtection = $ExtendedProtection[$i]
                    SslFlags           = $SslFlags[$i]
                }
            }
        }

        # Intended for inside of Invoke-Command.
        function GetApplicationHostConfig {
            $appHostConfig = New-Object -TypeName Xml
            try {
                $appHostConfigPath = "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config"
                $appHostConfig.Load($appHostConfigPath)
            } catch {
                Write-Verbose "Failed to loaded application host config file. $_"
                $appHostConfig = $null
            }
            return $appHostConfig
        }

        function GetExtendedProtectionConfiguration {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [System.Xml.XmlNode]$Xml,
                [Parameter(Mandatory = $true)]
                [string]$Path
            )
            process {
                try {
                    $nodePath = [string]::Empty
                    $extendedProtection = "None"
                    $ipRestrictionsHashTable = @{}
                    $pathIndex = [array]::IndexOf(($Xml.configuration.location.path).ToLower(), $Path.ToLower())
                    $rootIndex = [array]::IndexOf(($Xml.configuration.location.path).ToLower(), ($Path.Split("/")[0]).ToLower())

                    if ($pathIndex -ne -1) {
                        $configNode = $Xml.configuration.location[$pathIndex]
                        $nodePath = $configNode.Path
                        $ep = $configNode.'system.webServer'.security.authentication.windowsAuthentication.extendedProtection.tokenChecking
                        $ipRestrictions = $configNode.'system.webServer'.security.ipSecurity

                        if (-not ([string]::IsNullOrEmpty($ep))) {
                            Write-Verbose "Found tokenChecking: $ep"
                            $extendedProtection = $ep
                        } else {
                            Write-Verbose "Failed to find tokenChecking. Using default value of None."
                        }

                        [string]$sslSettings = $configNode.'system.webServer'.security.access.sslFlags

                        if ([string]::IsNullOrEmpty($sslSettings)) {
                            Write-Verbose "Failed to find SSL settings for the path. Falling back to the root."

                            if ($rootIndex -ne -1) {
                                Write-Verbose "Found root path."
                                $rootConfigNode = $Xml.configuration.location[$rootIndex]
                                [string]$sslSettings = $rootConfigNode.'system.webServer'.security.access.sslFlags
                            }
                        }

                        if (-not([string]::IsNullOrEmpty($ipRestrictions))) {
                            Write-Verbose "IP-filtered restrictions detected"
                            foreach ($restriction in $ipRestrictions.add) {
                                $ipRestrictionsHashTable.Add($restriction.ipAddress, $restriction.allowed)
                            }
                        }

                        Write-Verbose "SSLSettings: $sslSettings"

                        if ($null -ne $sslSettings) {
                            [array]$sslFlags = ($sslSettings.Split(",").ToLower()).Trim()
                        } else {
                            $sslFlags = $null
                        }

                        # SSL flags: https://docs.microsoft.com/iis/configuration/system.webserver/security/access#attributes
                        $requireSsl = $false
                        $ssl128Bit = $false
                        $clientCertificate = "Unknown"

                        if ($null -eq $sslFlags) {
                            Write-Verbose "Failed to find SSLFlags"
                        } elseif ($sslFlags.Contains("none")) {
                            $clientCertificate = "Ignore"
                        } else {
                            if ($sslFlags.Contains("ssl")) { $requireSsl = $true }
                            if ($sslFlags.Contains("ssl128")) { $ssl128Bit = $true }
                            if ($sslFlags.Contains("sslNegotiateCert".ToLower())) {
                                $clientCertificate = "Accept"
                            } elseif ($sslFlags.Contains("sslRequireCert".ToLower())) {
                                $clientCertificate = "Require"
                            } else {
                                $clientCertificate = "Ignore"
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Ran into some error trying to parse the application host config for $Path."
                    Invoke-CatchActionError $CatchActionFunction
                }
            } end {
                return [PSCustomObject]@{
                    ExtendedProtection = $extendedProtection
                    ValidPath          = ($pathIndex -ne -1)
                    NodePath           = $nodePath
                    SslSettings        = [PSCustomObject]@{
                        RequireSsl        = $requireSsl
                        Ssl128Bit         = $ssl128Bit
                        ClientCertificate = $clientCertificate
                        Value             = $sslSettings
                    }
                    MitigationSettings = [PScustomObject]@{
                        AllowUnlisted = $ipRestrictions.allowUnlisted
                        Restrictions  = $ipRestrictionsHashTable
                    }
                }
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $computerResult = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlock { return $env:COMPUTERNAME }
        $serverConnected = $null -ne $computerResult

        if ($null -eq $computerResult) {
            Write-Verbose "Failed to connect to server $ComputerName"
            return
        }

        if ($null -eq $ExSetupVersion) {
            [System.Version]$ExSetupVersion = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlock {
                (Get-Command ExSetup.exe |
                    ForEach-Object { $_.FileVersionInfo } |
                    Select-Object -First 1).FileVersion
            }

            if ($null -eq $ExSetupVersion) {
                throw "Failed to determine Exchange build number"
            }
        } else {
            # Hopefully the caller knows what they are doing, best be from the correct server!!
            Write-Verbose "Caller passed the ExSetupVersion information"
        }

        if ($null -eq $ApplicationHostConfig) {
            Write-Verbose "Trying to load the application host config from $ComputerName"
            $params = @{
                ComputerName        = $ComputerName
                ScriptBlock         = ${Function:GetApplicationHostConfig}
                CatchActionFunction = $CatchActionFunction
            }

            $ApplicationHostConfig = Invoke-ScriptBlockHandler @params

            if ($null -eq $ApplicationHostConfig) {
                throw "Failed to load application host config from $ComputerName"
            }
        } else {
            # Hopefully the caller knows what they are doing, best be from the correct server!!
            Write-Verbose "Caller passed the application host config."
        }

        $default = "Default Web Site"
        $backend = "Exchange Back End"
        $Script:IsExchange2013 = $ExSetupVersion.Major -eq 15 -and $ExSetupVersion.Minor -eq 0
        try {
            $VirtualDirectoryMatchEntries = @(
                (NewVirtualDirMatchingEntry "API" -WebSite $default, $backend -ExtendedProtection "Require", "Require")
                (NewVirtualDirMatchingEntry "Autodiscover" -WebSite $default, $backend -ExtendedProtection "None", "None")
                (NewVirtualDirMatchingEntry "ECP" -WebSite $default, $backend -ExtendedProtection "Require", "Require")
                (NewVirtualDirMatchingEntry "EWS" -WebSite $default, $backend -ExtendedProtection "Allow", "Require")
                (NewVirtualDirMatchingEntry "Microsoft-Server-ActiveSync" -WebSite $default, $backend -ExtendedProtection "Allow", "Require")
                # This was changed due to Outlook for Mac not being able to do download the OAB.
                (NewVirtualDirMatchingEntry "OAB" -WebSite $default, $backend -ExtendedProtection "Allow", "Require")
                (NewVirtualDirMatchingEntry "Powershell" -WebSite $default, $backend -ExtendedProtection "Require", "Require" -SslFlags "SslNegotiateCert", "Ssl,Ssl128,SslNegotiateCert")
                (NewVirtualDirMatchingEntry "OWA" -WebSite $default, $backend -ExtendedProtection "Require", "Require")
                (NewVirtualDirMatchingEntry "RPC" -WebSite $default, $backend -ExtendedProtection "Require", "Require")
                (NewVirtualDirMatchingEntry "MAPI" -WebSite $default -ExtendedProtection "Require")
                (NewVirtualDirMatchingEntry "PushNotifications" -WebSite $backend -ExtendedProtection "Require")
                (NewVirtualDirMatchingEntry "RPCWithCert" -WebSite $backend -ExtendedProtection "Require")
                (NewVirtualDirMatchingEntry "MAPI/emsmdb" -WebSite $backend -ExtendedProtection "Require")
                (NewVirtualDirMatchingEntry "MAPI/nspi" -WebSite $backend -ExtendedProtection "Require")
            )
        } catch {
            # Don't handle with Catch Error as this is a bug in the script.
            throw "Failed to create NewVirtualDirMatchingEntry. Inner Exception $_"
        }

        # Is Supported build of Exchange to have the configuration set.
        # Edge Server is not accounted for. It is the caller's job to not try to collect this info on Edge.
        $supportedVersion = $false
        $extendedProtectionList = New-Object 'System.Collections.Generic.List[object]'

        if ($ExSetupVersion.Major -eq 15) {
            if ($ExSetupVersion.Minor -eq 2) {
                $supportedVersion = $ExSetupVersion.Build -gt 1118 -or
                ($ExSetupVersion.Build -eq 1118 -and $ExSetupVersion.Revision -ge 11) -or
                ($ExSetupVersion.Build -eq 986 -and $ExSetupVersion.Revision -ge 28)
            } elseif ($ExSetupVersion.Minor -eq 1) {
                $supportedVersion = $ExSetupVersion.Build -gt 2507 -or
                ($ExSetupVersion.Build -eq 2507 -and $ExSetupVersion.Revision -ge 11) -or
                ($ExSetupVersion.Build -eq 2375 -and $ExSetupVersion.Revision -ge 30)
            } elseif ($ExSetupVersion.Minor -eq 0) {
                $supportedVersion = $ExSetupVersion.Build -gt 1497 -or
                ($ExSetupVersion.Build -eq 1497 -and $ExSetupVersion.Revision -ge 38)
            }
            Write-Verbose "Build $ExSetupVersion is supported: $supportedVersion"
        } else {
            Write-Verbose "Not on Exchange Version 15"
        }

        # Add all vDirs for which the IP filtering mitigation is supported
        $mitigationSupportedVDirs = $MyInvocation.MyCommand.Parameters["SiteVDirLocations"].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            ForEach-Object { return $_.ValidValues }
        Write-Verbose "Supported mitigated virtual directories: $([string]::Join(",", $mitigationSupportedVDirs))"
    }
    process {
        try {
            foreach ($matchEntry in $VirtualDirectoryMatchEntries) {
                try {
                    Write-Verbose "Verify extended protection setting for $($matchEntry.VirtualDirectory) on web site $($matchEntry.WebSite)"

                    $extendedConfiguration = GetExtendedProtectionConfiguration -Xml $applicationHostConfig -Path "$($matchEntry.WebSite)/$($matchEntry.VirtualDirectory)"

                    # Extended Protection is a windows security feature which blocks MiTM attacks.
                    # Supported server roles are: Mailbox and ClientAccess
                    # Possible configuration settings are:
                    # <None>: This value specifies that IIS will not perform channel-binding token checking.
                    # <Allow>: This value specifies that channel-binding token checking is enabled, but not required.
                    # <Require>: This value specifies that channel-binding token checking is required.
                    # https://docs.microsoft.com/iis/configuration/system.webserver/security/authentication/windowsauthentication/extendedprotection/

                    if ($extendedConfiguration.ValidPath) {
                        Write-Verbose "Configuration was successfully returned: $($extendedConfiguration.ExtendedProtection)"
                    } else {
                        Write-Verbose "Extended protection setting was not queried because it wasn't found on the system."
                    }

                    $sslFlagsToSet = $extendedConfiguration.SslSettings.Value
                    $currentSetFlags = $sslFlagsToSet.Split(",").Trim()
                    foreach ($sslFlag in $matchEntry.SslFlags.Split(",").Trim()) {
                        if (-not($currentSetFlags.Contains($sslFlag))) {
                            Write-Verbose "Failed to find SSL Flag $sslFlag"
                            # We do not want to include None in the flags as that takes priority over the other options.
                            if ($sslFlagsToSet -eq "None") {
                                $sslFlagsToSet = "$sslFlag"
                            } else {
                                $sslFlagsToSet += ",$sslFlag"
                            }
                            Write-Verbose "Updated SSL Flags Value: $sslFlagsToSet"
                        } else {
                            Write-Verbose "SSL Flag $sslFlag set."
                        }
                    }

                    $expectedExtendedConfiguration = if ($supportedVersion) { $matchEntry.ExtendedProtection } else { "None" }
                    $virtualDirectoryName = "$($matchEntry.WebSite)/$($matchEntry.VirtualDirectory)"

                    # Supported Configuration is when the current value of Extended Protection is less than our expected extended protection value.
                    # While this isn't secure as we would like, it is still a supported state that should work.
                    $supportedExtendedConfiguration = $expectedExtendedConfiguration -eq $extendedConfiguration.ExtendedProtection

                    if ($supportedExtendedConfiguration) {
                        Write-Verbose "The EP value set to the expected value."
                    } else {
                        Write-Verbose "We are expecting a value of '$expectedExtendedConfiguration' but the current value is '$($extendedConfiguration.ExtendedProtection)'"

                        if ($expectedExtendedConfiguration -eq "Require" -or
                            ($expectedExtendedConfiguration -eq "Allow" -and
                            $extendedConfiguration.ExtendedProtection -eq "None")) {
                            $supportedExtendedConfiguration = $true
                            Write-Verbose "This is still supported because it is lower than what we recommended."
                        } else {
                            Write-Verbose "This is not supported because you are higher than the recommended value and will likely cause problems."
                        }
                    }

                    # Properly Secured Configuration is when the current Extended Protection value is equal to or greater than the Expected Extended Protection Configuration.
                    # If the Expected value is Allow, you can have the value set to Allow or Required and it will not be a security risk. However, if set to None, that is a security concern.
                    # For a mitigation scenario, like EWS BE, Required is the Expected value. Therefore, on those directories, we need to verify that IP filtering is set if not set to Require.
                    $properlySecuredConfiguration = $expectedExtendedConfiguration -eq $extendedConfiguration.ExtendedProtection

                    if ($properlySecuredConfiguration) {
                        Write-Verbose "We are 'properly' secure because we have EP set to the expected EP configuration value: $($expectedExtendedConfiguration)"
                    } elseif ($expectedExtendedConfiguration -eq "Require") {
                        Write-Verbose "Checking to see if we have mitigations enabled for the supported vDirs"
                        # Only care about virtual directories that we allow mitigation for
                        $properlySecuredConfiguration = $mitigationSupportedVDirs -contains $virtualDirectoryName -and
                        $extendedConfiguration.MitigationSettings.AllowUnlisted -eq "false"
                    } elseif ($expectedExtendedConfiguration -eq "Allow") {
                        Write-Verbose "Checking to see if Extended Protection is set to 'Require' to still be considered secure"
                        $properlySecuredConfiguration = $extendedConfiguration.ExtendedProtection -eq "Require"
                    } else {
                        Write-Verbose "Recommended EP setting is 'None' means you can have it higher, but you might run into other issues. But you are 'secure'."
                        $properlySecuredConfiguration = $true
                    }

                    Write-Verbose "Properly Secure Configuration value: $properlySecuredConfiguration"

                    $extendedProtectionList.Add([PSCustomObject]@{
                            VirtualDirectoryName          = $virtualDirectoryName
                            Configuration                 = $extendedConfiguration
                            # The current Extended Protection configuration set on the server
                            ExtendedProtection            = $extendedConfiguration.ExtendedProtection
                            # The Recommended Extended Protection is to verify that we have set the current Extended Protection
                            #   setting value to the Expected Extended Protection Value
                            RecommendedExtendedProtection = $expectedExtendedConfiguration -eq $extendedConfiguration.ExtendedProtection
                            # The supported/expected Extended Protection Configuration value that we should be set to (based off the build of Exchange)
                            ExpectedExtendedConfiguration = $expectedExtendedConfiguration
                            # Properly Secured is determined if we have a value equal to or greater than the ExpectedExtendedConfiguration value
                            # However, if we have a value greater than the expected, this could mean that we might run into a known set of issues.
                            ProperlySecuredConfiguration  = $properlySecuredConfiguration
                            # The Supported Extended Protection is a value that is equal to or lower than the Expected Extended Protection configuration.
                            # While this is not the best security setting, it is lower and shouldn't cause a connectivity issue and should still be supported.
                            SupportedExtendedProtection   = $supportedExtendedConfiguration
                            MitigationEnabled             = ($extendedConfiguration.MitigationSettings.AllowUnlisted -eq "false")
                            MitigationSupported           = $mitigationSupportedVDirs -contains $virtualDirectoryName
                            ExpectedSslFlags              = $matchEntry.SslFlags
                            SslFlagsSetCorrectly          = $sslFlagsToSet.Split(",").Count -eq $currentSetFlags.Count
                            SslFlagsToSet                 = $sslFlagsToSet
                        })
                } catch {
                    Write-Verbose "Failed to get extended protection match entry."
                    Invoke-CatchActionError $CatchActionFunction
                }
            }
        } catch {
            Write-Verbose "Failed to get get extended protection."
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        return [PSCustomObject]@{
            ComputerName                          = $ComputerName
            ServerConnected                       = $serverConnected
            SupportedVersionForExtendedProtection = $supportedVersion
            ApplicationHostConfig                 = $ApplicationHostConfig
            ExtendedProtectionConfiguration       = $extendedProtectionList
            ExtendedProtectionConfigured          = $null -ne ($extendedProtectionList.ExtendedProtection | Where-Object { $_ -ne "None" })
        }
    }
}
