﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-CatchActionError.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

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
        [scriptblock]$CatchActionFunction
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
                [string[]]$SslFlags = @("Ssl, Ssl128", "Ssl, Ssl128")
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
                # Set EWS Vdir to None for known issues
                if ($ExcludeEWS -and $virtualDirectory -eq "EWS") { $ExtendedProtection[$i] = "None" }

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
                $appHostConfigPath = "$($env:WINDIR)\System32\inetsrv\config\applicationHost.config"
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
                    $pathIndex = [array]::IndexOf(($Xml.configuration.location.path).ToLower(), $Path.ToLower())
                    $rootIndex = [array]::IndexOf(($Xml.configuration.location.path).ToLower(), ($Path.Split("/")[0]).ToLower())

                    if ($pathIndex -ne -1) {
                        $configNode = $Xml.configuration.location[$pathIndex]
                        $nodePath = $configNode.Path
                        $ep = $configNode.'system.webServer'.security.authentication.windowsAuthentication.extendedProtection.tokenChecking

                        if (-not ([string]::IsNullOrEmpty($ep))) {
                            Write-Verbose "Failed to find tokenChecking"
                            $extendedProtection = $ep
                        }

                        $sslSettings = $configNode.'system.webServer'.security.access.sslFlags

                        if ([string]::IsNullOrEmpty($sslSettings)) {
                            Write-Verbose "Failed to find SSL settings for the path. Falling back to the root."

                            if ($rootIndex -ne -1) {
                                Write-Verbose "Found root path."
                                $rootConfigNode = $Xml.configuration.location[$rootIndex]
                                $sslSettings = $rootConfigNode.'system.webServer'.security.access.sslFlags
                            }
                        }

                        Write-Verbose "SSLSettings: $sslSettings"

                        if ($null -ne $sslSettings) {
                            [array]$sslFlags = ($sslSettings.Split(",").ToLower()).Trim()
                        }

                        # SSL flags: https://docs.microsoft.com/iis/configuration/system.webserver/security/access#attributes
                        $requireSsl = $false
                        $ssl128Bit = $false
                        $clientCertificate = "Unknown"

                        if ($sslFlags.Contains("none")) {
                            $clientCertificate = "Ignore"
                        } else {
                            if ($sslFlags.Contains("ssl")) { $requireSsl = $true }
                            if ($sslFlags.Contains("ssl128")) { $ssl128Bit = $true }
                            if ($sslFlags.Contains("sslnegotiatecert")) {
                                $clientCertificate = "Accept"
                            } elseif ($sslFlags.Contains("sslrequirecert")) {
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
                (Get-Command Exsetup.exe |
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
                (NewVirtualDirMatchingEntry "Microsoft-Server-ActiveSync" -WebSite $default, $backend -ExtendedProtection "Require", "Require")
                (NewVirtualDirMatchingEntry "OAB" -WebSite $default, $backend -ExtendedProtection "Require", "Require")
                (NewVirtualDirMatchingEntry "Powershell" -WebSite $default, $backend -ExtendedProtection "Require", "Require" -SslFlags "SslNegotiateCert", "Ssl, Ssl128, SslNegotiateCert")
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
                                $sslFlagsToSet += ", $sslFlag"
                            }
                            Write-Verbose "Updated SSL Flags Value: $sslFlagsToSet"
                        } else {
                            Write-Verbose "SSL Flag $sslFlag set."
                        }
                    }

                    $expectedExtendedConfiguration = if ($supportedVersion) { $matchEntry.ExtendedProtection } else { "None" }

                    $extendedProtectionList.Add([PSCustomObject]@{
                            VirtualDirectoryName          = "$($matchEntry.WebSite)/$($matchEntry.VirtualDirectory)"
                            Configuration                 = $extendedConfiguration
                            ExtendedProtection            = $extendedConfiguration.ExtendedProtection
                            SupportedExtendedProtection   = $expectedExtendedConfiguration -eq $extendedConfiguration.ExtendedProtection
                            ExpectedExtendedConfiguration = $expectedExtendedConfiguration
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
