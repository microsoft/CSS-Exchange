# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
. $PSScriptRoot\Get-WmiObjectHandler.ps1
. $PSScriptRoot\Get-RemoteRegistrySubKey.ps1
. $PSScriptRoot\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\Invoke-CatchActionError.ps1
. $PSScriptRoot\Invoke-CatchActionErrorLoop.ps1
. $PSScriptRoot\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1
function Get-AllNicInformation {
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$ComputerFQDN,
        [ScriptBlock]$CatchActionFunction
    )
    begin {

        #cspell:ignore Lbfo
        # Extract for Pester Testing - Start
        function Get-NicPnpCapabilitiesSetting {
            [CmdletBinding()]
            param(
                [ValidateNotNullOrEmpty()]
                [string]$NicAdapterComponentId
            )
            begin {
                $nicAdapterBasicPath = "SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}"
                [int]$i = 0
                Write-Verbose "Probing started to detect NIC adapter registry path"
                $registrySubKey = $null
            }
            process {
                Get-RemoteRegistrySubKey -MachineName $ComputerName -SubKey $nicAdapterBasicPath |
                    Invoke-RemotePipelineHandler -Result ([ref]$registrySubKey)
                if ($null -ne $registrySubKey) {
                    $optionalKeys = $registrySubKey.GetSubKeyNames() | Where-Object { $_ -like "0*" }
                    do {
                        $nicAdapterPnPCapabilitiesProbingKey = "$nicAdapterBasicPath\$($optionalKeys[$i])"
                        $netCfgRemoteRegistryParams = @{
                            MachineName         = $ComputerName
                            SubKey              = $nicAdapterPnPCapabilitiesProbingKey
                            GetValue            = "NetCfgInstanceId"
                            CatchActionFunction = $CatchActionFunction
                        }
                        $netCfgInstanceId = $null
                        Get-RemoteRegistryValue @netCfgRemoteRegistryParams |
                            Invoke-RemotePipelineHandler -Result ([ref]$netCfgInstanceId)

                        if ($netCfgInstanceId -eq $NicAdapterComponentId) {
                            Write-Verbose "Matching ComponentId found - now checking for PnPCapabilitiesValue"
                            $pnpRemoteRegistryParams = @{
                                MachineName         = $ComputerName
                                SubKey              = $nicAdapterPnPCapabilitiesProbingKey
                                GetValue            = "PnPCapabilities"
                                CatchActionFunction = $CatchActionFunction
                            }
                            $nicAdapterPnPCapabilitiesValue = $null
                            Get-RemoteRegistryValue @pnpRemoteRegistryParams |
                                Invoke-RemotePipelineHandler -Result ([ref]$nicAdapterPnPCapabilitiesValue)
                            break
                        } else {
                            Write-Verbose "No matching ComponentId found"
                            $i++
                        }
                    } while ($i -lt $optionalKeys.Count)
                }
            }
            end {
                return [PSCustomObject]@{
                    PnPCapabilities   = $nicAdapterPnPCapabilitiesValue
                    SleepyNicDisabled = ($nicAdapterPnPCapabilitiesValue -eq 24 -or $nicAdapterPnPCapabilitiesValue -eq 280)
                }
            }
        }

        # Extract for Pester Testing - End

        function Get-NetworkConfiguration {
            [CmdletBinding()]
            param(
                [string]$ComputerName
            )
            begin {
                $currentErrors = $Error.Count
                $params = @{
                    ErrorAction = "Stop"
                }
            }
            process {
                try {
                    if (($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) {
                        $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
                        $params.Add("CimSession", $cimSession)
                    }
                    $networkIpConfiguration = Get-NetIPConfiguration @params | Where-Object { $_.NetAdapter.MediaConnectionState -eq "Connected" }
                    Invoke-CatchActionErrorLoop -CurrentErrors $currentErrors -CatchActionFunction $CatchActionFunction
                    return $networkIpConfiguration
                } catch {
                    Write-Verbose "Failed to run Get-NetIPConfiguration. Error $($_.Exception)"
                    #just rethrow as caller will handle the catch
                    throw
                }
            }
        }

        function Get-NicInformation {
            [CmdletBinding()]
            param(
                [array]$NetworkConfiguration,
                [bool]$WmiObject
            )
            begin {

                function Get-IpvAddresses {
                    return [PSCustomObject]@{
                        Address        = ([string]::Empty)
                        Subnet         = ([string]::Empty)
                        DefaultGateway = ([string]::Empty)
                    }
                }

                if ($null -eq $NetworkConfiguration) {
                    Write-Verbose "NetworkConfiguration are null in New-NicInformation. Returning a null object."
                    return $null
                }

                $nicObjects = New-Object 'System.Collections.Generic.List[object]'
                $networkAdapterConfigurations = $null
                $getNetLbfoTeam = $null
                $getNetAdapter = $null
                $newCimSession = $null
            }
            process {
                if ($WmiObject) {
                    $networkAdapterConfigurationsParams = @{
                        ComputerName        = $ComputerName
                        Class               = "Win32_NetworkAdapterConfiguration"
                        Filter              = "IPEnabled = True"
                        CatchActionFunction = $CatchActionFunction
                    }
                    Get-WmiObjectHandler @networkAdapterConfigurationsParams |
                        Invoke-RemotePipelineHandler -Result ([ref]$networkAdapterConfigurations)
                }

                if (($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) {
                    try {
                        $newCimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
                    } catch {
                        Write-Verbose "Failed to get the Cim Session for the computer. Inner Exception $_"
                        Invoke-CatchActionError $CatchActionFunction
                    }
                }

                if ((($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) -and $null -eq $newCimSession) {
                    Write-Verbose "Failed to get the Cim Session for a non-local computer, can't get the additional adapter information."
                } else {
                    $params = @{
                        ErrorAction = "Stop"
                    }

                    if ($null -ne $newCimSession) {
                        $params.Add("CimSession", $newCimSession)
                    }

                    try {
                        $getNetLBfoTeam = Get-NetLbfoTeam @params
                    } catch {
                        Write-Verbose "Failed to run Get-NetLbfoTeam. Inner Exception: $_"
                        Invoke-CatchActionError $CatchActionFunction
                    }

                    try {
                        $getNetAdapter = Get-NetAdapter @params
                    } catch {
                        Write-Verbose "Failed to run Get-NetAdapter. Inner Exception: $_"
                        Invoke-CatchActionError $CatchActionFunction
                    }
                }

                foreach ($networkConfig in $NetworkConfiguration) {
                    $dnsClient = $null
                    $rssEnabledValue = 2
                    $netAdapterRss = $null
                    $mtuSize = 0
                    $driverDate = [DateTime]::MaxValue
                    $driverVersion = [string]::Empty
                    $description = [string]::Empty
                    $ipv4Address = @()
                    $ipv6Address = @()
                    $ipv6Enabled = $false
                    $isRegisteredInDns = $false
                    $dnsServerToBeUsed = $null
                    $isTeamedNic = $false
                    $teamedMembers = $null

                    if (-not ($WmiObject)) {
                        Write-Verbose "Working on NIC: $($networkConfig.InterfaceDescription)"
                        $adapter = $networkConfig.NetAdapter

                        if ($null -ne $getNetLbfoTeam) {
                            foreach ($team in $getNetLbfoTeam) {
                                if ($team.Name -eq $adapter.Name) {
                                    Write-Verbose "NIC Appears to be a teamed NIC"
                                    $isTeamedNic = $true
                                    $teamedMembers = $team.Members
                                    break
                                }
                            }
                        }

                        if ($adapter.DriverFileName -ne "NdIsImPlatform.sys") {
                            $nicPnpCapabilitiesSetting = $null
                            Get-NicPnpCapabilitiesSetting -NicAdapterComponentId $adapter.DeviceID |
                                Invoke-RemotePipelineHandler -Result ([ref]$nicPnpCapabilitiesSetting)
                        } else {
                            Write-Verbose "Multiplexor adapter detected. Going to skip PnpCapabilities check"
                            $nicPnpCapabilitiesSetting = [PSCustomObject]@{
                                PnPCapabilities = "MultiplexorNoPnP"
                            }
                        }

                        try {
                            $dnsClient = $adapter | Get-DnsClient -ErrorAction Stop
                            $isRegisteredInDns = $dnsClient.RegisterThisConnectionsAddress
                            Write-Verbose "Got DNS Client information"
                        } catch {
                            Write-Verbose "Failed to get the DNS client information"
                            Invoke-CatchActionError $CatchActionFunction
                        }

                        try {
                            $netAdapterRss = $adapter | Get-NetAdapterRss -ErrorAction Stop
                            Write-Verbose "Got Net Adapter RSS Information"

                            if ($null -ne $netAdapterRss) {
                                [int]$rssEnabledValue = $netAdapterRss.Enabled
                            }
                        } catch {
                            Write-Verbose "Failed to get RSS Information"
                            Invoke-CatchActionError $CatchActionFunction
                        }

                        foreach ($ipAddress in $networkConfig.AllIPAddresses.IPAddress) {
                            if ($ipAddress.Contains(":")) {
                                $ipv6Enabled = $true
                            }
                        }

                        for ($i = 0; $i -lt $networkConfig.IPv4Address.Count; $i++) {
                            $newIpvAddress = Get-IpvAddresses

                            if ($null -ne $networkConfig.IPv4Address -and
                                $i -lt $networkConfig.IPv4Address.Count) {
                                $newIpvAddress.Address = $networkConfig.IPv4Address[$i].IPAddress
                                $newIpvAddress.Subnet = $networkConfig.IPv4Address[$i].PrefixLength
                            }

                            if ($null -ne $networkConfig.IPv4DefaultGateway -and
                                $i -lt $networkConfig.IPv4Address.Count) {
                                $newIpvAddress.DefaultGateway = $networkConfig.IPv4DefaultGateway[$i].NextHop
                            }
                            $ipv4Address += $newIpvAddress
                        }

                        for ($i = 0; $i -lt $networkConfig.IPv6Address.Count; $i++) {
                            $newIpvAddress = Get-IpvAddresses

                            if ($null -ne $networkConfig.IPv6Address -and
                                $i -lt $networkConfig.IPv6Address.Count) {
                                $newIpvAddress.Address = $networkConfig.IPv6Address[$i].IPAddress
                                $newIpvAddress.Subnet = $networkConfig.IPv6Address[$i].PrefixLength
                            }

                            if ($null -ne $networkConfig.IPv6DefaultGateway -and
                                $i -lt $networkConfig.IPv6DefaultGateway.Count) {
                                $newIpvAddress.DefaultGateway = $networkConfig.IPv6DefaultGateway[$i].NextHop
                            }
                            $ipv6Address += $newIpvAddress
                        }

                        $mtuSize = $adapter.MTUSize
                        $driverDate = $adapter.DriverDate
                        $driverVersion = $adapter.DriverVersionString
                        $description = $adapter.InterfaceDescription
                        $dnsServerToBeUsed = $networkConfig.DNSServer.ServerAddresses
                    } else {
                        Write-Verbose "Working on NIC: $($networkConfig.Description)"
                        $adapter = $networkConfig
                        $description = $adapter.Description

                        if ($adapter.ServiceName -ne "NdIsImPlatformMp") {
                            $nicPnpCapabilitiesSetting = $null
                            Get-NicPnpCapabilitiesSetting -NicAdapterComponentId $adapter.Guid |
                                Invoke-RemotePipelineHandler -Result ([ref]$nicPnpCapabilitiesSetting)
                        } else {
                            Write-Verbose "Multiplexor adapter detected. Going to skip PnpCapabilities check"
                            $nicPnpCapabilitiesSetting = [PSCustomObject]@{
                                PnPCapabilities = "MultiplexorNoPnP"
                            }
                        }

                        #set the correct $adapterConfiguration to link to the correct $networkConfig that we are on
                        $adapterConfiguration = $networkAdapterConfigurations |
                            Where-Object { $_.SettingID -eq $networkConfig.GUID -or
                                $_.SettingID -eq $networkConfig.InterfaceGuid }

                        if ($null -eq $adapterConfiguration) {
                            Write-Verbose "Failed to find correct adapterConfiguration for this networkConfig."
                            Write-Verbose "GUID: $($networkConfig.GUID) | InterfaceGuid: $($networkConfig.InterfaceGuid)"
                        } else {
                            $ipv6Enabled = ($adapterConfiguration.IPAddress | Where-Object { $_.Contains(":") }).Count -ge 1

                            if ($null -ne $adapterConfiguration.DefaultIPGateway) {
                                $ipv4Gateway = $adapterConfiguration.DefaultIPGateway | Where-Object { $_.Contains(".") }
                                $ipv6Gateway = $adapterConfiguration.DefaultIPGateway | Where-Object { $_.Contains(":") }
                            } else {
                                $ipv4Gateway = "No default IPv4 gateway set"
                                $ipv6Gateway = "No default IPv6 gateway set"
                            }

                            for ($i = 0; $i -lt $adapterConfiguration.IPAddress.Count; $i++) {

                                if ($adapterConfiguration.IPAddress[$i].Contains(":")) {
                                    $newIpv6Address = Get-IpvAddresses
                                    if ($i -lt $adapterConfiguration.IPAddress.Count) {
                                        $newIpv6Address.Address = $adapterConfiguration.IPAddress[$i]
                                        $newIpv6Address.Subnet = $adapterConfiguration.IPSubnet[$i]
                                    }

                                    $newIpv6Address.DefaultGateway = $ipv6Gateway
                                    $ipv6Address += $newIpv6Address
                                } else {
                                    $newIpv4Address = Get-IpvAddresses
                                    if ($i -lt $adapterConfiguration.IPAddress.Count) {
                                        $newIpv4Address.Address = $adapterConfiguration.IPAddress[$i]
                                        $newIpv4Address.Subnet = $adapterConfiguration.IPSubnet[$i]
                                    }

                                    $newIpv4Address.DefaultGateway = $ipv4Gateway
                                    $ipv4Address += $newIpv4Address
                                }
                            }

                            $isRegisteredInDns = $adapterConfiguration.FullDNSRegistrationEnabled
                            $dnsServerToBeUsed = $adapterConfiguration.DNSServerSearchOrder
                        }
                    }

                    $nicObjects.Add([PSCustomObject]@{
                            WmiObject         = $WmiObject
                            Name              = $adapter.Name
                            LinkSpeed         = ((($adapter.Speed) / 1000000).ToString() + " Mbps")
                            DriverDate        = $driverDate
                            NetAdapterRss     = $netAdapterRss
                            RssEnabledValue   = $rssEnabledValue
                            IPv6Enabled       = $ipv6Enabled
                            Description       = $description
                            DriverVersion     = $driverVersion
                            MTUSize           = $mtuSize
                            PnPCapabilities   = $nicPnpCapabilitiesSetting.PnpCapabilities
                            SleepyNicDisabled = $nicPnpCapabilitiesSetting.SleepyNicDisabled
                            IPv4Addresses     = $ipv4Address
                            IPv6Addresses     = $ipv6Address
                            RegisteredInDns   = $isRegisteredInDns
                            DnsServer         = $dnsServerToBeUsed
                            DnsClient         = $dnsClient
                            IsTeamedNic       = $isTeamedNic
                            TeamedMembers     = $teamedMembers
                        })
                }
            }
            end {
                $obj = [PSCustomObject]@{
                    Adapters       = [array]$nicObjects
                    GetNetAdapter  = $getNetAdapter
                    GetNetLbfoTeam = $getNetLbfoTeam
                }
                Write-Verbose "Found $($nicObjects.Count) active adapters on the computer."
                Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
                return $obj
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed - ComputerName: '$ComputerName' | ComputerFQDN: '$ComputerFQDN'"
    }
    process {
        try {
            try {
                $networkConfiguration = $null
                Get-NetworkConfiguration -ComputerName $ComputerName |
                    Invoke-RemotePipelineHandler -Result ([ref]$networkConfiguration)
            } catch {
                Invoke-CatchActionError $CatchActionFunction

                try {
                    if (-not ([string]::IsNullOrEmpty($ComputerFQDN))) {
                        $networkConfiguration = $null
                        Get-NetworkConfiguration -ComputerName $ComputerFQDN |
                            Invoke-RemotePipelineHandler -Result ([ref]$networkConfiguration)
                    } else {
                        $bypassCatchActions = $true
                        Write-Verbose "No FQDN was passed, going to rethrow error."
                        throw
                    }
                } catch {
                    #Just throw again
                    throw
                }
            }

            if ([String]::IsNullOrEmpty($networkConfiguration)) {
                # Throw if nothing was returned by previous calls.
                # Can be caused when executed on Server 2008 R2 where CIM namespace ROOT/StandardCiMv2 is invalid.
                Write-Verbose "No value was returned by 'Get-NetworkConfiguration'. Fallback to WMI."
                throw
            }

            $getNicInformation = $null
            Get-NicInformation -NetworkConfiguration $networkConfiguration |
                Invoke-RemotePipelineHandler -Result ([ref]$getNicInformation)
            return $getNicInformation
        } catch {
            if (-not $bypassCatchActions) {
                Invoke-CatchActionError $CatchActionFunction
            }

            $wmiNetworkCardsParams = @{
                ComputerName        = $ComputerName
                Class               = "Win32_NetworkAdapter"
                Filter              = "NetConnectionStatus ='2'"
                CatchActionFunction = $CatchActionFunction
            }
            $wmiNetworkCards = $null
            Get-WmiObjectHandler @wmiNetworkCardsParams |
                Invoke-RemotePipelineHandler -Result ([ref]$wmiNetworkCards)

            $getNicInformation = $null
            Get-NicInformation -NetworkConfiguration $wmiNetworkCards -WmiObject $true |
                Invoke-RemotePipelineHandler -Result ([ref]$getNicInformation)
            return $getNicInformation
        }
    }
}
