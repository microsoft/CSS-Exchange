#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ComputerInformation/Get-AllNicInformation/Get-AllNicInformation.ps1
#v21.01.25.0238
Function Get-AllNicInformation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Just creating internal objects')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $false)][string]$ComputerFQDN,
        [Parameter(Mandatory = $false)][scriptblock]$CatchActionFunction
    )
    #Function Version #v21.01.25.0238

    Write-VerboseWriter("Calling: Get-AllNicInformation")
    Write-VerboseWriter("Passed [string]ComputerName: {0} | [string]ComputerFQDN: {1}" -f $ComputerName, $ComputerFQDN)

    Function Get-NicPnpCapabilitiesSetting {
        [CmdletBinding()]
        param(
            [string]$NicAdapterComponentId
        )

        if ($NicAdapterComponentId -eq [string]::Empty) {
            throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid NicAdapterDeviceId or NicAdapterComponentId"
        }

        $nicAdapterBasicPath = "SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}"
        Write-VerboseWriter("Probing started to detect NIC adapter registry path")
        [int]$i = 0

        do {
            $nicAdapterPnPCapabilitiesProbingKey = "{0}\{1}" -f $nicAdapterBasicPath, ($i.ToString().PadLeft(4, "0"))
            $netCfgInstanceId = Invoke-RegistryGetValue -MachineName $ComputerName -Subkey $nicAdapterPnPCapabilitiesProbingKey -GetValue "NetCfgInstanceId" -CatchActionFunction $CatchActionFunction

            if ($netCfgInstanceId -eq $NicAdapterComponentId) {
                Write-VerboseWriter("Matching ComponentId found - now checking for PnPCapabilitiesValue")
                $nicAdapterPnPCapabilitiesValue = Invoke-RegistryGetValue -MachineName $ComputerName -SubKey $nicAdapterPnPCapabilitiesProbingKey -GetValue "PnPCapabilities" -CatchActionFunction $CatchActionFunction
                break
            } else {
                Write-VerboseWriter("No matching ComponentId found")
                $i++
            }
        } while ($null -ne $netCfgInstanceId)

        $obj = New-Object PSCustomObject
        $sleepyNicDisabled = $false

        if ($nicAdapterPnPCapabilitiesValue -eq 24 -or
            $nicAdapterPnPCapabilitiesValue -eq 280) {
            $sleepyNicDisabled = $true
        }

        $obj | Add-Member -MemberType NoteProperty -Name "PnPCapabilities" -Value $nicAdapterPnPCapabilitiesValue
        $obj | Add-Member -MemberType NoteProperty -Name "SleepyNicDisabled" -Value $sleepyNicDisabled
        return $obj
    }

    Function Get-NetworkConfiguration {
        [CmdletBinding()]
        param(
            [string]$ComputerName
        )
        try {
            $currentErrors = $Error.Count
            $params = @{
                ErrorAction = "Stop"
            }
            if (($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) {
                $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
                $params.Add("CimSession", $cimSession)
            }
            $networkIpConfiguration = Get-NetIPConfiguration @params | Where-Object { $_.NetAdapter.MediaConnectionState -eq "Connected" }

            if ($null -ne $CatchActionFunction) {
                $index = 0
                while ($index -lt ($Error.Count - $currentErrors)) {
                    & $CatchActionFunction $Error[$index]
                    $index++
                }
            }

            return $networkIpConfiguration
        } catch {
            Write-VerboseWriter("Failed to run Get-NetIPConfiguration. Error {0}." -f $Error[0].Exception)
            #just rethrow as caller will handle the catch
            throw
        }
    }

    Function New-NICInformation {
        param(
            [array]$NetworkConfigurations,
            [bool]$WmiObject
        )
        if ($null -eq $NetworkConfigurations) {
            Write-VerboseWriter("NetworkConfigurations are null in New-NICInformation. Returning a null object.")
            return $null
        }

        Function New-IpvAddresses {

            $obj = New-Object PSCustomObject
            $obj | Add-Member -MemberType NoteProperty -Name "Address" -Value ([string]::Empty)
            $obj | Add-Member -MemberType NoteProperty -Name "Subnet" -Value ([string]::Empty)
            $obj | Add-Member -MemberType NoteProperty -Name "DefaultGateway" -Value ([string]::Empty)

            return $obj
        }

        if ($WmiObject) {
            $networkAdapterConfigurations = Get-WmiObjectHandler -ComputerName $ComputerName -Class "Win32_NetworkAdapterConfiguration" -Filter "IPEnabled = True" -CatchActionFunction $CatchActionFunction
        }

        [array]$nicObjects = @()
        foreach ($networkConfig in $NetworkConfigurations) {
            $dnsClient = $null
            $rssEnabledValue = 2
            $netAdapterRss = $null
            if (!$WmiObject) {
                Write-VerboseWriter("Working on NIC: {0}" -f $networkConfig.InterfaceDescription)
                $adapter = $networkConfig.NetAdapter
                $nicPnpCapabilitiesSetting = Get-NicPnpCapabilitiesSetting -NicAdapterComponentId $adapter.DeviceID

                try {
                    $dnsClient = $adapter | Get-DnsClient -ErrorAction Stop
                    Write-VerboseWriter("Got DNS Client information")
                } catch {
                    Write-VerboseWriter("Failed to get the DNS Client information")
                    if ($null -ne $CatchActionFunction) {
                        & $CatchActionFunction
                    }
                }

                try {
                    $netAdapterRss = $adapter | Get-NetAdapterRss -ErrorAction Stop
                    Write-VerboseWriter("Got Net Adapter RSS information")
                    if ($null -ne $netAdapterRss) {
                        [int]$rssEnabledValue = $netAdapterRss.Enabled
                    }
                } catch {
                    Write-VerboseWriter("Failed to get RSS Information")
                    if ($null -ne $CatchActionFunction) {
                        & $CatchActionFunction
                    }
                }
            } else {
                Write-VerboseWriter("Working on NIC: {0}" -f $networkConfig.Description)
                $adapter = $networkConfig
                $nicPnpCapabilitiesSetting = Get-NicPnpCapabilitiesSetting -NicAdapterComponentId $adapter.Guid
            }

            $nicInformationObj = New-Object PSCustomObject
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "WmiObject" -Value $WmiObject
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "Name" -Value ($adapter.Name)
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "LinkSpeed" -Value ((($adapter.Speed) / 1000000).ToString() + " Mbps")
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "DriverDate" -Value ([DateTime]::MaxValue)
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "NICObject" -Value $networkConfig
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "NetAdapterRss" -Value $netAdapterRss
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "RssEnabledValue" -Value $rssEnabledValue
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "IPv6Enabled" -Value $false
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "Description" -Value $adapter.Description
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "DriverVersion" -Value ([string]::Empty)
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "MTUSize" -Value 0
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "PnPCapabilities" -Value ($nicPnpCapabilitiesSetting.PnPCapabilities)
            $nicInformationObj | Add-Member -MemberType NoteProperty -Name "SleepyNicDisabled" -Value ($nicPnpCapabilitiesSetting.SleepyNicDisabled)

            if (!$WmiObject) {
                $nicInformationObj.MTUSize = $adapter.MtuSize
                $nicInformationObj.DriverDate = $adapter.DriverDate
                $nicInformationObj.DriverVersion = $adapter.DriverVersionString
                $nicInformationObj.Description = $adapter.InterfaceDescription

                foreach ($ipAddress in $networkConfig.AllIPAddresses.IPAddress) {
                    if ($ipAddress.Contains(":")) {
                        $nicInformationObj.IPv6Enabled = $true
                    }
                }

                $ipv4Address = @()
                for ($i = 0; $i -lt $networkConfig.IPv4Address.Count; $i++) {
                    $obj = New-IpvAddresses

                    if ($null -ne $networkConfig.IPv4Address -and
                        $i -lt $networkConfig.IPv4Address.Count) {
                        $obj.Address = $networkConfig.IPv4Address[$i].IPAddress
                        $obj.Subnet = $networkConfig.IPv4Address[$i].PrefixLength
                    }

                    if ($null -ne $networkConfig.IPv4DefaultGateway -and
                        $i -lt $networkConfig.IPv4DefaultGateway.Count) {
                        $obj.DefaultGateway = $networkConfig.IPv4DefaultGateway[$i].NextHop
                    }

                    $ipv4Address += $obj
                }

                $ipv6Address = @()
                for ($i = 0; $i -lt $networkConfig.IPv6Address.Count; $i++) {
                    $obj = New-IpvAddresses

                    if ($null -ne $networkConfig.IPv6Address -and
                        $i -lt $networkConfig.IPv6Address.Count) {
                        $obj.Address = $networkConfig.IPv6Address[$i].IPAddress
                        $obj.Subnet = $networkConfig.IPv6Address[$i].PrefixLength
                    }

                    if ($null -ne $networkConfig.IPv6DefaultGateway -and
                        $i -lt $networkConfig.IPv6DefaultGateway.Count) {
                        $obj.DefaultGateway = $networkConfig.IPv6DefaultGateway[$i].NextHop
                    }

                    $ipv6Address += $obj
                }

                $nicInformationObj | Add-Member -MemberType NoteProperty -Name "IPv4Addresses" -Value $ipv4Address
                $nicInformationObj | Add-Member -MemberType NoteProperty -Name "Ipv6Addresses" -Value $ipv6Address
                $nicInformationObj | Add-Member -MemberType NoteProperty -Name "RegisteredInDns" -Value $dnsClient.RegisterThisConnectionsAddress
                $nicInformationObj | Add-Member -MemberType NoteProperty -Name "DnsServer" -Value $networkConfig.DNSServer.ServerAddresses
                $nicInformationObj | Add-Member -MemberType NoteProperty -Name "DnsClientObject" -Value $dnsClient
            } else {
                $stopProcess = $false
                foreach ($adapterConfiguration in $networkAdapterConfigurations) {
                    Write-VerboseWriter("Working on '{0}' | SettingID: {1}" -f $adapterConfiguration.Description, ($settingId = $adapterConfiguration.SettingID))
                    if ($settingId -eq $networkConfig.GUID -or
                        $settingId -eq $networkConfig.InterfaceGuid) {
                        foreach ($ipAddress in $adapterConfiguration.IPAddress) {
                            if ($ipAddress.Contains(":")) {
                                $nicInformationObj.IPv6Enabled = $true
                                $stopProcess = $true
                                break
                            }
                        }
                    }

                    if ($stopProcess) {
                        break
                    }
                }
            }

            $nicObjects += $nicInformationObj
        }

        Write-VerboseWriter("Found {0} active adapters on the computer." -f $nicObjects.Count)
        Write-VerboseWriter("Exiting: Get-AllNicInformation")
        return $nicObjects
    }

    try {
        try {
            $networkConfiguration = Get-NetworkConfiguration -ComputerName $ComputerName
        } catch {

            if ($CatchActionFunction -ne $null) {
                & $CatchActionFunction
            }

            try {
                if ($ComputerFQDN -ne [string]::Empty -and
                    $null -ne $ComputerName) {
                    $networkConfiguration = Get-NetworkConfiguration -ComputerName $ComputerFQDN
                } else {
                    $bypassCatchActions = $true
                    Write-VerboseWriter("No FQDN was passed, going to rethrow error.")
                    throw
                }
            } catch {
                #Just throw again
                throw
            }
        }

        return (New-NICInformation -NetworkConfigurations $networkConfiguration)
    } catch {
        if (!$bypassCatchActions -and
            $CatchActionFunction -ne $null) {
            & $CatchActionFunction
        }

        $wmiNetworkCards = Get-WmiObjectHandler -ComputerName $ComputerName -Class "Win32_NetworkAdapter" -Filter "NetConnectionStatus ='2'" -CatchActionFunction $CatchActionFunction
        return (New-NICInformation -NetworkConfigurations $wmiNetworkCards -WmiObject $true)
    }
}
