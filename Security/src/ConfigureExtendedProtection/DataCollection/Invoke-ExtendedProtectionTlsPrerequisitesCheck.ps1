# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# TODO: Move this to shared functions onces the script goes public
. $PSScriptRoot\..\..\..\..\Diagnostics\HealthChecker\DataCollection\ServerInformation\Get-AllTlsSettings.ps1

function Invoke-ExtendedProtectionTlsPrerequisitesCheck {
    [CmdletBinding()]
    [OutputType("System.Object")]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ExchangeServers
    )

    begin {
        function NewActionObject {
            param(
                [string]$Name,
                [array]$List,
                [string]$Action
            )

            return [PSCustomObject]@{
                Name   = $Name
                List   = $List
                Action = $Action
            }
        }

        function GetTLSConfigurationForAllServers {
            [CmdletBinding()]
            [OutputType("System.Object")]
            param(
                [string[]]$ExchangeServers
            )

            $tlsSettingsList = New-Object 'System.Collections.Generic.List[object]'
            $serversUnreachableList = New-Object 'System.Collections.Generic.List[string]'

            $counter = 0
            foreach ($server in $ExchangeServers) {
                $tlsSettings = Get-AllTlsSettings -MachineName $server
                $counter = $counter + 1
                $completed = ($counter/($ExchangeServers.Count)*100)
                Write-Progress -Activity "Querying TLS Settings" -Status "Processing: $server" -PercentComplete $completed

                if ($null -ne $tlsSettings.SecurityProtocol) {
                    Write-Verbose "TLS settings successfully received"
                    $tlsSettingsList.Add([PSCustomObject]@{
                            ComputerName = $server
                            TlsSettings  = $tlsSettings
                        })
                } else {
                    Write-Verbose "Unable to query TLS settings"
                    $serversUnreachableList.Add($server)
                }
            }

            return [PSCustomObject]@{
                NumberOfServersPassed       = $ExchangeServers.Count
                NumberOfTlsSettingsReturned = $tlsSettingsList.Count
                UnreachableServers          = $serversUnreachableList
                TlsSettingsReturned         = $tlsSettingsList
            }
        }

        function CompareTlsServerSettings {
            [CmdletBinding()]
            [OutputType("System.Object")]
            param(
                [System.Collections.Generic.List[object]]$TlsSettingsList
            )

            $tlsMisconfiguredList = New-Object 'System.Collections.Generic.List[object]'
            $tlsServersPassedList = New-Object 'System.Collections.Generic.List[object]'
            $majorityFound = $false
            $stopProcessing = $false
            $refIndex = 0

            # We loop through the collected TLS settings and trying to find a valid configuration that exists on the majority of
            # the Exchange servers within the organization. We compare the properties of any other servers TLS settings
            # against the reference configuration.
            while ((($majorityFound -eq $false) -and
                ($stopProcessing -eq $false)) -or
                ($TlsSettingsList.Count -lt $refIndex)) {
                $matchIndex = 0
                $referenceTlsObject = $TlsSettingsList[$refIndex]

                # Validate whether the TLS settings are Enabled or Disabled and skip if server has misconfigured settings
                if ((-not($referenceTlsObject.TlsSettings.Registry.TLS.Values.TLSConfiguration.Contains("Half Disabled"))) -and
                    (-not($referenceTlsObject.TlsSettings.Registry.TLS.Values.TLSConfiguration.Contains("Misconfigured")))) {
                    foreach ($tls in $TlsSettingsList) {
                        $tlsMismatchFound = $false
                        $netMismatchFound = $false

                        Write-Verbose "Comparing TLS settings"
                        $referenceTlsObject.TlsSettings.Registry.Tls.GetEnumerator() | ForEach-Object {
                            Write-Verbose "$($_.key) - Current TLS mismatch value: $tlsMismatchFound"
                            $tlsParams = @{
                                ReferenceObject  = $_.value
                                DifferenceObject = $tls.TlsSettings.Registry.Tls["$($_.key)"]
                                Property         = "TLSConfiguration"
                                IncludeEqual     = $true
                            }
                            $tlsResults = Compare-Object @tlsParams
                            foreach ($tlsR in $tlsResults) {
                                if ($tlsR.SideIndicator -ne "==") {
                                    $tlsMismatchFound = $true
                                }
                            }
                        }

                        Write-Verbose "Comparing .NET settings"
                        $referenceTlsObject.TlsSettings.Registry.NET.GetEnumerator() | ForEach-Object {
                            if ($_.key -ne "NETv2") {
                                Write-Verbose "$($_.key) - Current .NET mismatch value: $netMismatchFound"
                                $netParams = @{
                                    ReferenceObject  = $_.value
                                    DifferenceObject = $tls.TlsSettings.Registry.NET["$($_.key)"]
                                    Property         = "SchUseStrongCrypto", "WowSchUseStrongCrypto", "SystemDefaultTlsVersions", "WowSystemDefaultTlsVersions"
                                    IncludeEqual     = $true
                                }
                                $netResults = Compare-Object @netParams
                                foreach ($netR in $netResults) {
                                    if ($netR.SideIndicator -ne "==") {
                                        $netMismatchFound = $true
                                    }
                                }
                            } else {
                                Write-Verbose "NETv2 is only required for Exchange 2010 - going to skip validation"
                            }
                        }

                        if (($tlsMismatchFound -eq $false) -and
                            ($netMismatchFound -eq $false)) {
                            Write-Verbose "TLS settings are the same on both systems - Reference: $($referenceTlsObject.ComputerName) Server: $($tls.ComputerName)"
                            $tlsServersPassedList.Add($tls)
                            $matchIndex++
                        } else {
                            Write-Verbose "TLS settings are different - Reference: $($referenceTlsObject.ComputerName) Server: $($tls.ComputerName)"
                            $tlsMisconfiguredList.Add($tls)
                        }
                    }

                    if ($matchIndex -ge $tlsMisconfiguredList.Count) {
                        Write-Verbose "We found the TLS configuration that exists on the most systems within the organization"
                        $majorityFound = $true
                    } else {
                        Write-Verbose "We did no find the TLS configuration that exists on the most systems. Retrying with the next server"
                        $tlsServersPassedList.Clear()
                        $tlsMisconfiguredList.Clear()
                        $refIndex++
                    }
                } else {
                    Write-Verbose "Server: $($referenceTlsObject.ComputerName) has invalid TLS settings and will be skipped as reference"
                    $refIndex++
                    if ($TlsSettingsList.Count -eq $refIndex) {
                        Write-Verbose "We did not find any server returning a valid Tls configuration"
                        foreach ($tls in $TlsSettingsList) {
                            $tlsMisconfiguredList.Add($tls)
                        }
                        $stopProcessing = $true
                    }
                }
            }

            return [PSCustomObject]@{
                MajorityFound     = $majorityFound
                MajorityConfig    = if ($majorityFound) { $referenceTlsObject.TlsSettings } else { $null }
                MajorityServer    = if ($majorityFound) { $referenceTlsObject.ComputerName } else { $null }
                ServersPassedList = $tlsServersPassedList
                MisconfiguredList = $tlsMisconfiguredList
            }
        }
    } process {
        $tlsConfiguration = GetTLSConfigurationForAllServers -ExchangeServers $ExchangeServers
        $tlsCompared = CompareTlsServerSettings -TlsSettingsList $tlsConfiguration.TlsSettingsReturned

        if (($null -ne $tlsConfiguration) -and
            ($null -ne $tlsCompared)) {
            $actionsRequiredList = New-Object 'System.Collections.Generic.List[object]'

            if ($tlsConfiguration.NumberOfServersPassed -ne $tlsConfiguration.NumberOfTlsSettingsReturned) {
                $serverReachableParam = @{
                    Name   = "Not all servers are reachable"
                    List   = $tlsConfiguration.UnreachableServers
                    Action = "Check connectivity and validate the TLS configuration manually"
                }
                $action = NewActionObject @serverReachableParam
                Write-Verbose "Unable to compare the TLS configuration for all servers within your organization"
                $actionsRequiredList.Add($action)
            }

            if ($tlsCompared.MajorityFound -eq $false) {
                $majorityFoundParam = @{
                    Name   = "No majority TLS configuration found"
                    Action = "Please ensure that all of your servers are running the same TLS configuration"
                }
                $action = NewActionObject @majorityFoundParam
                Write-Verbose "Unable to find a majority of correct TLS configurations within your organization"
                $actionsRequiredList.Add($action)
            } else {
                $tlsVersionList = New-Object 'System.Collections.Generic.List[object]'
                $tlsCompared.MajorityConfig.Registry.TLS.GetEnumerator() | ForEach-Object {
                    $tlsVersionObject = [PSCustomObject]@{
                        TlsVersion    = $_.key
                        ServerEnabled = $_.value.ServerEnabled
                        ClientEnabled = $_.Value.ClientEnabled
                    }
                    $tlsVersionList.Add($tlsVersionObject)
                }

                $netVersionList = New-Object 'System.Collections.Generic.List[object]'
                $tlsCompared.MajorityConfig.Registry.NET.GetEnumerator() | ForEach-Object {
                    $netVersionObject = [PSCustomObject]@{
                        NETVersion                  = $_.key
                        SystemDefaultTlsVersions    = $_.value.SystemDefaultTlsVersions
                        WowSystemDefaultTlsVersions = $_.value.WowSystemDefaultTlsVersions
                        SchUseStrongCrypto          = $_.value.SchUseStrongCrypto
                        WowSchUseStrongCrypto       = $_.value.WowSchUseStrongCrypto
                    }
                    $netVersionList.Add($netVersionObject)
                    if ($_.key -ne "NETv2") {
                        if (($_.value.SchUseStrongCrypto -eq $false) -or
                            ($_.value.WowSchUseStrongCrypto -eq $false)) {
                            $netv4StrongCryptoParams = @{
                                Name   = "SchUseStrongCrypto is not configured as expected"
                                Action = "Configure SchUseStrongCrypto for $($_.key) as described here: https://aka.ms/PlaceHolderLink"
                            }
                            $action = NewActionObject @netv4StrongCryptoParams
                            Write-Verbose "SchUseStrongCrypto doesn't match the expected configuration"
                            $actionsRequiredList.Add($action)
                        }

                        if (($_.value.SystemDefaultTlsVersions -eq $false) -or
                            ($_.value.WowSystemDefaultTlsVersions -eq $false)) {
                            $netv4SystemDefaultParams = @{
                                Name   = "SystemDefaultTlsVersions is not configured as expected"
                                Action = "Configure SystemDefaultTlsVersions for $($_.key) as described here: https://aka.ms/PlaceHolderLink"
                            }
                            $action = NewActionObject @netv4SystemDefaultParams
                            Write-Verbose "SystemDefaultTlsVersions doesn't match the expected configuration"
                            $actionsRequiredList.Add($action)
                        }
                    }
                }

                if ($tlsCompared.MisconfiguredList.Count -ge 1) {
                    $misconfiguredListParams = @{
                        Name   = "$($tlsCompared.MisconfiguredList.Count) server(s) have a different TLS configuration"
                        List   = $tlsCompared.MisconfiguredList.ComputerName
                        Action = "Please ensure that the listed servers are running the same TLS configuration as: $($tlsCompared.MajorityServer)"
                    }
                    $action = NewActionObject @misconfiguredListParams
                    $actionsRequiredList.Add($action)
                }
            }
        }
    } end {
        return [PSCustomObject]@{
            CheckPassed         = ($actionsRequiredList.Count -eq 0)
            TlsVersions         = $tlsVersionList
            NetVersions         = $netVersionList
            ServerPassed        = $tlsCompared.ServersPassedList
            ServerFailed        = $tlsCompared.MisconfiguredList
            ReferenceServer     = $tlsCompared.MajorityServer
            ActionsRequired     = $actionsRequiredList
            ServerFailedToReach = $tlsConfiguration.UnreachableServers
        }
    }
}
