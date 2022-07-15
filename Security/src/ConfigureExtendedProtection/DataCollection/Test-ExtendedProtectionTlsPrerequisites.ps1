# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# TODO: Move this to shared functions onces the script goes public
. $PSScriptRoot\..\..\..\..\Diagnostics\HealthChecker\DataCollection\ServerInformation\Get-AllTlsSettings.ps1

function Test-ExtendedProtectionTlsPrerequisites {
    [CmdletBinding()]
    [OutputType("System.Object")]
    param(
        [Parameter(Mandatory = $true)]
        [System.Object[]]$ExchangeServers
    )

    begin {
        function GetTLSConfigurationForAllServers {
            [CmdletBinding()]
            [OutputType("System.Object")]
            param(
                [System.Object[]]$ExchangeServers
            )

            $tlsSettingsList = New-Object 'System.Collections.Generic.List[object]'
            $serversUnreachableList = New-Object 'System.Collections.Generic.List[string]'

            $counter = 0
            foreach ($server in $ExchangeServers) {
                $tlsSettings = Get-AllTlsSettings -MachineName $server.Fqdn
                $counter = $counter + 1
                $completed = ($counter/($ExchangeServers.Count)*100)
                Write-Progress -Activity "Querying TLS Settings" -Status "Progress:" -PercentComplete $completed

                if ($null -ne $tlsSettings.SecurityProtocol) {
                    Write-Verbose "TLS settings successfully received"
                    $tlsSettingsList.Add([PSCustomObject]@{
                            ComputerName = $server.Fqdn
                            TlsSettings  = $tlsSettings
                        })
                } else {
                    Write-Verbose "Unable to query TLS settings"
                    $serversUnreachableList.Add($server.Fqdn)
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
            $majorityFound = $false
            $refIndex = 0

            # We loop through the collected TLS settings and trying to find a valid configuration that exists on the majority of
            # the Exchange servers within the organization. We compare the properties of any other servers TLS settings
            # against the reference configuration.
            while (($majorityFound -eq $false) -or
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
                        $tlsMisconfiguredList.Clear()
                        $refIndex++
                    }
                } else {
                    Write-Verbose "Server: $($referenceTlsObject.ComputerName) has invalid TLS settings and will be skipped as reference"
                    $refIndex++
                }
            }

            return [PSCustomObject]@{
                MajorityFound     = $majorityFound
                MajorityConfig    = if ($majorityFound) { $referenceTlsObject.TlsSettings } else { $null }
                MajorityServer    = if ($majorityFound) { $referenceTlsObject.ComputerName } else { $null }
                MisconfiguredList = $tlsMisconfiguredList
            }
        }
    } process {
        $tlsConfiguration = GetTLSConfigurationForAllServers -ExchangeServers $ExchangeServers
        $tlsComparedInfo = CompareTlsServerSettings -TlsSettingsList $tlsConfiguration.TlsSettingsReturned
    } end {
        return [PSCustomObject]@{
            TlsConfiguration = $tlsConfiguration
            TlsComparedInfo  = $tlsComparedInfo
        }
    }
}
