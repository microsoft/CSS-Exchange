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
                $completed = ($counter / ($ExchangeServers.Count) * 100)
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

            $groupedResults = New-Object 'System.Collections.Generic.List[object]'

            # loop through the least amount of times to compare the TLS settings
            # if the values are different add them to the list
            $tlsKeys = @("1.0", "1.1", "1.2")
            $netKeys = @("NETv4") # Only think we care about v4

            foreach ($serverTls in $TlsSettingsList) {
                $currentServer = $serverTls.ComputerName
                $tlsSettings = $serverTls.TlsSettings
                $tlsRegistry = $tlsSettings.Registry.TLS
                $netRegistry = $tlsSettings.Registry.NET
                $listIndex = 0
                $addNewGroupList = $true
                Write-Verbose "Working on Server $currentServer"

                # only need to compare against the current groupedResults List
                # if this is the first time, we don't compare we just add
                while ($listIndex -lt $groupedResults.Count) {
                    $referenceTlsSettings = $groupedResults[$listIndex].TlsSettings
                    $nextServer = $false
                    Write-Verbose "Working on TLS Setting index $listIndex"

                    foreach ($key in $tlsKeys) {
                        $props = $tlsRegistry[$key].PSObject.Properties.Name
                        $result = Compare-Object -ReferenceObject $referenceTlsSettings.Registry.TLS[$key] -DifferenceObject $tlsRegistry[$key] -Property $props
                        if ($null -ne $result) {
                            Write-Verbose "Found difference in TLS for $key"
                            $nextServer = $true
                            break;
                        }
                    }

                    if ($nextServer) { $listIndex++; continue; }

                    foreach ($key in $netKeys) {
                        $props = $netRegistry[$key].PSObject.Properties.Name
                        $result = Compare-Object -ReferenceObject $referenceTlsSettings.Registry.NET[$key] -DifferenceObject $netRegistry[$key] -Property $props
                        if ($null -ne $result) {
                            Write-Verbose "Found difference in NET for $key"
                            $nextServer = $true
                            break
                        }
                    }

                    if ($nextServer) { $listIndex++; continue; }
                    if ($tlsSettings.SecurityProtocol -ne $referenceTlsSettings.SecurityProtocol) { Write-Verbose "Security Protocol didn't match"; $listIndex++; continue; }

                    # we must match so add to the current groupResults and break
                    Write-Verbose "Server appears to match current reference TLS Object"
                    $groupedResults[$listIndex].MatchedServer.Add($currentServer)
                    Write-Verbose "Now $($groupedResults[$listIndex].MatchedServer.Count) servers match this reference"
                    $addNewGroupList = $false
                    break
                }

                if ($addNewGroupList) {
                    Write-Verbose "Added new grouped result because of server $currentServer"
                    $obj = [PSCustomObject]@{
                        TlsSettings   = $tlsSettings
                        MatchedServer = New-Object 'System.Collections.Generic.List[string]'
                    }
                    $obj.MatchedServer.Add($currentServer)
                    $groupedResults.Add($obj)
                }
            }
            return $groupedResults
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

            foreach ($tlsResults in $tlsCompared) {
                # Check for actions to take against
                $netKeys = @("NETv4")
                $netRegistry = $tlsResults.TlsSettings.Registry.NET
                foreach ($key in $netKeys) {
                    if ($netRegistry[$key].SchUseStrongCrypto -eq $false -or
                        $netRegistry[$key].WowSchUseStrongCrypto -eq $false -or
                        $null -eq $netRegistry[$key].SchUseStrongCryptoValue -or
                        $null -eq $netRegistry[$key].WowSchUseStrongCryptoValue) {
                        $params = @{
                            Name   = "SchUseStrongCrypto is not configured as expected"
                            List   = $tlsResults.MatchedServer
                            Action = "Configure SchUseStrongCrypto for $key as described here: https://aka.ms/PlaceHolderLink"
                        }
                        $actionsRequiredList.Add((NewActionObject @params))
                        Write-Verbose "SchUseStrongCrypto doesn't match the expected configuration"
                    }

                    if ($netRegistry[$key].SystemDefaultTlsVersions -eq $false -or
                        $netRegistry[$key].WowSystemDefaultTlsVersions -eq $false -or
                        $null -eq $netRegistry[$key].SystemDefaultTlsVersionsValue -or
                        $null -eq $netRegistry[$key].WowSystemDefaultTlsVersionsValue) {
                        $params = @{
                            Name   = "SystemDefaultTlsVersions is not configured as expected"
                            List   = $tlsResults.MatchedServer
                            Action = "Configure SystemDefaultTlsVersions for $key as described here: https://aka.ms/PlaceHolderLink"
                        }
                        $actionsRequiredList.Add((NewActionObject @params))
                        Write-Verbose "SystemDefaultTlsVersions doesn't match the expected configuration"
                    }
                }
            }

            if ($tlsCompared.Count -gt 1) {
                $params = @{
                    Name   = "Multiple TLS differences have been detected"
                    Action = "Please ensure that all servers are running the same TLS configuration"
                }
                $action = NewActionObject @params
                $actionsRequiredList.Add($action)
            }
        }
    } end {
        return [PSCustomObject]@{
            CheckPassed         = ($actionsRequiredList.Count -eq 0)
            TlsSettings         = $tlsCompared
            ActionsRequired     = $actionsRequiredList
            ServerFailedToReach = $tlsConfiguration.UnreachableServers
        }
    }
}
