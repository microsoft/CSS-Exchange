# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Used to test the TLS Configuration
function Invoke-ExtendedProtectionTlsPrerequisitesCheck {
    [CmdletBinding()]
    [OutputType("System.Object")]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$TlsConfiguration
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

        function GroupTlsServerSettings {
            [CmdletBinding()]
            param(
                [System.Collections.Generic.List[object]]$TlsSettingsList
            )

            $groupedResults = New-Object 'System.Collections.Generic.List[object]'

            # loop through the least amount of times to compare the TLS settings
            # if the values are different add them to the list
            $tlsKeys = @("1.0", "1.1", "1.2")
            $netKeys = @("NETv4") # Only think we care about v4

            foreach ($serverTls in $TlsSettingsList) {
                $currentServer = $serverTls.FQDN
                $tlsSettings = $serverTls.Settings
                # Removing TLS 1.3 here to avoid it being displayed
                $tlsSettings.Registry.TLS.Remove("1.3")
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
                            break
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
                    Write-Verbose "This server's Security Protocol is set to $($tlsSettings.SecurityProtocol)"

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

        $actionsRequiredList = New-Object 'System.Collections.Generic.List[object]'
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {

        $tlsGroupedResults = @(GroupTlsServerSettings -TlsSettingsList $TlsConfiguration)

        if ($null -ne $tlsGroupedResults -and
            $tlsGroupedResults.Count -gt 0) {

            foreach ($tlsResults in $tlsGroupedResults) {
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
                            Action = "Configure SchUseStrongCrypto for $key as described here: https://aka.ms/ExchangeEPDoc"
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
                            Action = "Configure SystemDefaultTlsVersions for $key as described here: https://aka.ms/ExchangeEPDoc"
                        }
                        $actionsRequiredList.Add((NewActionObject @params))
                        Write-Verbose "SystemDefaultTlsVersions doesn't match the expected configuration"
                    }
                }
            }

            if ($tlsGroupedResults.Count -gt 1) {
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
            CheckPassed     = ($actionsRequiredList.Count -eq 0)
            TlsSettings     = $tlsGroupedResults
            ActionsRequired = $actionsRequiredList
        }
    }
}
