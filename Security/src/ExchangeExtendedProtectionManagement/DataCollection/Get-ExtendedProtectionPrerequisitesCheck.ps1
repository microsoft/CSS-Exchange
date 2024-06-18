# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\TLS\Get-AllTlsSettings.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExtendedProtectionConfiguration.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1

# This function is used to collect the required information needed to determine if a server is ready for Extended Protection
function Get-ExtendedProtectionPrerequisitesCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ExchangeServers,

        [Parameter(Mandatory = $false)]
        [string[]]$SiteVDirLocations,

        [Parameter(Mandatory = $false)]
        [bool]$SkipEWS,

        [Parameter(Mandatory = $false)]
        [bool]$SkipEWSFe
    )
    begin {
        $results = New-Object 'System.Collections.Generic.List[object]'
        $counter = 0
        $totalCount = $ExchangeServers.Count
        $progressParams = @{
            Activity        = "Prerequisites Check"
            Status          = [string]::Empty
            PercentComplete = 0
        }
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {
        foreach ($server in $ExchangeServers) {

            $counter++
            $baseStatus = "Processing: $server -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Extended Protection Configuration"
            Write-Progress @progressParams
            $tlsSettings = $null
            $registryValues = @{
                SuppressExtendedProtection = 0
                LmCompatibilityLevel       = $null
            }
            Write-Verbose "$($progressParams.Status)"

            $params = @{
                ComputerName         = $server.FQDN
                IsClientAccessServer = $server.IsClientAccessServer
                IsMailboxServer      = $server.IsMailboxServer
                ExcludeEWS           = $SkipEWS
                ExcludeEWSFe         = $SkipEWSFe
            }

            if ($null -ne $SiteVDirLocations) {
                $params.Add("SiteVDirLocations", $SiteVDirLocations)
            }
            $extendedProtectionConfiguration = Get-ExtendedProtectionConfiguration @params

            if ($extendedProtectionConfiguration.ServerConnected) {
                Write-Verbose "Server appears to be up going to get the TLS settings as well"
                $progressParams.Status = "$baseStatus TLS Settings"
                Write-Progress @progressParams
                Write-Verbose "$($progressParams.Status)"
                $tlsSettings = Get-AllTlsSettings -MachineName $server.FQDN
                $params = @{
                    MachineName = $server.FQDN
                    SubKey      = "SYSTEM\CurrentControlSet\Control\Lsa"
                }

                $lmValue = Get-RemoteRegistryValue @params -GetValue "LmCompatibilityLevel" -ValueType "DWord"
                [int]$epValue = Get-RemoteRegistryValue @params -GetValue "SuppressExtendedProtection"

                if ($null -eq $lmValue) { $lmValue = 3 }

                Write-Verbose "Server $($server.FQDN) LmCompatibilityLevel set to $lmValue"
                $registryValues.SuppressExtendedProtection = $epValue
                $registryValues.LmCompatibilityLevel = $lmValue
            } else {
                Write-Verbose "Server doesn't appear to be online. Skipped over trying to get the TLS settings"
            }

            $results.Add([PSCustomObject]@{
                    ComputerName                    = $server.Name
                    FQDN                            = $server.FQDN
                    ExtendedProtectionConfiguration = $extendedProtectionConfiguration
                    TlsSettings                     = [PSCustomObject]@{
                        ComputerName = $server.Name
                        FQDN         = $server.FQDN
                        Settings     = $tlsSettings
                    }
                    RegistryValue                   = $registryValues
                    ServerOnline                    = $extendedProtectionConfiguration.ServerConnected
                })
        }
        Write-Progress @progressParams -Completed
    } end {
        return $results
    }
}
