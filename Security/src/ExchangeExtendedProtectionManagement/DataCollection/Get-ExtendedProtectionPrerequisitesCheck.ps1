# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\TLS\Get-AllTlsSettings.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExtendedProtectionConfiguration.ps1

# This function is used to collect the required information needed to determine if a server is ready for Extended Protection
function Get-ExtendedProtectionPrerequisitesCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ExchangeServers,

        [Parameter(Mandatory = $false)]
        [string[]]$SiteVDirLocations,

        [Parameter(Mandatory = $false)]
        [bool]$SkipEWS
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
            Write-Verbose "$($progressParams.Status)"

            $params = @{
                ComputerName         = $server.ToString()
                IsClientAccessServer = $server.IsClientAccessServer
                IsMailboxServer      = $server.IsMailboxServer
                ExcludeEWS           = $SkipEWS
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
                $tlsSettings = Get-AllTlsSettings -MachineName $server
            } else {
                Write-Verbose "Server doesn't appear to be online. Skipped over trying to get the TLS settings"
            }

            $results.Add([PSCustomObject]@{
                    ComputerName                    = $server.ToString()
                    ExtendedProtectionConfiguration = $extendedProtectionConfiguration
                    TlsSettings                     = [PSCustomObject]@{
                        ComputerName = $server.ToString()
                        Settings     = $tlsSettings
                    }
                    ServerOnline                    = $extendedProtectionConfiguration.ServerConnected
                })
        }
        Write-Progress @progressParams -Completed
    } end {
        return $results
    }
}
