# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Diagnostics\HealthChecker\DataCollection\ServerInformation\Get-AllNicInformation.ps1

# This function is used to get a list of all the IP in use by the Exchange Servers accross the topology
function Get-ExchangeServerIPs {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath
    )

    begin {
        $IPs           = @()
        $FailedServers = @()

        $progressParams = @{
            Activity        = "Getting List of IPs in use by Exchange Servers"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
    process {
        try {
            $ExchangeServers = Get-ExchangeServer
        } catch {
            Write-Host ("Unable to run Get-ExchangeServer due to: Inner Exception") -ForegroundColor Red
            Write-HostErrorInformation $_
            exit
        }

        $counter = 0
        $totalCount = $ExchangeServers.Count

        foreach ($Server in $ExchangeServers) {
            $baseStatus = "Processing: $($Server.Name) -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Getting IPs"
            Write-Progress @progressParams

            $HostNetworkInfo = Get-AllNicInformation -ComputerName $Server.Name -ComputerFQDN $Server.FQDN
            if ($null -ne $HostNetworkInfo) {
                if ($null -ne $HostNetworkInfo.IPv4Addresses) {
                    foreach ($address in $HostNetworkInfo.IPv4Addresses) {
                        $IPs += $address.Address
                    }
                }
                if ($null -ne $HostNetworkInfo.IPv6Addresses) {
                    foreach ($address in $HostNetworkInfo.IPv6Addresses) {
                        $IPs += $address.Address
                    }
                }
            } else {
                $FailedServers += $Server.Name
                Write-Verbose "Ip of $($Server.Name) cannot be found and will not be added to ip allow list." -ForegroundColor Red
            }

            $counter++
        }
    }
    end {
        if ($FailedServers -gt 0) {
            Write-Host ("Unable to get IPs from the following servers: {0}" -f [string]::Join(", ", $FailedServers)) -ForegroundColor Red
        }

        try {
            $IPs | Out-File $OutputFilePath
            Write-Host ("Please find the collected IPs at {0}" -f $OutputFilePath)
        } catch {
            Write-Host "Unable to write to file. Please check the path provided." -ForegroundColor Red
        }
    }
}
