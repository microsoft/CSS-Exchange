# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-AllNicInformation.ps1

# This function is used to get a list of all the IP in use by the Exchange Servers across the topology
function Get-ExchangeServerIPs {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath,
        [Parameter(Mandatory = $false)]
        [object[]]$ExchangeServers
    )

    begin {
        $IPs           = New-Object 'System.Collections.Generic.List[string]'
        $FailedServers = New-Object 'System.Collections.Generic.List[string]'

        $progressParams = @{
            Activity        = "Getting List of IPs in use by Exchange Servers"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
    process {
        $counter = 0
        $totalCount = $ExchangeServers.Count

        foreach ($Server in $ExchangeServers) {
            $baseStatus = "Processing: $($Server.Name) -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Getting IPs"
            Write-Progress @progressParams

            $IpsFound = $false
            # TODO: Refactor Get-AllNicInformation function to get rid of the duplicate ComputerName / FQDN logic
            $HostNetworkInfo = Get-AllNicInformation -ComputerName $Server.FQDN
            if ($null -ne $HostNetworkInfo) {
                if ($null -ne $HostNetworkInfo.IPv4Addresses) {
                    foreach ($address in $HostNetworkInfo.IPv4Addresses) {
                        $IPs += $address.Address
                        $IpsFound = $true
                    }
                }
                if ($null -ne $HostNetworkInfo.IPv6Addresses) {
                    foreach ($address in $HostNetworkInfo.IPv6Addresses) {
                        $IPs += $address.Address
                        $IpsFound = $true
                    }
                }
            }

            if (-not $IpsFound) {
                $FailedServers += $Server.Name
                Write-Verbose "IP of $($Server.Name) cannot be found and will not be added to IP allow list."
            }

            $counter++
        }

        Write-Progress @progressParams -Completed
    }
    end {
        if ($FailedServers -gt 0) {
            Write-Host ("Unable to get IPs from the following servers: {0}" -f [string]::Join(", ", $FailedServers)) -ForegroundColor Red
        }

        try {
            $IPs | Out-File $OutputFilePath
            Write-Host ("Please find the collected IPs at {0}" -f $OutputFilePath)
        } catch {
            Write-Host "Unable to write to file. Please check the path provided. Inner Exception:" -ForegroundColor Red
            Write-HostErrorInformation $_
        }
    }
}
