# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

# This function is used to get a list of all the IP in use by the Exchange Servers accross the topology
function Get-IPRangeAllowListFromFile {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    begin {
        $results = @{
            ipRangeAllowListRules = @()
            IsError               = $false
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
    process {
        $FilePath = $FilePath.Trim('"', "'")
        $IsPathValid = Test-Path -Path $FilePath

        if ($IsPathValid -eq $false) {
            Write-Host "Input file name for provided for IPRange isn't valid. Rexecute the command with correct path for IPRange parameter." -ForegroundColor Red
            $results.IsError = $true
            return
        }

        try {
            $SubnetStrings = (Get-Content -Path $FilePath) | ? {$_.trim() -ne "" } 
        } catch {
            Write-Host "Unable to read the content of file provided for IPRange. Inner Exception" -ForegroundColor Red
            Write-HostErrorInformation $_
            $results.IsError = $true
            return
        }

        if ($null -eq $SubnetStrings -or $SubnetStrings.Length -eq 0) {
            $SubnetStrings = @()
            Write-Warning "The provided file is empty."
            $params = @{
                Message   = "Display Warning about using an empty ip file for ip filtering"
                Target    = "The file provided to create the ip filtering allow list is empty." +
                " Using this will block all external inbound connections." +
                "`r`nYou can find more information on: https://aka.ms/ExchangeEPDoc. Do you want to proceed?"
                Operation = "Enabling IP Filtering Mitigation"
            }

            Show-Disclaimer @params
            $ipRangesString = "{}"
        } else {
            $ipRangesString  = [string]::Join(", ", $SubnetStrings)
        }

        # Log all the IPs present in the txt file supplied by user
        Write-Verbose ("Read the contents of the file Successfully. List of IP ranges received from user: {0}" -f $ipRangesString)

        Write-Verbose "Validating the IP ranges specified in the file"
        try {
            foreach ($SubnetString in $SubnetStrings) {
                $SubnetString = $SubnetString.Trim()
                if ([string]::IsNullOrEmpty($SubnetString)) {
                    continue
                }

                $IpAddressString = $SubnetString.Split("/")[0]
                $SubnetMaskString = $SubnetString.Split("/")[1]

                # Check the type of IP address (IPv4/IPv6)
                $IsIPv6 = $false
                $IpAddress = $IpAddressString -as [IPAddress]

                if ($null -eq $IpAddress -or ($IpAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -and $IpAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6)) {
                    # Invalid IP address found
                    Write-Host ("Input file provided for IPRange doesn't have correct syntax of IPs or IP subnets. Rexecute the command with proper input file for IPRange parameter. Invalid IP address detected: {0}." -f $IpAddressString) -ForegroundColor Red
                    $results.IsError = $true
                    return
                } elseif ($IpAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                    $IsIPv6 = $true;
                }

                $IsSubnetMaskPresent = [Bool]$SubnetMaskString

                if ($IsSubnetMaskPresent) {
                    # Check if the subnet value is valid (IPv4 <= 32, IPv6 <= 128 or empty)
                    $SubnetMask = $SubnetMaskString -as [int]
                    if ($null -eq $SubnetMask) {
                        Write-Host ("Input file provided for IPRange doesn't have correct syntax of IPs or IP subnets. Rexecute the command with proper input file for IPRange parameter. Invalid Subnet Mask found: Unable to parse Subnet Mask {0}. Note: Subnet Mask must be either empty or a non-negative integer. For IPv4 the value must be <= 32 and for IPv6 the value must be <= 128." -f $SubnetMaskString) -ForegroundColor Red
                        $results.IsError = $true
                        return
                    } elseif (($SubnetMask -gt 32 -and -not $IsIPv6) -or $SubnetMask -gt 128 -or $SubnetMask -lt 0) {
                        Write-Host ("Input file provided for IPRange doesn't have correct syntax of IPs or IP subnets. Rexecute the command with proper input file for IPRange parameter. Invalid Subnet Mask found: The Subnet Mask {0} is not in valid range. Note: Subnet Mask must be either empty or a non-negative integer. For IPv4 the value must be <= 32 and for IPv6 the value must be <= 128." -f $SubnetMaskString) -ForegroundColor Red
                        $results.IsError = $true
                        return
                    }
                    if ($null -eq ($results.ipRangeAllowListRules | Where-Object {$_.Type -eq "Subnet" -and $_.IP -eq $IpAddressString -and $_.SubnetMask -eq $SubnetMaskString -and $_.Allowed -eq $true})) {
                        $results.ipRangeAllowListRules  += @{Type = "Subnet"; IP=$IpAddressString; SubnetMask=$SubnetMaskString; Allowed=$true }
                    }
                } else {
                    if ($null -eq ($results.ipRangeAllowListRules | Where-Object {$_.Type -eq "Single IP" -and $_.IP -eq $IpAddressString -and $_.Allowed -eq $true})) {
                        $results.ipRangeAllowListRules  += @{Type = "Single IP"; IP=$IpAddressString; Allowed=$true }
                    }
                }
            }

            if($results.ipRangeAllowListRules.count -gt 500){
                Write-Host ("Too many IP filtering rules. Please reduce the specified entries by providing appropriate subnets." -f $SubnetMaskString) -ForegroundColor Red
                $results.IsError = $true
                return
            }

        } catch {
            Write-Host ("Unable to create IP allow rules. Inner Exception") -ForegroundColor Red
            Write-HostErrorInformation $_
            $results.IsError = $true
            return
        }
    }
    end {
        return $results
    }
}
