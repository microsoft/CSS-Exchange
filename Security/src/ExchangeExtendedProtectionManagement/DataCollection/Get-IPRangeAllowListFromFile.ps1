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
            Write-Host "The path to file specified is invalid. Please provide a valid path." -ForegroundColor Red
            $results.IsError = $true
            return
        }

        try {
            $SubnetStrings = (Get-Content -Path $FilePath)
        } catch {
            Write-Host "Unable to read the content of specified file. Inner Exception" -ForegroundColor Red
            Write-HostErrorInformation $_
            $results.IsError = $true
            return
        }

        <#if ($null -eq $SubnetStrings -or $SubnetStrings.Length -eq 0) {
            Write-Host "The provided file is empty."
            return
        }#>

        # Log all the IPs present in the txt file supplied by user
        Write-Verbose ("Read the contents of the file Successfully. List of IP ranges received from user: {0}" -f [string]::Join(", ", $SubnetStrings))

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
                    Write-Host ("Invalid IP address: {0} found in CSV." -f $IpAddressString) -ForegroundColor Red
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
                        Write-Host ("Invalid Subnet Mask found: Unable to parse Subnet Mask {0}. Note: Subnet Mask must be either empty or a non-negative integer. For IPv4 the value must be <= 32 and for IPv6 the value must be <= 128." -f $SubnetMaskString) -ForegroundColor Red
                        $results.IsError = $true
                        return
                    } elseif (($SubnetMask -gt 32 -and -not $IsIPv6) -or $SubnetMask -gt 128 -or $SubnetMask -lt 0) {
                        Write-Host ("Invalid Subnet Mask found: The Subnet Mask {0} is not in valid range. Note: Subnet Mask must be either empty or a non-negative integer. For IPv4 the value must be <= 32 and for IPv6 the value must be <= 128." -f $SubnetMaskString) -ForegroundColor Red
                        $results.IsError = $true
                        return
                    }

                    $results.ipRangeAllowListRules  += @{Type = "Subnet"; IP=$IpAddressString; SubnetMask=$SubnetMaskString; Allowed=$true }
                } else {
                    if ($IsIPv6) {
                        $results.ipRangeAllowListRules  += @{Type = "Single IP"; IP=$IpAddressString; SubnetMask="128"; Allowed=$true }
                    } else {
                        $results.ipRangeAllowListRules  += @{Type = "Single IP"; IP=$IpAddressString; SubnetMask="32"; Allowed=$true }
                    }
                }
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
