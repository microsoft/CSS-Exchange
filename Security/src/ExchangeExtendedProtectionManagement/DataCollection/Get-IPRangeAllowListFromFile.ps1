# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

# This function is used to get a list of all the IP in use by the Exchange Servers across the topology
function Get-IPRangeAllowListFromFile {
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    begin {
        $results = @{
            ipRangeAllowListRules = New-Object 'System.Collections.Generic.List[object]'
            IsError               = $true
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
    process {
        try {
            $SubnetStrings = (Get-Content -Path $FilePath -ErrorAction Stop) | Where-Object { $_.trim() -ne "" }
        } catch {
            Write-Host "Unable to read the content of file provided for IPRange. Inner Exception" -ForegroundColor Red
            Write-HostErrorInformation $_
            return
        }

        if ($null -eq $SubnetStrings -or $SubnetStrings.Length -eq 0) {
            Write-Host "The IP range file provided is empty. Please provide a valid file." -ForegroundColor Red
            return
        } else {
            $ipRangesString  = [string]::Join(", ", $SubnetStrings)
        }

        # Log all the IPs present in the txt file supplied by user
        Write-Verbose ("Read the contents of the file Successfully. List of IP ranges received from user: {0}" -f $ipRangesString)

        Write-Verbose "Validating the IP ranges specified in the file"
        try {
            foreach ($SubnetString in $SubnetStrings) {
                $SubnetString = $SubnetString.Trim()

                $IpAddressString = $SubnetString.Split("/")[0]
                $SubnetMaskString = $SubnetString.Split("/")[1]

                # Check the type of IP address (IPv4/IPv6)
                $IpAddress = $IpAddressString -as [IPAddress]
                $baseError = "Input file provided for IPRange doesn't have correct syntax of IPs or IP subnets."
                if ($null -eq $IpAddress -or $null -eq $IpAddress.AddressFamily) {
                    # Invalid IP address found
                    Write-Host ("$baseError Re-execute the command with proper input file for IPRange parameter. Invalid IP address detected: {0}." -f $IpAddressString) -ForegroundColor Red
                    return
                }

                $IsIPv6 = $IpAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6

                if ($SubnetMaskString) {
                    # Check if the subnet value is valid (IPv4 <= 32, IPv6 <= 128 or empty)
                    $SubnetMask = $SubnetMaskString -as [int]

                    $InvalidSubnetMaskString = "$baseError Invalid Subnet Mask found: The Subnet Mask $SubnetMaskString is not in valid range.Note: Subnet Mask must be either empty or a non-negative integer.  For IPv4 the value must be <= 32 and for IPv6 the value must be <= 128. Re-execute the command with proper input file for IPRange parameter."
                    if ($null -eq $SubnetMask) {
                        Write-Host ($InvalidSubnetMaskString) -ForegroundColor Red
                        return
                    } elseif (($SubnetMask -gt 32 -and -not $IsIPv6) -or $SubnetMask -gt 128 -or $SubnetMask -lt 0) {
                        Write-Host ($InvalidSubnetMaskString) -ForegroundColor Red
                        return
                    }

                    if ($null -eq ($results.ipRangeAllowListRules | Where-Object { $_.Type -eq "Subnet" -and $_.IP -eq $IpAddressString -and $_.SubnetMask -eq $SubnetMaskString })) {
                        $results.ipRangeAllowListRules.Add(@{Type = "Subnet"; IP=$IpAddressString; SubnetMask=$SubnetMaskString; Allowed=$true })
                    } else {
                        Write-Verbose ("Not adding $IpAddressString/$SubnetMaskString to the list as it is a duplicate entry in the file provided.")
                    }
                } else {
                    if ($null -eq ($results.ipRangeAllowListRules | Where-Object { $_.Type -eq "Single IP" -and $_.IP -eq $IpAddressString })) {
                        $results.ipRangeAllowListRules.Add(@{Type = "Single IP"; IP=$IpAddressString; Allowed=$true })
                    } else {
                        Write-Verbose ("Not adding $IpAddressString to the list as it is a duplicate entry in the file provided.")
                    }
                }
            }

            if ($results.ipRangeAllowListRules.count -gt 500) {
                Write-Host ("Too many IP filtering rules. Please reduce the specified entries by providing appropriate subnets." -f $SubnetMaskString) -ForegroundColor Red
                return
            }
        } catch {
            Write-Host ("Unable to create IP allow rules. Inner Exception") -ForegroundColor Red
            Write-HostErrorInformation $_
            return
        }

        $results.IsError = $false
    }
    end {
        return $results
    }
}
