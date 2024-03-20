# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

function Invoke-ValidateMitigation {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ExchangeServers,
        [Parameter(Mandatory = $false)]
        [object[]]$ipRangeAllowListRules,
        [Parameter(Mandatory = $true)]
        [string[]]$SiteVDirLocations
    )

    begin {
        $FailedServersEP = @{}
        $FailedServersFilter = @{}

        $UnMitigatedServersEP = @{}
        $UnMitigatedServersFilter = @{}

        $progressParams = @{
            Activity        = "Verifying Mitigations"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $ValidateMitigationScriptBlock = {
            param(
                [Object]$Arguments
            )

            $SiteVDirLocations = $Arguments.SiteVDirLocations
            $IpRangesForFiltering = $Arguments.IpRangesForFiltering

            $results = @{}

            function GetLocalIPAddresses {
                $ips = New-Object 'System.Collections.Generic.List[string]'
                $interfaces = Get-NetIPAddress
                foreach ($interface in $interfaces) {
                    if ($interface.AddressState -eq 'Preferred') {
                        $ips += $interface.IPAddress
                    }
                }

                return $ips
            }

            # Set EP to None
            function GetExtendedProtectionState {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation
                )

                $Filter = 'system.webServer/security/authentication/windowsAuthentication/extendedProtection'

                $ExtendedProtection = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -Name tokenChecking
                return $ExtendedProtection
            }

            # Create IP allow list from user provided IP subnets
            function VerifyIPRangeAllowList {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation,
                    [Parameter(Mandatory = $true)]
                    [object[]]$IpFilteringRules,
                    [Parameter(Mandatory = $true)]
                    [Hashtable]$state
                )

                $state.IsWindowsFeatureInstalled = (Get-WindowsFeature -Name "Web-IP-Security").InstallState -eq "Installed"
                $state.IsWindowsFeatureVerified = $true

                if (-not $state.IsWindowsFeatureInstalled) {
                    return
                }

                $Filter = 'system.webServer/security/ipSecurity'
                $IISPath = 'IIS:\'

                $ExistingRules = @(Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -Name collection)

                foreach ($IpFilteringRule in $IpFilteringRules) {
                    $ExistingIPSubnetRule = $ExistingRules | Where-Object {
                        $_.ipAddress -eq $IpFilteringRule.IP -and
                        ($_.subnetMask -eq $IpFilteringRule.SubnetMask -or $IpFilteringRule.Type -eq "Single IP") -and
                        $_.allowed -eq $IpFilteringRule.Allowed
                    }

                    if ($null -eq $ExistingIPSubnetRule) {
                        if ($IpFilteringRule.Type -eq "Single IP") {
                            $IpString = $IpFilteringRule.IP
                        } else {
                            $IpString = ("{0}/{1}" -f $IpFilteringRule.IP, $IpFilteringRule.SubnetMask)
                        }
                        $state.RulesNotFound += $IpString
                    }
                }

                $state.AreIPRulesVerified = $true

                $state.IsDefaultFilterDeny = -not ((Get-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted").Value)
                $state.IsDefaultFilterVerified = $true
            }

            foreach ($SiteVDirLocation in $SiteVDirLocations) {
                try {
                    $state = @{
                        IsEPVerified              = $false
                        IsEPOff                   = $false
                        IsWindowsFeatureInstalled = $false
                        IsWindowsFeatureVerified  = $false
                        AreIPRulesVerified        = $false
                        IsDefaultFilterVerified   = $false
                        IsDefaultFilterDeny       = $false
                        RulesNotFound             = New-Object 'System.Collections.Generic.List[string]'
                        ErrorContext              = $null
                    }

                    $EPState = GetExtendedProtectionState -SiteVDirLocation $SiteVDirLocation
                    if ($EPState -eq "None") {
                        $state.IsEPOff = $true
                    } else {
                        $state.IsEPOff = $false
                    }

                    $state.IsEPVerified = $true

                    if ($null -ne $IpRangesForFiltering) {
                        $localIPs = GetLocalIPAddresses

                        $localIPs | ForEach-Object {
                            $IpRangesForFiltering += @{Type="Single IP"; IP=$_; Allowed=$true }
                        }

                        VerifyIPRangeAllowList -SiteVDirLocation $SiteVDirLocation -IpFilteringRules $IpRangesForFiltering -state $state
                    }
                } catch {
                    $state.ErrorContext = $_
                }

                $results[$SiteVDirLocation] = $state
            }

            return $results
        }
    } process {
        $ScriptBlockArgs = [PSCustomObject]@{
            SiteVDirLocations    = $SiteVDirLocations
            IpRangesForFiltering = $ipRangeAllowListRules
        }

        $counter = 0
        $totalCount = $ExchangeServers.Count
        if ($null -eq $ipRangeAllowListRules) {
            $ipRangeAllowListString = "null"
        } else {
            $ipRangeAllowListString = [string]::Join(", ", $ipRangeAllowListRules)
        }

        $SiteVDirLocations | ForEach-Object {
            $FailedServersEP[$_] = New-Object 'System.Collections.Generic.List[string]'
            $FailedServersFilter[$_] = New-Object 'System.Collections.Generic.List[string]'

            $UnMitigatedServersEP[$_] = New-Object 'System.Collections.Generic.List[string]'
            $UnMitigatedServersFilter[$_] = New-Object 'System.Collections.Generic.List[string]'
        }

        foreach ($Server in $ExchangeServers) {
            $baseStatus = "Processing: $Server -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Validating rules"
            Write-Progress @progressParams
            $counter ++

            Write-Verbose ("Calling Invoke-ScriptBlockHandler on Server {0} with arguments SiteVDirLocations: {1}, ipRangeAllowListRules: {2}" -f $Server, [string]::Join(", ", $SiteVDirLocations), $ipRangeAllowListString)
            $resultsInvoke = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock $ValidateMitigationScriptBlock -ArgumentList $ScriptBlockArgs

            if ($null -eq $resultsInvoke) {
                $line = "Server Unreachable: Unable to validate IP filtering rules on server $($Server)."
                Write-Verbose $line
                Write-Warning $line
                $SiteVDirLocations | ForEach-Object { $FailedServersEP[$_].Add($Server) }
                $SiteVDirLocations | ForEach-Object { $FailedServersFilter[$_].Add($Server) }
                continue
            }

            foreach ($SiteVDirLocation in $SiteVDirLocations) {
                $state = $resultsInvoke[$SiteVDirLocation]

                if ($state.IsEPOff) {
                    Write-Verbose ("Expected: The state of Extended protection flag is None for VDir $($SiteVDirLocation) on server $Server")
                } elseif ($state.IsEPVerified) {
                    Write-Verbose ("Unexpected: The state of Extended protection flag is not set to None for VDir $($SiteVDirLocation) on server $Server")
                    $UnMitigatedServersEP[$SiteVDirLocation] += $Server
                } else {
                    Write-Host ("Unknown: Script failed to get state of Extended protection flag for VDir $($SiteVDirLocation) with Inner Exception") -ForegroundColor Red
                    Write-HostErrorInformation $results.ErrorContext
                    $FailedServersEP[$SiteVDirLocation] += $Server
                    $FailedServersFilter[$SiteVDirLocation] += $Server
                    continue
                }

                $IsFilterUnMitigated = $false

                if (-not $state.IsWindowsFeatureVerified) {
                    Write-Host ("Unknown: Script failed to verify if the Windows feature Web-IP-Security is present for VDir $($SiteVDirLocation) on server $Server with Inner Exception") -ForegroundColor Red
                    Write-HostErrorInformation $results.ErrorContext
                    $FailedServersFilter[$SiteVDirLocation] += $Server
                    continue
                } elseif (-not $state.IsWindowsFeatureInstalled) {
                    Write-Verbose ("Unexpected: Windows feature Web-IP-Security is not present on the server for VDir $($SiteVDirLocation) on server $Server")
                    $IsFilterUnMitigated = $true
                } else {
                    Write-Verbose ("Expected: Successfully verified that the Windows feature Web-IP-Security is present on the server for VDir $($SiteVDirLocation) on server $Server")
                    if (-not $state.AreIPRulesVerified) {
                        Write-Host ("Unknown: Script failed to verify IP Filtering Rules for VDir $($SiteVDirLocation) on server $Server with Inner Exception") -ForegroundColor Red
                        Write-HostErrorInformation $results.ErrorContext
                        $FailedServersFilter[$SiteVDirLocation] += $Server
                        continue
                    } elseif ($null -ne $state.RulesNotFound -and $state.RulesNotFound.Length -gt 0) {
                        Write-Verbose ("Unexpected: Some or all the rules present in the file specified aren't applied for VDir $($SiteVDirLocation) on server $Server")
                        Write-Verbose ("Following Rules weren't found: {0}" -f [string]::Join(", ", [string[]]$state.RulesNotFound))
                        $IsFilterUnMitigated = $true
                    } else {
                        Write-Verbose ("Expected: Successfully verified all the IP filtering rules for VDir $($SiteVDirLocation) on server $Server")
                    }

                    if ($state.IsDefaultFilterDeny) {
                        Write-Verbose ("Expected: The default IP Filtering rule is set to deny for VDir $($SiteVDirLocation) on server $Server")
                    } elseif ($state.IsDefaultFilterVerified) {
                        Write-Verbose ("Unexpected: The default IP Filtering rule is not set to deny for VDir $($SiteVDirLocation) on server $Server")
                        $IsFilterUnMitigated = $true
                    } else {
                        Write-Host ("Unknown: Script failed to get the default IP Filtering rule for VDir $($SiteVDirLocation) on server $Server with Inner Exception") -ForegroundColor Red
                        Write-HostErrorInformation $results.ErrorContext
                        $FailedServersFilter[$SiteVDirLocation] += $Server
                        continue
                    }
                }

                if ($IsFilterUnMitigated) {
                    $UnMitigatedServersFilter[$SiteVDirLocation] += $Server
                }
            }
        }
    } end {
        $FoundFailedOrUnmitigated = $false
        foreach ($SiteVDirLocation in $SiteVDirLocations) {
            if ($UnMitigatedServersEP[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("Extended Protection on the following servers are not set to expected values for VDir {0}: {1}" -f $SiteVDirLocation, [string]::Join(", ", $UnMitigatedServersEP[$SiteVDirLocation])) -ForegroundColor Red
                $FoundFailedOrUnmitigated = $true
            }

            if ($UnMitigatedServersFilter[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("IP Filtering Rules or Default IP rule on the following servers does not contain all the IP Ranges/addresses provided for validation in VDir {0}: {1}" -f $SiteVDirLocation, [string]::Join(", ", $UnMitigatedServersFilter[$SiteVDirLocation])) -ForegroundColor Red
                $FoundFailedOrUnmitigated = $true
            }

            if ($FailedServersEP[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("Unable to verify Extended Protection on the following servers for VDir {0}: {1}" -f $SiteVDirLocation, [string]::Join(", ", $FailedServersEP[$SiteVDirLocation])) -ForegroundColor Red
                $FoundFailedOrUnmitigated = $true
            }

            if ($FailedServersFilter[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("Unable to verify IP Filtering Rules on the following servers for VDir {0}: {1}" -f $SiteVDirLocation, [string]::Join(", ", $FailedServersFilter[$SiteVDirLocation])) -ForegroundColor Red
                $FoundFailedOrUnmitigated = $true
            }
        }

        if (-not $FoundFailedOrUnmitigated) {
            Write-Host "All the servers have been validated successfully!" -ForegroundColor Green
        }
    }
}
