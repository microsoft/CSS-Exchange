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

        function GetCommaSaperatedString {
            param(
                $list
            )

            $string = ""
            foreach ($element in $list) {
                $string += ($element.ToString() + ", ")
            }

            return $string.Trim(", ")
        }

        $ValidateMitigationScriptBlock = {
            param(
                [Object]$Arguments
            )

            $SiteVDirLocations = $Arguments.SiteVDirLocations
            $IpRangesForFiltering = $Arguments.IpRangesForFiltering

            $results = @{}

            function Get-LocalIpAddresses {
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
            function GetEPState {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation
                )

                $Filter = 'system.webServer/security/authentication/windowsAuthentication/extendedProtection'

                $ExtendedProtection = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name tokenChecking
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
                    [hashtable]$state
                )

                $state.IsWindowsFeatureInstalled = (Get-WindowsFeature -Name "Web-IP-Security").InstallState -eq "Installed"
                $state.IsWindowsFeatureVerified = $true

                if (-not $state.IsWindowsFeatureInstalled) {
                    return
                }

                $Filter = 'system.webServer/security/ipSecurity'
                $IISPath = 'IIS:\'

                $ExistingRules = @(Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name collection)

                foreach ($IpFilteringRule in $IpFilteringRules) {
                    $ExistingIPSubnetRule = $ExistingRules | Where-Object { $_.ipAddress -eq $IpFilteringRule.IP -and ($_.subnetMask -eq $IpFilteringRule.SubnetMask -or $IpFilteringRule.Type -eq "Single IP") -and $_.allowed -eq $IpFilteringRule.Allowed }
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

                    $EPState = GetEPState -SiteVDirLocation $SiteVDirLocation
                    if ($EPState -eq "None") {
                        $state.IsEPOff = $true
                    } else {
                        $state.IsEPOff = $false
                    }

                    $state.IsEPVerified = $true

                    if ($null -ne $IpRangesForFiltering) {
                        $localIPs = Get-LocalIpAddresses

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
        $scriptblockArgs = [PSCustomObject]@{
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
            $counter ++;

            Write-Verbose ("Calling Invoke-ScriptBlockHandler on Server {0} with arguments SiteVDirLocations: {1}, ipRangeAllowListRules: {2}" -f $Server, [string]::Join(", ", $SiteVDirLocations), $ipRangeAllowListString)
            $resultsInvoke = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock $ValidateMitigationScriptBlock -ArgumentList $scriptblockArgs

            if ($null -eq $resultsInvoke) {
                $line = "Failed to validate IP filtering rules on server $($Server), because we weren't able to reach it."
                Write-Verbose $line
                Write-Warning $line
                $SiteVDirLocations | ForEach-Object { $FailedServersEP[$_].Add($Server) }
                $SiteVDirLocations | ForEach-Object { $FailedServersFilter[$_].Add($Server) }
                continue
            }

            foreach ($SiteVDirLocation in $SiteVDirLocations) {
                $state = $resultsInvoke[$SiteVDirLocation]

                if ($state.IsEPOff) {
                    Write-Verbose ("Expected: The state of Extended protection flag is None for Vdir $($SiteVDirLocation) on server $Server")
                } elseif ($state.IsEPVerified) {
                    Write-Host ("Unexpected: The state of Extended protection flag is not set to None for Vdir $($SiteVDirLocation) on server $Server") -ForegroundColor Red
                    $UnMitigatedServersEP[$SiteVDirLocation] += $Server
                } else {
                    Write-Host ("Unknown: Script failed to get state of Extended protection flag for Vdir $($SiteVDirLocation) with Inner Exception") -ForegroundColor Red
                    Write-HostErrorInformation $results.ErrorContext
                    $FailedServersEP[$SiteVDirLocation] += $Server
                    $FailedServersFilter[$SiteVDirLocation] += $Server
                    continue
                }

                $IsFilterUnMitigated = $false

                if (-not $state.IsWindowsFeatureVerified) {
                    Write-Host ("Unknown: Script failed to verify if the Windows feature Web-IP-Security is present for Vdir $($SiteVDirLocation) on server $Server with Inner Exception") -ForegroundColor Red
                    Write-HostErrorInformation $results.ErrorContext
                    $FailedServersFilter[$SiteVDirLocation] += $Server
                    continue
                } elseif (-not $state.IsWindowsFeatureInstalled) {
                    Write-Host ("Unexpected: Windows feature Web-IP-Security is not present on the server for Vdir $($SiteVDirLocation) on server $Server") -ForegroundColor Red
                    $IsFilterUnMitigated = $true
                } else {
                    Write-Verbose ("Expected: Successfully verified that the Windows feature Web-IP-Security is present on the server for Vdir $($SiteVDirLocation) on server $Server")
                    if (-not $state.AreIPRulesVerified) {
                        Write-Host ("Unknown: Script failed to verify IP Filtering Rules for Vdir $($SiteVDirLocation) on server $Server with Inner Exception") -ForegroundColor Red
                        Write-HostErrorInformation $results.ErrorContext
                        $FailedServersFilter[$SiteVDirLocation] += $Server
                        continue
                    } elseif ($null -ne $state.RulesNotFound -and $state.RulesNotFound.Length -gt 0) {
                        Write-Host ("Unexpected: Some or all the rules present in the file specified aren't applied for Vdir $($SiteVDirLocation) on server $Server") -ForegroundColor Red
                        Write-Verbose ("Following Rules weren't found: {0}" -f (GetCommaSaperatedString -list $state.RulesNotFound))
                        $IsFilterUnMitigated = $true
                    } else {
                        Write-Verbose ("Expected: Successfully verified all the IP filtering rules for Vdir $($SiteVDirLocation) on server $Server")
                    }

                    if ($state.IsDefaultFilterDeny) {
                        Write-Verbose ("Expected: The default IP Filtering rule is set to deny for Vdir $($SiteVDirLocation) on server $Server")
                    } elseif ($state.IsDefaultFilterVerified) {
                        Write-Host ("Unexpected: The default IP Filtering rule is not set to deny for Vdir $($SiteVDirLocation) on server $Server") -ForegroundColor Red
                        $IsFilterUnMitigated = $true
                    } else {
                        Write-Host ("Unknown: Script failed to get the default IP Filtering rule for Vdir $($SiteVDirLocation) on server $Server with Inner Exception") -ForegroundColor Red
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
                Write-Host ("IP Filtering Rules or Default IP rule on the following servers is not as expected for VDir {0}: {1}" -f $SiteVDirLocation, [string]::Join(", ", $UnMitigatedServersFilter[$SiteVDirLocation])) -ForegroundColor Red
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
