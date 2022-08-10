# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

$ValidateMitigationScriptBlock = {
    param(
        [Object]$Arguments
    )

    $SiteVDirLocation = $Arguments.SiteVDirLocation
    $IpRangesForFiltering = $Arguments.IpRangesForFiltering

    $results = @{
        IsEPVerified            = $false
        IsEPOff                 = $false
        IsWindowsFeatureInstalled = $false
        IsWindowsFeatureVerified = $false
        AreIPRulesVerified      = $false
        IsDefaultFilterVerified = $false
        IsDefaultFilterDeny     = $false
        RulesNotFound           = @()
        ErrorContext            = $null
    }

    function Get-LocalIpAddresses {
        $ips = @()
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

    # Create ip allow list from user provided ip subnets
    function VerifyIPRangeAllowList {
        param (
            [Parameter(Mandatory = $true)]
            [string]$SiteVDirLocation,
            [Parameter(Mandatory = $true)]
            [object[]]$IpFilteringRules,
            [Parameter(Mandatory = $true)]
            [hashtable]$results
        )
        
        $results.IsWindowsFeatureInstalled = (Get-WindowsFeature -Name "Web-IP-Security").InstallState -eq "Installed"
        $results.IsWindowsFeatureVerified = $true

        if (-not $results.IsWindowsFeatureInstalled) {
            return
        }

        $Filter = 'system.webServer/security/ipSecurity'
        $IISPath = 'IIS:\'

        $ExistingRules = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name collection

        foreach ($IpFilteringRule in $IpFilteringRules) {
            $ExistingIPSubnetRule = $ExistingRules | Where-Object { $_.ipAddress -eq $IpFilteringRule.IP -and ($_.subnetMask -eq $IpFilteringRule.SubnetMask -or $IpFilteringRule.Type -eq "Single IP") }
            if ($null -eq $ExistingIPSubnetRule) {
                if ($IpFilteringRule.Type -eq "Single IP") {
                    $IpString = $IpFilteringRule.IP
                } else {
                    $IpString = ("{0}/{1}" -f $IpFilteringRule.IP, $IpFilteringRule.SubnetMask)
                }
                $results.RulesNotFound += $IpString
            }
        }

        $results.AreIPRulesVerified = $true

        $results.IsDefaultFilterDeny = -not ((Get-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted").Value)
        $results.IsDefaultFilterVerified = $true
    }

    try {
        $EPState = GetEPState -SiteVDirLocation $SiteVDirLocation

        if ($EPState -eq "None") {
            $results.IsEPOff = $true
        } else {
            $results.IsEPOff = $false
        }

        $results.IsEPVerified = $true

        if ($null -ne $IpRangesForFiltering) {
            $localIPs = Get-LocalIpAddresses

            $localIPs | ForEach-Object {
                $IpRangesForFiltering += @{Type="Single IP"; IP=$_; Allowed=$true }
            }

            VerifyIPRangeAllowList -SiteVDirLocation $SiteVDirLocation -IpFilteringRules $IpRangesForFiltering -results $results
        }
    } catch {
        $results.ErrorContext = $_
    }

    return $results
}

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

function Invoke-ValidateMitigation {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ExchangeServers,
        [Parameter(Mandatory = $false)]
        $ipRangeAllowListRules,
        [Parameter(Mandatory = $true)]
        [string]$Site,
        [Parameter(Mandatory = $true)]
        [string]$VDir
    )

    begin {
        $FailedServersEP = New-Object 'System.Collections.Generic.List[string]'
        $FailedServersFilter = New-Object 'System.Collections.Generic.List[string]'

        $UnMitigatedServersEP = New-Object 'System.Collections.Generic.List[string]'
        $UnMitigatedServersFilter = New-Object 'System.Collections.Generic.List[string]'

        $progressParams = @{
            Activity        = "Verifying Mitigations"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        $ShouldVerifyFilter = ($null -ne $ipRangeAllowListRules)

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {
        $SiteVDirLocation = $Site
        if ($VDir -ne '') {
            $SiteVDirLocation += '/' + $VDir
        }

        $scriptblockArgs = [PSCustomObject]@{
            SiteVDirLocation     = $SiteVDirLocation
            IpRangesForFiltering = $ipRangeAllowListRules
        }

        $counter = 0
        $totalCount = $ExchangeServers.Count
        foreach ($Server in $ExchangeServers) {
            $baseStatus = "Processing: $Server -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Validating rules"
            Write-Progress @progressParams
            $counter ++;

            Write-Verbose ("Calling Invoke-ScriptBlockHandler on Server {0} with arguments SiteVDirLocation: {1}, ipRangeAllowListRules: list of length" -f $Server, $SiteVDirLocation, $ipRangeAllowListRules.Length.ToString())
            Write-Host ("Validating state of Extended protection flag on Server {0}" -f $Server)
            $resultsInvoke = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock $ValidateMitigationScriptBlock -ArgumentList $scriptblockArgs

            if ($resultsInvoke.IsEPOff) {
                Write-Host ("Expected: The state of Extended protection flag is None")
            } elseif ($resultsInvoke.IsEPVerified) {
                Write-Host ("Unexpected: The state of Extended protection flag is not set to None") -ForegroundColor Red
                $UnMitigatedServersEP += $Server
            } else {
                Write-Host ("Unknown: Script failed to get state of Extended protection flag with Inner Exception") -ForegroundColor Red
                Write-HostErrorInformation $results.ErrorContext
                $FailedServersEP += $Server
                $FailedServersFilter += $Server
                continue
            }

            if (-not $ShouldVerifyFilter) {
                continue
            }

            Write-Host ("Validating IP restrictions on Server {0}" -f $Server)
            $IsFilterUnMitigated = $false

            if (-not $resultsInvoke.IsWindowsFeatureVerified) {
                Write-Host ("Unknown: Script failed to verify if the Windows feature Web-IP-Security is present with Inner Exception") -ForegroundColor Red
                Write-HostErrorInformation $results.ErrorContext
                $FailedServersFilter += $Server
                continue
            } elseif (-not $resultsInvoke.IsWindowsFeatureInstalled) {
                Write-Host ("Unexpected: Windows feature Web-IP-Security is not present on the server") -ForegroundColor Red
                $IsFilterUnMitigated = $true
            } else {
                Write-Host ("Expected: Successfully verified that the Windows feature Web-IP-Security is present on the server")
                if (-not $resultsInvoke.AreIPRulesVerified) {
                    Write-Host ("Unknown: Script failed to verify IP Filtering Rules with Inner Exception") -ForegroundColor Red
                    Write-HostErrorInformation $results.ErrorContext
                    $FailedServersFilter += $Server
                    continue
                } elseif ($null -ne $resultsInvoke.RulesNotFound -and $resultsInvoke.RulesNotFound.Length -gt 0) {
                    Write-Host ("Unexpected: Some or all the rules present in the file specified aren't applied") -ForegroundColor Red
                    Write-Verbose ("Following Rules weren't found: {0}" -f (GetCommaSaperatedString -list $resultsInvoke.RulesNotFound))
                    $IsFilterUnMitigated = $true
                } else {
                    Write-Host ("Expected: Successfully verified all the IP filtering rules")
                }

                if ($resultsInvoke.IsDefaultFilterDeny) {
                    Write-Host ("Expected: The default IP Filtering rule is set to deny")
                } elseif ($resultsInvoke.IsDefaultFilterVerified) {
                    Write-Host ("Unexpected: The default IP Filtering rule is not set to deny") -ForegroundColor Red
                    $IsFilterUnMitigated = $true
                } else {
                    Write-Host ("Unknown: Script failed to get the default IP Filtering rule with Inner Exception") -ForegroundColor Red
                    Write-HostErrorInformation $results.ErrorContext
                    $FailedServersFilter += $Server
                    continue
                }
            }

            if ($IsFilterUnMitigated) {
                $UnMitigatedServersFilter += $Server
            }
        }
    } end {
        if ($UnMitigatedServersEP.Length -gt 0) {
            Write-Host ("Extended Protection on the following servers are not set to expected values: {0}" -f [string]::Join(", ", $UnMitigatedServersEP)) -ForegroundColor Red
        }

        if ($UnMitigatedServersFilter.Length -gt 0) {
            Write-Host ("IP Filtering Rules or Default IP rule on the following servers is not as expected: {0}" -f [string]::Join(", ", $UnMitigatedServersFilter)) -ForegroundColor Red
        }

        if ($FailedServersEP.Length -gt 0) {
            Write-Host ("Unable to verify Extended Protection on the following servers: {0}" -f [string]::Join(", ", $FailedServersEP)) -ForegroundColor Red
        }

        if ($FailedServersFilter.Length -gt 0) {
            Write-Host ("Unable to verify IP Filtering Rules on the following servers: {0}" -f [string]::Join(", ", $FailedServersFilter)) -ForegroundColor Red
        }
    }
}
