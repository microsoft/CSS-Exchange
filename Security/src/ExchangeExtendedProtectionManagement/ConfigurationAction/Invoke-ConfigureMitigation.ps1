# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

function Invoke-ConfigureMitigation {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ExchangeServers,
        [Parameter(Mandatory = $false)]
        [object[]]$ipRangeAllowListRules,
        [Parameter(Mandatory = $true)]
        [string]$Site,
        [Parameter(Mandatory = $true)]
        [string]$VDir
    )

    begin {
        $FailedServersEP = New-Object 'System.Collections.Generic.List[string]'
        $FailedServersFilter = New-Object 'System.Collections.Generic.List[string]'

        $progressParams = @{
            Activity        = "Turning Off EP and applying IP filtering Rules"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        $ShouldConfigureFilter = ($null -ne $ipRangeAllowListRules)

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $ConfigureMitigation = {
            param(
                [Object]$Arguments
            )

            $SiteVDirLocation = $Arguments.SiteVDirLocation
            $IpRangesForFiltering = $Arguments.IpRangesForFiltering
            $Filter = 'system.webServer/security/ipSecurity'
            $IISPath = 'IIS:\'
            $ExistingRules = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name collection

            $results = @{
                IsTurnOffEPSuccessful      = $false
                IsWindowsFeatureInstalled  = $false
                IsGetLocalIPSuccessful     = $false
                IsBackUpSuccessful         = $false
                IsCreateIPRulesSuccessful  = $false
                IsSetDefaultRuleSuccessful = $false
                ErrorContext               = $null
                IPsNotAdded                = New-Object 'System.Collections.Generic.List[string]'
                LocalIPs                   = New-Object 'System.Collections.Generic.List[string]'
            }

            function Backup-currentIpFilteringRules {
                param(
                    $BackupPath
                )

                $DefaultForUnspecifiedIPs = Get-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted"
                if ($null -eq $ExistingRules) {
                    $ExistingRules = New-Object 'System.Collections.Generic.List[object]'
                }

                $BackupFilteringConfiguration = @{Rules=$ExistingRules; DefaultForUnspecifiedIPs=$DefaultForUnspecifiedIPs }
                $BackupFilteringConfiguration |  ConvertTo-Json -Depth 2 | Out-File $BackupPath
                return $true
            }

            function Get-LocalIpAddresses {
                $ips = New-Object 'System.Collections.Generic.List[string]'
                $interfaces = Get-NetIPAddress -ErrorAction Stop
                foreach ($interface in $interfaces) {
                    if ($interface.AddressState -eq 'Preferred') {
                        $ips += $interface.IPAddress
                    }
                }

                return $ips
            }

            # Set EP to None
            function TurnOffEP {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation
                )

                $ExtendedProtection = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name tokenChecking

                if ($ExtendedProtection -ne "None") {
                    Set-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name tokenChecking -Value "None"
                }

                return $true
            }

            # Create ip allow list from user provided ip subnets
            function CreateIPRangeAllowList {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation,
                    [Parameter(Mandatory = $true)]
                    [object[]]$IpFilteringRules,
                    [Parameter(Mandatory = $true)]
                    [hashtable] $results
                )

                $backupPath = "$($env:WINDIR)\System32\inetsrv\config\IpFilteringRules_" + $SiteVDirLocation.Replace('/', '-') + "_$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak"
                $results.IsBackUpSuccessful = Backup-currentIpFilteringRules -BackupPath $backupPath

                $RulesToBeAdded = New-Object 'System.Collections.Generic.List[object]'

                foreach ($IpFilteringRule in $IpFilteringRules) {
                    $ExistingIPSubnetRule = $ExistingRules | Where-Object { $_.ipAddress -eq $IpFilteringRule.IP -and ($_.subnetMask -eq $IpFilteringRule.SubnetMask -or $IpFilteringRule.Type -eq "Single IP") }

                    if ($null -eq $ExistingIPSubnetRule) {
                        if ($IpFilteringRule.Type -eq "Single IP") {
                            $RulesToBeAdded += @{ipAddress=$IpFilteringRule.IP; allowed=$IpFilteringRule.Allowed; }
                        } else {
                            $RulesToBeAdded += @{ipAddress=$IpFilteringRule.IP; subnetMask=$IpFilteringRule.SubnetMask; allowed=$IpFilteringRule.Allowed; }
                        }
                    } else {
                        if ($ExistingIPSubnetRule.allowed -ne $IpFilteringRule.Allowed) {
                            if ($IpFilteringRule.Type -eq "Single IP") {
                                $IpString = $IpFilteringRule.IP
                            } else {
                                $IpString = ("{0}/{1}" -f $IpFilteringRule.IP, $IpFilteringRule.SubnetMask)
                            }

                            $results.IPsNotAdded += $IpString
                        }
                    }
                }

                Add-WebConfigurationProperty  -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "." -Value $RulesToBeAdded -ErrorAction Stop

                $results.IsCreateIPRulesSuccessful = $true

                # Setting default to deny
                Set-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted" -Value $false
                $results.IsSetDefaultRuleSuccessful = $true
            }

            try {
                $results.IsTurnOffEPSuccessful = TurnOffEP -SiteVDirLocation $SiteVDirLocation

                if ($null -ne $IpRangesForFiltering) {
                    try {
                        $baseError = "Installation of IP and Domain filtering Module failed."
                        $InstallResult = Install-WindowsFeature Web1-IP-Security -ErrorAction Stop
                        if (-not $InstallResult.Success) {
                            throw $baseError
                        }
                    } catch {
                        throw "$baseError Inner exception: $_"
                    }

                    $results.IsWindowsFeatureInstalled = $true

                    $localIPs = Get-LocalIpAddresses
                    $results.IsGetLocalIPSuccessful = $true

                    foreach ($localIP in $localIPs) {
                        if ($null -eq ($IpRangesForFiltering | Where-Object { $_.Type -eq "Single IP" -and $_.IP -eq $localIP })) {
                            $IpRangesForFiltering += @{Type="Single IP"; IP=$localIP; Allowed=$true }
                        }
                    }

                    $results.LocalIPs = $localIPs
                    CreateIPRangeAllowList -SiteVDirLocation $SiteVDirLocation -IpFilteringRules $IpRangesForFiltering -results $results
                }
            } catch {
                $results.ErrorContext = $_
            }

            return $results
        }

        function GetCommaSaperatedString {
            param(
                [Parameter(Mandatory = $true)]
                [object[]]$list
            )

            $string = ""
            foreach ($element in $list) {
                $string += ($element.ToString() + ", ")
            }

            return $string.Trim(", ")
        }
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

        if ($null -eq $ipRangeAllowListRules) {
            $ipRangeAllowListString = "null"
        } else {
            $ipRangeAllowListString = [string]::Join(", ", $ipRangeAllowListRules)
        }

        foreach ($Server in $ExchangeServers) {
            $baseStatus = "Processing: $Server -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Applying rules"
            Write-Progress @progressParams
            $counter ++;

            Write-Verbose ("Calling Invoke-ScriptBlockHandler on Server {0} with arguments SiteVDirLocation: {1}, ipRangeAllowListRules: {2}" -f $Server, $SiteVDirLocation, $ipRangeAllowListString)
            $resultsInvoke = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock $ConfigureMitigation -ArgumentList $scriptblockArgs

            Write-Host ("Setting Extended protection flag to None on Server {0}" -f $Server)
            if ($resultsInvoke.IsTurnOffEPSuccessful) {
                Write-Host ("Successfully turned Off Extended Protection")
            } else {
                Write-Host ("Script failed to Turn Off Extended protection with the Inner Exception:") -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $FailedServersEP += $Server
                $FailedServersFilter += $Server
                continue
            }

            if (-not $ShouldConfigureFilter) {
                continue
            }

            Write-Host ("Adding IP Restriction rules on Server {0}" -f $Server)
            if ($resultsInvoke.IsWindowsFeatureInstalled) {
                Write-Host ("Successfully installed windows feature - Web-IP-Security")
            } else {
                Write-Host ("Script failed to install windows feature - Web-IP-Security with the Inner Exception:") -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $FailedServersFilter += $Server
                continue
            }

            if ($resultsInvoke.IsGetLocalIPSuccessful) {
                Write-Host ("Successfully retrieved local IPs for the server")
                if ($null -ne $resultsInvoke.LocalIPs -and $resultsInvoke.LocalIPs.Length -gt 0) {
                    Write-Verbose ("Local IPs detected for this server: {0}" -f (GetCommaSaperatedString -list $resultsInvoke.LocalIPs))
                } else {
                    Write-Verbose ("No Local IPs detected for this server")
                }
            } else {
                Write-Host ("Script failed to retrieve local IPs for the server with the Inner Exception:") -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $FailedServersFilter += $Server
                continue
            }

            if ($resultsInvoke.IsBackUpSuccessful) {
                Write-Host ("Successfully backed up IP filtering allow list")
            } else {
                Write-Host ("Script failed to backup IP filtering allow list with the Inner Exception:") -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $FailedServersFilter += $Server
                continue
            }

            if ($resultsInvoke.IsCreateIPRulesSuccessful) {
                Write-Host ("Successfully updated IP filtering allow list")
                if ($resultsInvoke.IPsNotAdded.Length -gt 0) {
                    $line = ("Few IPs were not added to the allow list as deny rules for these IPs were already present.")
                    Write-Warning ($line + "Check logs for further details.")
                    Write-Verbose $line
                    Write-Verbose (GetCommaSaperatedString -list $resultsInvoke.IPsNotAdded)
                }
            } else {
                Write-Host ("Script failed to update IP filtering allow list with the Inner Exception:") -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $FailedServersFilter += $Server
                continue
            }

            if ($resultsInvoke.IsSetDefaultRuleSuccessful) {
                Write-Host ("Successfully set the default IP filtering rule to deny")
            } else {
                Write-Host ("Script failed to set the default IP filtering rule to deny with the Inner Exception:") -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $FailedServersFilter += $Server
                continue
            }
        }
    } end {
        if ($FailedServersEP.Length -gt 0) {
            Write-Host ("Unable to Turn Off Extended Protection on the following servers: {0}" -f [string]::Join(", ", $FailedServersEP)) -ForegroundColor Red
        }

        if ($FailedServersFilter.Length -gt 0) {
            Write-Host ("Unable to create IP Filtering Rules on the following servers: {0}" -f [string]::Join(", ", $FailedServersFilter)) -ForegroundColor Red
        }
    }
}
