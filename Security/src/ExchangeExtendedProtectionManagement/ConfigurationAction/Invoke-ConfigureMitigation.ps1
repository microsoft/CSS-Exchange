# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

# Steps: TurnOffEP -> Install windows feature -> GetLocalIP -> backup configuration -> CreateAllowRules -> SetDefaultToDeny
$ConfigureMitigation = {
    param(
        [Object]$Arguments
    )

    $SiteVDirLocation = $Arguments.SiteVDirLocation
    $IpRangesForFiltering = $Arguments.IpRangesForFiltering

    $results = @{
        IsTurnOffEPSuccessful      = $false
        IsWindowsFeatureInstalled  = $false
        IsGetLocalIPSuccessful     = $false
        IsBackUpSuccessful         = $false
        IsCreateIPRulesSuccessful  = $false
        IsSetDefaultRuleSuccessful = $false
        ErrorContext               = $null
        IPsNotAdded                = @()
        LocalIPs                   = @()
    }

    function Backup-currentIpFilteringRules {
        param(
            $BackupPath
        )

        $Filter = 'system.webServer/security/ipSecurity'
        $IISPath = 'IIS:\'

        $ExistingRules = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name collection
        $DefaultForUnspecifiedIPs = Get-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted"
        $BackupFilteringConfiguration = @{Rules=$ExistingRules; DefaultForUnspecifiedIPs=$DefaultForUnspecifiedIPs }
        $BackupFilteringConfiguration |  ConvertTo-Json -Depth 2 | Out-File $BackupPath

        return $true
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
    function TurnOffEP {
        param (
            [Parameter(Mandatory = $true)]
            [string]$SiteVDirLocation
        )

        $Filter = 'system.webServer/security/authentication/windowsAuthentication/extendedProtection'
        $IISPath = 'IIS:\'

        $ExtendedProtection = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name tokenChecking

        if ($ExtendedProtection -ne "None") {
            Set-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name tokenChecking -Value "None"
        }
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

        $backupPath = "$($env:WINDIR)\System32\inetsrv\config\IpFilteringRules_" + $SiteVDirLocation.Replace('/','-') + "_$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak"

        Backup-currentIpFilteringRules -BackupPath $backupPath
        $results.IsBackUpSuccessful = $true

        $Filter = 'system.webServer/security/ipSecurity'
        $IISPath = 'IIS:\'

        $RulesToBeAdded = @()
        $IPsNotAdded = @()

        $ExistingRules = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name collection

        foreach ($IpFilteringRule in $IpFilteringRules) {
            $ExistingIPSubnetRule = $ExistingRules | Where-Object { $_.ipAddress -eq $IpFilteringRule.IP -and ($_.subnetMask -eq $IpFilteringRule.SubnetMask -or $IpFilteringRule.Type -eq "Single IP") }

            if ($null -eq $ExistingIPSubnetRule) {
                if ($IpFilteringRule.Type -eq "Single IP") {
                    $RulesToBeAdded += @{ipAddress=$IpFilteringRule.IP; allowed=$IpFilteringRule.Allowed; }
                } else {
                    $RulesToBeAdded += @{ipAddress=$IpFilteringRule.IP; subnetMask=$IpFilteringRule.SubnetMask; allowed=$IpFilteringRule.Allowed; }
                }
            } else {
                if ($IpFilteringRule.Type -eq "Single IP") {
                    $IpString = $IpFilteringRule.IP
                    # Write-Verbose ("Unable to add allow rule for ip address: {0} as an already existing rule exist for this." -f $IpFilteringRule.IP )
                } else {
                    $IpString = ("{0}/{1}" -f $IpFilteringRule.IP, $IpFilteringRule.SubnetMask)
                    # Write-Verbose ("Unable to add allow rule for ip subnet: {0}/{1} as an already existing rule exist for this." -f $IpFilteringRule.IP, $IpFilteringRule.SubnetMask )
                }

                $IPsNotAdded += $IpString
            }
        }

        Add-WebConfigurationProperty  -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "." -Value $RulesToBeAdded -ErrorAction Stop

        $results.IsCreateIPRulesSuccessful = $true

        # Setting default to deny
        Set-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted" -Value $false
        $results.IsSetDefaultRuleSuccessful = $true
        return $IPsNotAdded
    }

    try {
        TurnOffEP -SiteVDirLocation $SiteVDirLocation
        $results.IsTurnOffEPSuccessful = $true

        if ($null -ne $IpRangesForFiltering) {
            $installResult = Install-WindowsFeature Web-IP-Security
            if (-not $installResult) {
                throw ("Unable to install Windows feature Web-IP-Security which is required to add IP filtering rules to IIS.")
            }

            $results.IsWindowsFeatureInstalled = $true

            $localIPs = Get-LocalIpAddresses
            $results.IsGetLocalIPSuccessful = $true

            $localIPs | ForEach-Object {
                $IpRangesForFiltering += @{Type="Single IP"; IP=$_; SubnetMask=$null; Allowed=$true }
            }

            $results.LocalIPs = $localIPs
            $results.IPsNotAdded = CreateIPRangeAllowList -SiteVDirLocation $SiteVDirLocation -IpFilteringRules $IpRangesForFiltering -results $results
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
            $progressParams.Status = "$baseStatus Applying rules"
            Write-Progress @progressParams
            $counter ++;

            Write-Verbose ("Calling Invoke-ScriptBlockHandler on Server {0} with arguments SiteVDirLocation: {1}, ipRangeAllowListRules: {2}" -f $Server, $SiteVDirLocation, [string]::Join(", ", $ipRangeAllowListRules))
            Write-Host ("Applying Mitigations on Server {0}" -f $Server)
            $resultsInvoke = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock $ConfigureMitigation -ArgumentList $scriptblockArgs

            if ($resultsInvoke.IsTurnOffEPSuccessful) {
                Write-Host ("Successfully turned Off Extended Protection") -ForegroundColor Green
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

            if ($resultsInvoke.IsWindowsFeatureInstalled) {
                Write-Host ("Successfully installed windows feature - Web-IP-Security") -ForegroundColor Green
            } else {
                Write-Host ("Script failed to install windows feature - Web-IP-Security with the Inner Exception:") -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $FailedServersFilter += $Server
                continue
            }

            if ($resultsInvoke.IsGetLocalIPSuccessful) {
                Write-Host ("Successfully retrieved local IPs for the server") -ForegroundColor Green
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
                Write-Host ("Successfully backed up IP filtering allow list") -ForegroundColor Green
            } else {
                Write-Host ("Script failed to backup IP filtering allow list with the Inner Exception:") -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $FailedServersFilter += $Server
                continue
            }

            if ($resultsInvoke.IsCreateIPRulesSuccessful) {
                Write-Host ("Successfully updated IP filtering allow list") -ForegroundColor Green
                if ($resultsInvoke.IPsNotAdded.Length -gt 0) {
                    $line = ("We didn't add the below IPs to the allow list as there are already existing rules present.`n{0}" -f (GetCommaSaperatedString -list $resultsInvoke.IPsNotAdded))
                    Write-Warning $line
                    Write-Verbose $line
                }
            } else {
                Write-Host ("Script failed to update IP filtering allow list with the Inner Exception:") -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $FailedServersFilter += $Server
                continue
            }

            if ($resultsInvoke.IsSetDefaultRuleSuccessful) {
                Write-Host ("Successfully set the default IP filtering rule to deny") -ForegroundColor Green
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
