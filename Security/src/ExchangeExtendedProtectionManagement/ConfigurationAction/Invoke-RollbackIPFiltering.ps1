# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

function Invoke-RollbackIPFiltering {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ExchangeServers,
        [Parameter(Mandatory = $true)]
        [string[]]$SiteVDirLocations
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $FailedServers = @{}

        $progressParams = @{
            Activity        = "Rolling back IP filtering Rules"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        $RollbackIPFiltering = {
            param(
                [Object]$Arguments
            )

            $SiteVDirLocations = $Arguments.SiteVDirLocations
            $WhatIf = $Arguments.PassedWhatIf
            $Filter = 'system.webServer/security/ipSecurity'
            $FilterEP = 'system.WebServer/security/authentication/windowsAuthentication'
            $IISPath = 'IIS:\'

            $results = @{}

            function BackupCurrentIPFilteringRules {
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$BackupPath,
                    [Parameter(Mandatory = $true)]
                    [string]$Filter,
                    [Parameter(Mandatory = $true)]
                    [string]$IISPath,
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation,
                    [Parameter(Mandatory = $false)]
                    [System.Collections.Generic.List[object]]$ExistingRules
                )

                $DefaultForUnspecifiedIPs = Get-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted"
                if ($null -eq $ExistingRules) {
                    $ExistingRules = New-Object 'System.Collections.Generic.List[object]'
                }

                $BackupFilteringConfiguration = @{Rules=$ExistingRules; DefaultForUnspecifiedIPs=$DefaultForUnspecifiedIPs }
                if (-not $WhatIf) {
                    $BackupFilteringConfiguration |  ConvertTo-Json -Depth 2 | Out-File $BackupPath
                }

                return $true
            }

            function RestoreOriginalIPFilteringRules {
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$Filter,
                    [Parameter(Mandatory = $true)]
                    [string]$IISPath,
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation,
                    [Parameter(Mandatory = $false)]
                    [object[]]$OriginalIpFilteringRules,
                    [Parameter(Mandatory = $true)]
                    [object]$DefaultForUnspecifiedIPs
                )

                Clear-WebConfiguration -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -ErrorAction Stop -WhatIf:$WhatIf
                $RulesToBeAdded = New-Object 'System.Collections.Generic.List[object]'
                foreach ($IpFilteringRule in $OriginalIpFilteringRules) {
                    $RulesToBeAdded += @{ipAddress=$IpFilteringRule.ipAddress; subnetMask=$IpFilteringRule.subnetMask; domainName=$IpFilteringRule.domainName; allowed=$IpFilteringRule.allowed; }
                }
                Set-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted" -Value $DefaultForUnspecifiedIPs.Value -WhatIf:$WhatIf
                if ($OriginalIpFilteringRules.Length -gt 0) {
                    Add-WebConfigurationProperty  -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "." -Value $RulesToBeAdded -ErrorAction Stop -WhatIf:$WhatIf
                }

                return $true
            }

            function TurnONExtendedProtection {
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$Filter,
                    [Parameter(Mandatory = $true)]
                    [string]$IISPath,
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation
                )
                $ExtendedProtection = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -Name "extendedProtection.tokenChecking"
                if ($ExtendedProtection -ne "Require") {
                    Set-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "extendedProtection.tokenChecking" -Value "Require"
                }
            }

            foreach ($SiteVDirLocation in $SiteVDirLocations) {
                $state = @{
                    TurnOnEPSuccessful      = $false
                    RestoreFileExists       = $false
                    BackUpPath              = $null
                    BackupCurrentSuccessful = $false
                    RestorePath             = $null
                    RestoreSuccessful       = $false
                    ErrorContext            = $null
                }
                try {
                    $state.RestorePath = (Get-ChildItem "$($env:WINDIR)\System32\inetSrv\config\" -Filter ("*IpFilteringRules_"+  $SiteVDirLocation.Replace('/', '-') + "*.bak") | Sort-Object CreationTime | Select-Object -First 1).FullName
                    if ($null -eq $state.RestorePath) {
                        throw "Invalid operation. No backup file exists at path $($env:WINDIR)\System32\inetSrv\config\"
                    }
                    $state.RestoreFileExists = $true

                    TurnONExtendedProtection -Filter $FilterEP -IISPath $IISPath -SiteVDirLocation $SiteVDirLocation
                    $state.TurnOnEPSuccessful = $true

                    $state.BackUpPath = "$($env:WINDIR)\System32\inetSrv\config\IpFilteringRules_" + $SiteVDirLocation.Replace('/', '-') + "_$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak"
                    $ExistingRules = @(Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -Name collection)
                    $state.BackupCurrentSuccessful = BackupCurrentIPFilteringRules -BackupPath $state.BackUpPath -Filter $Filter -IISPath $IISPath -SiteVDirLocation $SiteVDirLocation -ExistingRules $ExistingRules

                    $originalIpFilteringConfigurations = (Get-Content $state.RestorePath | Out-String | ConvertFrom-Json)
                    $state.RestoreSuccessful = RestoreOriginalIPFilteringRules -OriginalIpFilteringRules ($originalIpFilteringConfigurations.Rules) -DefaultForUnspecifiedIPs ($originalIpFilteringConfigurations.DefaultForUnspecifiedIPs) -Filter $Filter -IISPath $IISPath -SiteVDirLocation $SiteVDirLocation
                } catch {
                    $state.ErrorContext = $_
                }

                $results[$SiteVDirLocation] = $state
            }

            return $results
        }
    } process {
        $ScriptBlockArgs = [PSCustomObject]@{
            SiteVDirLocations = $SiteVDirLocations
            PassedWhatIf      = $WhatIfPreference
        }

        $exchangeServersProcessed = 0
        $totalExchangeServers = $ExchangeServers.Count

        $SiteVDirLocations | ForEach-Object {
            $FailedServers[$_] = New-Object 'System.Collections.Generic.List[string]'
        }

        foreach ($Server in $ExchangeServers) {
            $baseStatus = "Processing: $($Server.Name) -"
            $progressParams.PercentComplete = ($exchangeServersProcessed / $totalExchangeServers * 100)
            $progressParams.Status = "$baseStatus Rolling back rules"
            Write-Progress @progressParams
            $exchangeServersProcessed++

            Write-Verbose ("Calling Invoke-ScriptBlockHandler on Server {0} with Arguments Site: {1}, VDir: {2}" -f $Server.Name, $Site, $VDir)
            Write-Verbose ("Restoring previous state for Server {0}" -f $Server.Name)
            $resultsInvoke = Invoke-ScriptBlockHandler -ComputerName $Server.FQDN -ScriptBlock $RollbackIPFiltering -ArgumentList $ScriptBlockArgs

            if ($null -eq $resultsInvoke) {
                $line = "Server Unreachable: Unable to rollback IP filtering rules on server $($Server.Name)."
                Write-Verbose $line
                Write-Warning $line
                $SiteVDirLocations | ForEach-Object { $FailedServers[$_].Add($Server.Name) }
                continue
            }

            foreach ($SiteVDirLocation in $SiteVDirLocations) {
                $Failed = $false
                $state = $resultsInvoke[$SiteVDirLocation]
                if ($state.RestoreFileExists) {
                    if ($state.TurnOnEPSuccessful) {
                        Write-Host "Turned on Extended Protection on server $($Server.Name) for VDir $SiteVDirLocation"
                        if ($state.BackupCurrentSuccessful) {
                            Write-Verbose "Successfully backed up current configuration on server $($Server.Name) at $($state.BackUpPath) for VDir $SiteVDirLocation"
                            if ($state.RestoreSuccessful) {
                                Write-Host "Successfully rolled back IP filtering rules on server $($Server.Name) from $($state.RestorePath) for VDir $SiteVDirLocation"
                            } else {
                                Write-Host "Failed to rollback IP filtering rules on server $($Server.Name). Aborting rollback on the server $($Server.Name) for VDir $SiteVDirLocation. Inner Exception:" -ForegroundColor Red
                                Write-HostErrorInformation $state.ErrorContext
                                $Failed = $true
                            }
                        } else {
                            Write-Host "Failed to backup the current configuration on server $($Server.Name). Aborting rollback on the server $($Server.Name) for VDir $SiteVDirLocation. Inner Exception:" -ForegroundColor Red
                            Write-HostErrorInformation $state.ErrorContext
                            $Failed = $true
                        }
                    } else {
                        Write-Host "Failed to turn on Extended Protection on server $($Server.Name). Aborting rollback on the server $($Server.Name) for VDir $SiteVDirLocation. Inner Exception:" -ForegroundColor Red
                        Write-HostErrorInformation $state.ErrorContext
                        $Failed = $true
                    }
                } else {
                    Write-Host "No restore file exists on server $($Server.Name). Aborting rollback on the server $($Server.Name) for VDir $SiteVDirLocation." -ForegroundColor Red
                    $Failed = $true
                }

                if ($Failed) {
                    $FailedServers[$SiteVDirLocation] += $Server.Name
                }
            }
        }
    } end {
        foreach ($SiteVDirLocation in $SiteVDirLocations) {
            if ($FailedServers[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("Unable to rollback for VDir $SiteVDirLocation on the following servers: {0}" -f [string]::Join(", ", $FailedServers[$SiteVDirLocation])) -ForegroundColor Red
            }
        }
    }
}
