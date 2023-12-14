# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

function Invoke-DisableExtendedProtection {
    [CmdletBinding()]
    param(
        [string[]]$ExchangeServers
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $counter = 0
        $totalCount = $ExchangeServers.Count
        $failedServers = New-Object 'System.Collections.Generic.List[string]'
        $updatedServers = New-Object 'System.Collections.Generic.List[string]'
        $progressParams = @{
            Id              = 1
            Activity        = "Disabling Extended Protection"
            Status          = [string]::Empty
            PercentComplete = 0
        }
    }
    process {
        <#
            We need to loop through each of the servers and set extended protection to None for each virtual directory for exchange that we did set.
            This list of virtual directories for exchange will be managed within Get-ExtendedProtectionConfiguration.
            To avoid a second list here of the names of vDirs, we will call Get-ExtendedProtectionConfiguration for each server prior to setting EP to none.
            This will result in a double call to that server, but rather do that then have a double list of vDirs that we want to manage.
        #>

        foreach ($server in $ExchangeServers) {
            $counter++
            $baseStatus = "Processing: $($server) -"
            $progressParams.Status = "$baseStatus Gathering Information"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            Write-Progress @progressParams

            $serverExtendedProtection = Get-ExtendedProtectionConfiguration -ComputerName $server

            if (-not ($serverExtendedProtection.ServerConnected)) {
                Write-Warning "$($server): Server not online. Unable to execute remotely."
                $failedServers.Add($server)
                continue
            }

            if ($serverExtendedProtection.ExtendedProtectionConfiguration.Count -eq 0) {
                Write-Warning "$($server): Server wasn't able to collect Extended Protection configuration."
                $failedServers.Add($server)
                continue
            }

            $commandParameter = [PSCustomObject]@{
                TokenChecking = @{}
            }

            foreach ($virtualDirectory in $serverExtendedProtection.ExtendedProtectionConfiguration) {
                Write-Verbose "$($server): Virtual Directory Name: $($virtualDirectory.VirtualDirectoryName) Current Set Extended Protection: $($virtualDirectory.ExtendedProtection)"
                $commandParameter.TokenChecking.Add($virtualDirectory.VirtualDirectoryName, "None")
            }

            $progressParams.Status = "$baseStatus Executing Actions on Server"
            Write-Progress @progressParams

            $results = Invoke-ScriptBlockHandler -ComputerName $server -ScriptBlock {
                param(
                    [object]$Commands,
                    [bool]$PassedWhatIf
                )
                $internalCounter = 0
                $internalTotalCommands = $Commands.TokenChecking.Count
                $internalProgressParams = @{
                    ParentId        = 1
                    Activity        = "Executing Actions on $env:ComputerName"
                    PercentComplete = 0
                }
                Write-Progress @internalProgressParams
                $errorContext = New-Object 'System.Collections.Generic.List[object]'
                $setAllTokenChecking = $true
                foreach ($siteKey in $Commands.TokenChecking.Keys) {
                    $internalCounter++
                    $internalProgressParams.Status = "Setting TokenChecking for $siteKey"
                    $internalProgressParams.PercentComplete = ($internalCounter / $internalTotalCommands * 100)
                    Write-Progress @internalProgressParams

                    try {
                        $params = @{
                            Filter      = "system.WebServer/security/authentication/windowsAuthentication"
                            Name        = "extendedProtection.tokenChecking"
                            Value       = $Commands.TokenChecking[$siteKey]
                            Location    = $siteKey
                            PSPath      = "IIS:\"
                            ErrorAction = "Stop"
                            WhatIf      = $PassedWhatIf
                        }
                        Set-WebConfigurationProperty @params
                    } catch {
                        Write-Host "$($env:COMPUTERNAME): Failed to set tokenChecking for $siteKey with the value $($Commands.TokenChecking[$siteKey]). Inner Exception $_"
                        $setAllTokenChecking = $false
                        $errorContext.Add($_)
                    }
                }

                Write-Progress @internalProgressParams -Completed
                return [PSCustomObject]@{
                    SetAllTokenChecking = $setAllTokenChecking
                    ErrorContext        = $errorContext
                }
            } -ArgumentList $commandParameter, $WhatIfPreference

            Write-Verbose "$($server): SetAllTokenChecking: $($results.SetAllTokenChecking)"

            if ($results.SetAllTokenChecking) {
                Write-Host "Successfully updated applicationHost.config"
                $updatedServers.Add($server)
            } else {
                Write-Warning "$($server): Failed to set Extended Protection to None."
                $failedServers.Add($server)
            }
        }
    }
    end {
        Write-Progress @progressParams -Completed
        Write-Host

        if ($failedServers.Count -gt 0) {
            Write-Warning "Failed to disable Extended Protection: $([string]::Join(", ", $failedServers))"
        }

        if ($updatedServers.Count -gt 0) {
            Write-Host "Successfully disabled Extended Protection: $([string]::Join(",", $updatedServers))"
        }
    }
}
