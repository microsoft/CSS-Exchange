# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-ExtendedProtectionConfiguration.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

function Invoke-ConfigureExtendedProtection {
    param(
        [object[]]$ExtendedProtectionConfigurations
    )

    begin {
        $offlineServers = New-Object System.Collections.Generic.List[string]
        $noChangesMadeServers = New-Object System.Collections.Generic.List[string]
        $noEpConfigurationServer = New-Object System.Collections.Generic.List[string]
        $iisConfigurationManagements = New-Object System.Collections.Generic.List[object]
        $counter = 0
        $totalCount = $ExtendedProtectionConfigurations.Count
        $progressParams = @{
            Id              = 1
            Activity        = "Configuring Extended Protection"
            Status          = [string]::Empty
            PercentComplete = 0
        }
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {
        foreach ($serverExtendedProtection in $ExtendedProtectionConfigurations) {
            $counter++
            # Check to make sure server is connected and valid information is provided.
            if (-not ($serverExtendedProtection.ServerConnected)) {
                Write-Warning "$($serverExtendedProtection.ComputerName): Server not online. Cannot get Extended Protection configuration settings."
                $offlineServers.Add($serverExtendedProtection.ComputerName)
                continue
            }

            if ($serverExtendedProtection.ExtendedProtectionConfiguration.Count -eq 0) {
                Write-Warning "$($serverExtendedProtection.ComputerName): Server wasn't able to collect Extended Protection configuration."
                $noEpConfigurationServer.Add($serverExtendedProtection.ComputerName)
                continue
            }

            # set the extended protection (TokenChecking) configuration to the expected and supported configuration if different
            # only Set SSLFlags option if we are not setting extended protection to None
            $actionList = New-Object System.Collections.Generic.List[object]
            $baseStatus = "Processing: $($serverExtendedProtection.ComputerName) -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Evaluating Extended Protection Settings"
            Write-Progress @progressParams

            foreach ($virtualDirectory in $serverExtendedProtection.ExtendedProtectionConfiguration) {
                Write-Verbose "$($serverExtendedProtection.ComputerName): Virtual Directory Name: $($virtualDirectory.VirtualDirectoryName) Current Set Extended Protection: $($virtualDirectory.ExtendedProtection) Expected Value $($virtualDirectory.ExpectedExtendedConfiguration)"
                Write-Verbose "$($serverExtendedProtection.ComputerName): Current Set SSL Flags: $($virtualDirectory.Configuration.SslSettings.Value) Expected SSL Flags: $($virtualDirectory.ExpectedSslFlags) Set Correctly: $($virtualDirectory.SslFlagsSetCorrectly)"
                if ($virtualDirectory.ExtendedProtection -ne $virtualDirectory.ExpectedExtendedConfiguration) {
                    $actionList.Add((New-IISConfigurationAction -Action ([PSCustomObject]@{
                                    Cmdlet     = "Set-WebConfigurationProperty"
                                    Parameters = @{
                                        Filter   = "system.WebServer/security/authentication/windowsAuthentication"
                                        Name     = "extendedProtection.tokenChecking"
                                        Value    = $virtualDirectory.ExpectedExtendedConfiguration
                                        PSPath   = "IIS:\"
                                        Location = $virtualDirectory.VirtualDirectoryName
                                    }
                                })))

                    if ($virtualDirectory.ExpectedExtendedConfiguration -ne "None" -and
                        $virtualDirectory.SslFlagsSetCorrectly -eq $false) {
                        $actionList.Add((New-IISConfigurationAction -Action ([PSCustomObject]@{
                                        Cmdlet     = "Set-WebConfigurationProperty"
                                        Parameters = @{
                                            Filter   = "system.WebServer/security/access"
                                            Name     = "sslFlags"
                                            Value    = $virtualDirectory.SslFlagsToSet
                                            PSPath   = "IIS:\"
                                            Location = $virtualDirectory.VirtualDirectoryName
                                        }
                                    })))
                    }
                }
            }

            if ($actionList.Count -gt 0) {
                $iisConfigurationManagements.Add([PSCustomObject]@{
                        ServerName     = $serverExtendedProtection.ComputerName
                        Actions        = $actionList
                        BackupFileName = "ConfigureExtendedProtection"
                    })
            } else {
                Write-Host "$($serverExtendedProtection.ComputerName): No changes made. Exchange build supports Extended Protection? $($serverExtendedProtection.SupportedVersionForExtendedProtection)"
                $noChangesMadeServers.Add($serverExtendedProtection.ComputerName)
            }
        }
    } end {
        Write-Progress @progressParams -Completed
        if ($iisConfigurationManagements.Count -gt 0) {
            Invoke-IISConfigurationManagerAction $iisConfigurationManagements -ConfigurationDescription "Configure Extended Protection"
        }
        Write-Host ""
        if ($offlineServers.Count -gt 0) {
            Write-Warning "Failed to enable Extended Protection on the following servers, because they were offline: $([string]::Join(", " ,$offlineServers))"
        }

        if ($noEpConfigurationServer.Count -gt 0) {
            Write-Warning "Failed to determine what actions to take on the following servers, because we couldn't retrieve the EP configuration: $([string]::Join(",", $noEpConfigurationServer))"
        }

        if ($noChangesMadeServers.Count -gt 0) {
            Write-Host "No changes were needed on the following servers: $([string]::Join(", " ,$noChangesMadeServers))"
        }
    }
}
