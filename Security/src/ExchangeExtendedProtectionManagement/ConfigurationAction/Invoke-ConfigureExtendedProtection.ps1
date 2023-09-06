# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-ExtendedProtectionConfiguration.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

function Invoke-ConfigureExtendedProtection {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [object[]]$ExtendedProtectionConfigurations
    )

    begin {
        $failedServers = New-Object 'System.Collections.Generic.List[string]'
        $noChangesMadeServers = New-Object 'System.Collections.Generic.List[string]'
        $updatedServers = New-Object 'System.Collections.Generic.List[string]'
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
                $line = "$($serverExtendedProtection.ComputerName): Server not online. Cannot get Extended Protection configuration settings."
                Write-Verbose $line
                Write-Warning $line
                $failedServers.Add($serverExtendedProtection.ComputerName)
                continue
            }

            if ($serverExtendedProtection.ExtendedProtectionConfiguration.Count -eq 0) {
                $line = "$($serverExtendedProtection.ComputerName): Server wasn't able to collect Extended Protection configuration."
                Write-Verbose $line
                Write-Warning $line
                continue
            }

            # set the extended protection (TokenChecking) configuration to the expected and supported configuration if different
            # only Set SSLFlags option if we are not setting extended protection to None
            $commandParameters = [PSCustomObject]@{
                TokenChecking = @{}
                SSLFlags      = @{}
            }

            $baseStatus = "Processing: $($serverExtendedProtection.ComputerName) -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Evaluating Extended Protection Settings"
            Write-Progress @progressParams

            foreach ($virtualDirectory in $serverExtendedProtection.ExtendedProtectionConfiguration) {
                Write-Verbose "$($serverExtendedProtection.ComputerName): Virtual Directory Name: $($virtualDirectory.VirtualDirectoryName) Current Set Extended Protection: $($virtualDirectory.ExtendedProtection) Expected Value $($virtualDirectory.ExpectedExtendedConfiguration)"
                Write-Verbose "$($serverExtendedProtection.ComputerName): Current Set SSL Flags: $($virtualDirectory.Configuration.SslSettings.Value) Expected SSL Flags: $($virtualDirectory.ExpectedSslFlags) Set Correctly: $($virtualDirectory.SslFlagsSetCorrectly)"
                if ($virtualDirectory.ExtendedProtection -ne $virtualDirectory.ExpectedExtendedConfiguration) {
                    $commandParameters.TokenChecking.Add($virtualDirectory.VirtualDirectoryName, $virtualDirectory.ExpectedExtendedConfiguration)

                    if ($virtualDirectory.ExpectedExtendedConfiguration -ne "None" -and
                        $virtualDirectory.SslFlagsSetCorrectly -eq $false) {
                        $commandParameters.SSLFlags.Add($virtualDirectory.VirtualDirectoryName, $virtualDirectory.SslFlagsToSet)
                    }
                }
            }

            if ($commandParameters.TokenChecking.Count -gt 0) {
                $progressParams.Status = "$baseStatus Executing Actions on Server"
                Write-Progress @progressParams
                Write-Host "$($serverExtendedProtection.ComputerName): Backing up applicationHost.config."
                # provide what we are changing outside of the script block for remote servers.
                $commandParameters.TokenChecking.Keys | ForEach-Object { Write-Verbose "$($serverExtendedProtection.ComputerName): Setting the $_ with the tokenChecking value of $($commandParameters.TokenChecking[$_])" }
                $commandParameters.SSLFlags.Keys | ForEach-Object { Write-Verbose "$($serverExtendedProtection.ComputerName): Setting the $_ with the SSLFlags value of $($commandParameters.SSLFlags[$_])" }
                $results = Invoke-ScriptBlockHandler -ComputerName $serverExtendedProtection.ComputerName -ScriptBlock {
                    param(
                        [object]$Commands,
                        [bool]$PassedWhatIf
                    )
                    $saveToPath = "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config"
                    $backupLocation = $saveToPath.Replace(".config", ".cep.$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak")
                    $internalTotalCommands = $Commands.TokenChecking.Count + $Commands.SSLFlags.Count
                    $internalCounter = 0
                    $internalProgressParams = @{
                        ParentId        = 1
                        Activity        = "Executing Actions on $env:ComputerName"
                        Status          = "Backing Up ApplicationHost.Config"
                        PercentComplete = 0
                    }
                    Write-Progress @internalProgressParams
                    try {
                        $backupSuccessful = $false
                        Copy-Item -Path $saveToPath -Destination $backupLocation -ErrorAction Stop -WhatIf:$PassedWhatIf
                        $backupSuccessful = $true
                        $errorContext = New-Object 'System.Collections.Generic.List[object]'
                        $setAllTokenChecking = $true
                        $setAllSslFlags = $true
                        Write-Host "$($env:COMPUTERNAME): Successful backup to $backupLocation"
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
                        foreach ($siteKey in $Commands.SSLFlags.Keys) {
                            try {
                                $internalCounter++
                                $internalProgressParams.Status = "Setting SSLFlags for $siteKey"
                                $internalProgressParams.PercentComplete = ($internalCounter / $internalTotalCommands * 100)
                                Write-Progress @internalProgressParams
                                $params = @{
                                    Filter      = "system.WebServer/security/access"
                                    Name        = "sslFlags"
                                    Value       = $Commands.SSLFlags[$siteKey]
                                    Location    = $siteKey
                                    PSPath      = "IIS:\"
                                    ErrorAction = "Stop"
                                    WhatIf      = $PassedWhatIf
                                }
                                Set-WebConfigurationProperty @params
                            } catch {
                                Write-Host "$($env:COMPUTERNAME): Failed to set sslFlags for $siteKey with the value $($Commands.SSLFlags[$siteKey]). Inner Exception $_"
                                $setAllSslFlags = $false
                                $errorContext.Add($_)
                            }
                        }
                        # Save out our changes
                        Copy-Item -Path $saveToPath -Destination $backupLocation.Replace(".cep.", ".cepChanges") -ErrorAction Stop -WhatIf:$PassedWhatIf
                    } catch {
                        Write-Host "$($env:COMPUTERNAME): Failed to backup applicationHost.config. Inner Exception $_"
                    }
                    Write-Progress @internalProgressParams -Completed
                    return [PSCustomObject]@{
                        BackupSuccess       = $backupSuccessful
                        BackupLocation      = $backupLocation
                        SetAllTokenChecking = $setAllTokenChecking
                        SetAllSslFlags      = $setAllSslFlags
                        ErrorContext        = $errorContext
                    }
                } -ArgumentList $commandParameters, $WhatIfPreference

                Write-Verbose "$($serverExtendedProtection.ComputerName): Backup Success: $($results.BackupSuccess) SetAllTokenChecking: $($results.SetAllTokenChecking) SetAllSslFlags: $($results.SetAllSslFlags)"

                if ($results.BackupSuccess -and ($results.SetAllTokenChecking -and $results.SetAllSslFlags)) {
                    Write-Verbose "$($serverExtendedProtection.ComputerName): Backed up the file to $($results.BackupLocation)"
                    Write-Host "$($serverExtendedProtection.ComputerName): Successfully updated applicationHost.config."
                    $updatedServers.Add($serverExtendedProtection.ComputerName)
                    continue
                } elseif ($results.BackupSuccess -eq $false) {
                    $line = "$($serverExtendedProtection.ComputerName): Failed to backup the applicationHost.config. No settings were applied."
                    Write-Verbose $line
                    Write-Warning $line
                } else {
                    $line = "$($serverExtendedProtection.ComputerName): Failed to set the values required for Extended Protection."
                    Write-Verbose $line
                    Write-Warning $line
                }
                $failedServers.Add($serverExtendedProtection.ComputerName)
                $results.ErrorContext | ForEach-Object { Write-HostErrorInformation "$($serverExtendedProtection.ComputerName): $_" }
                Write-Host ""
            } else {
                Write-Host "$($serverExtendedProtection.ComputerName): No changes made. Exchange build supports Extended Protection? $($serverExtendedProtection.SupportedVersionForExtendedProtection)"
                $noChangesMadeServers.Add($serverExtendedProtection.ComputerName)
            }
        }
    } end {
        Write-Progress @progressParams -Completed
        Write-Host ""
        if ($failedServers.Count -gt 0) {
            $line = "Failed to enable Extended Protection: $([string]::Join(", " ,$failedServers))"
            Write-Verbose $line
            Write-Warning $line
        }

        if ($noChangesMadeServers.Count -gt 0) {
            Write-Host "No changes made: $([string]::Join(", " ,$noChangesMadeServers))"
        }

        if ($updatedServers.Count -gt 0 ) {
            Write-Host "Successfully enabled Extended Protection: $([string]::Join(", " ,$updatedServers))"
        }
    }
}
