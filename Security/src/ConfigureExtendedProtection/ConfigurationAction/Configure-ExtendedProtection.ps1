# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\DataCollection\Get-ExtendedProtectionConfiguration.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

function Configure-ExtendedProtection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Work in progress - future adjustment')]
    param()

    if ($Rollback) {
        Write-Verbose "Rollback initialized"

        foreach ($server in $ExchangeServers) {
            Write-Host "Attempting to rollback on $server"
            $results = Invoke-ScriptBlockHandler -ComputerName $server -ScriptBlock {
                try {
                    $saveToPath = "$($env:WINDIR)\System32\inetsrv\config\applicationHost.config"
                    $backupLocation = $saveToPath.Replace(".config", ".revert.cep.$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak")
                    $restoreFile = (Get-ChildItem "$($env:WINDIR)\System32\inetsrv\config\" -Filter "*applicationHost.cep.*.bak" | Sort-Object LastWriteTime | Select-Object -First 1).FullName
                    $successRestore = $false
                    $successBackupCurrent = $false

                    if ($null -eq $restoreFile) {
                        throw "Failed to find applicationHost.cep.*.bak file."
                    }

                    Copy-Item -Path $saveToPath -Destination $backupLocation -ErrorAction Stop
                    $successBackupCurrent = $true
                    Copy-Item -Path $restoreFile -Destination $saveToPath -Force -ErrorAction Stop
                    $successRestore = $true
                } catch {
                    Write-Host "Failed to restore application host file on server $env:COMPUTERNAME. Inner Exception $_"
                }
                return [PSCustomObject]@{
                    RestoreFile          = $restoreFile
                    SuccessRestore       = $successRestore
                    SuccessBackupCurrent = $successBackupCurrent
                    ErrorContext         = $Error[0]
                }
            }

            if ($results.SuccessRestore -and $results.SuccessBackupCurrent) {
                Write-Host "Successful restored $($results.RestoreFile) on server $server"
                continue
            } elseif ($results.SuccessBackupCurrent -eq $false) {
                Write-Host "Failed to backup the current configuration on server $server"
            } else {
                Write-Host "Failed to restore $($results.RestoreFile) to be the active application host config file on server $server"
            }
            Write-HostErrorInformation $results.ErrorContext
        }

        return
    }

    $extendedProtectionConfigurations = $ExchangeServers | ForEach-Object { Get-ExtendedProtectionConfiguration -ComputerName $_ }

    foreach ($serverExtendedProtection in $extendedProtectionConfigurations) {
        # set the extended protection configuration to the expected and supported configuration if different
        $saveInformation = @{}

        foreach ($virtualDirectory in $serverExtendedProtection.ExtendedProtectionConfiguration) {
            Write-Verbose "Virtual Directory Name: $($virtualDirectory.VirtualDirectoryName) Current Set Extended Protection: $($virtualDirectory.ExtendedProtection) Expected Value $($virtualDirectory.ExpectedExtendedConfiguration)"
            if ($virtualDirectory.ExtendedProtection -ne $virtualDirectory.ExpectedExtendedConfiguration) {
                $saveInformation.Add($virtualDirectory.VirtualDirectoryName, $virtualDirectory.ExpectedExtendedConfiguration)
            }
        }

        if ($saveInformation.Count -gt 0) {
            Write-Host "An update has occurred to the application host config file for server $($serverExtendedProtection.ComputerName). Going to backup the application host config file and update it."
            # provide what we are going to be changing outside of the script block for remote servers.
            Write-Verbose "Going to be setting the following values on the server $($serverExtendedProtection.ComputerName)"
            $saveInformation.Keys | ForEach-Object { Write-Verbose "Setting the $_ with the tokenChecking value of $($saveInformation[$_])" }
            $results = Invoke-ScriptBlockHandler -ComputerName $serverExtendedProtection.ComputerName -ScriptBlock {
                param(
                    [hashtable]$Commands
                )
                $saveToPath = "$($env:WINDIR)\System32\inetsrv\config\applicationHost.config"
                $backupLocation = $saveToPath.Replace(".config", ".cep.$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak")
                try {
                    $backupSuccessful = $false
                    Copy-Item -Path $saveToPath -Destination $backupLocation -ErrorAction Stop
                    $backupSuccessful = $true
                    $errorContext = New-Object 'System.Collections.Generic.List[object]'
                    Write-Host "Successful backup of the application host config file to $backupLocation"
                    foreach ($siteKey in $Commands.Keys) {
                        try {
                            Set-WebConfigurationProperty -Filter "system.WebServer/security/authentication/windowsAuthentication" -Name extendedProtection.tokenChecking -Value $Commands[$siteKey] -Location $siteKey -PSPath IIS:\ -ErrorAction Stop
                        } catch {
                            Write-Host "Failed to set tokenChecking for $env:COMPUTERNAME SITE: $siteKey with the value $($Commands[$siteKey])"
                            $errorContext.Add($_)
                        }
                    }
                } catch {
                    Write-Host "Failed to save application host file on server $env:COMPUTERNAME. Inner Exception $_"
                }
                return [PSCustomObject]@{
                    BackupSuccess       = $backupSuccessful
                    BackupLocation      = $backupLocation
                    SetAllTokenChecking = $errorContext.Count -eq 0
                    ErrorContext        = $errorContext
                }
            } -ArgumentList $saveInformation

            Write-Verbose "Backup Success: $($results.BackupSuccess) SetAllTokenChecking: $($results.SetAllTokenChecking)"

            if ($results.BackupSuccess -and $results.SetAllTokenChecking) {
                Write-Verbose "Backed up the file to $($results.BackupLocation)"
                Write-Host "Successfully backed up and saved new application host config file."
                continue
            } elseif ($results.BackupSuccess -eq $false) {
                Write-Host "Failed to backup the application host config file. No settings were applied."
            } else {
                Write-Host "Failed to properly set all the tokenChecking values on the server $($serverExtendedProtection.ComputerName). Recommended to address!"
            }
            $results.ErrorContext | ForEach-Object { Write-HostErrorInformation $_ }
        } else {
            Write-Host "No change was made for the server $($serverExtendedProtection.ComputerName)"
        }
    }
}
