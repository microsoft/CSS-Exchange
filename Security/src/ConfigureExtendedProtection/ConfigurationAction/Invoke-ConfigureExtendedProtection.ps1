# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\DataCollection\Get-ExtendedProtectionConfiguration.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

function Invoke-ConfigureExtendedProtection {
    [CmdletBinding()]
    param(
        [object[]]$ExtendedProtectionConfigurations
    )

    begin {
        $failedServers = New-Object 'System.Collections.Generic.List[string]'
        $noChangesMadeServers = New-Object 'System.Collections.Generic.List[string]'
        $updatedServers = New-Object 'System.Collections.Generic.List[string]'
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {
        foreach ($serverExtendedProtection in $ExtendedProtectionConfigurations) {
            # Check to make sure server is connected and valid information is provided.
            if (-not ($serverExtendedProtection.ServerConnected)) {
                $line = "Server $($serverExtendedProtection.ComputerName) isn't online to get valid Extended Protection Configuration settings"
                Write-Verbose $line
                Write-Warning $line
                $failedServers.Add($serverExtendedProtection.ComputerName)
                continue
            }

            if ($serverExtendedProtection.ExtendedProtectionConfiguration.Count -eq 0) {
                $line = "Server $($serverExtendedProtection.ComputerName) wasn't able to collect Extended Protection Configuration"
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

            foreach ($virtualDirectory in $serverExtendedProtection.ExtendedProtectionConfiguration) {
                Write-Verbose "Virtual Directory Name: $($virtualDirectory.VirtualDirectoryName) Current Set Extended Protection: $($virtualDirectory.ExtendedProtection) Expected Value $($virtualDirectory.ExpectedExtendedConfiguration)"
                Write-Verbose "Current Set SSL Flags: $($virtualDirectory.Configuration.SslSettings.Value) Expected SSL Flags: $($virtualDirectory.ExpectedSslFlags) Set Correctly: $($virtualDirectory.SslFlagsSetCorrectly)"
                if ($virtualDirectory.ExtendedProtection -ne $virtualDirectory.ExpectedExtendedConfiguration) {
                    $commandParameters.TokenChecking.Add($virtualDirectory.VirtualDirectoryName, $virtualDirectory.ExpectedExtendedConfiguration)

                    if ($virtualDirectory.ExpectedExtendedConfiguration -ne "None" -and
                        $virtualDirectory.SslFlagsSetCorrectly -eq $false) {
                        $commandParameters.SSLFlags.Add($virtualDirectory.VirtualDirectoryName, $virtualDirectory.SslFlagsToSet)
                    }
                }
            }

            if ($commandParameters.TokenChecking.Count -gt 0) {
                Write-Host "An update has occurred to the application host config file for server $($serverExtendedProtection.ComputerName). Backing up the application host config file and updating it."
                # provide what we are changing outside of the script block for remote servers.
                Write-Verbose "Setting the following values on the server $($serverExtendedProtection.ComputerName)"
                $commandParameters.TokenChecking.Keys | ForEach-Object { Write-Verbose "Setting the $_ with the tokenChecking value of $($commandParameters.TokenChecking[$_])" }
                $commandParameters.SSLFlags.Keys | ForEach-Object { Write-Verbose "Setting the $_ with the SSLFlags value of $($commandParameters.SSLFlags[$_])" }
                $results = Invoke-ScriptBlockHandler -ComputerName $serverExtendedProtection.ComputerName -ScriptBlock {
                    param(
                        [object]$Commands
                    )
                    $saveToPath = "$($env:WINDIR)\System32\inetsrv\config\applicationHost.config"
                    $backupLocation = $saveToPath.Replace(".config", ".cep.$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak")
                    try {
                        $backupSuccessful = $false
                        Copy-Item -Path $saveToPath -Destination $backupLocation -ErrorAction Stop
                        $backupSuccessful = $true
                        $errorContext = New-Object 'System.Collections.Generic.List[object]'
                        $setAllTokenChecking = $true
                        $setAllSslFlags = $true
                        Write-Host "Successful backup of the application host config file to $backupLocation"
                        foreach ($siteKey in $Commands.TokenChecking.Keys) {
                            try {
                                Set-WebConfigurationProperty -Filter "system.WebServer/security/authentication/windowsAuthentication" -Name extendedProtection.tokenChecking -Value $Commands.TokenChecking[$siteKey] -Location $siteKey -PSPath IIS:\ -ErrorAction Stop
                            } catch {
                                Write-Host "Failed to set tokenChecking for $env:COMPUTERNAME SITE: $siteKey with the value $($Commands.TokenChecking[$siteKey]). Inner Exception $_"
                                $setAllTokenChecking = $false
                                $errorContext.Add($_)
                            }
                        }
                        foreach ($siteKey in $Commands.SSLFlags.Keys) {
                            try {
                                Set-WebConfigurationProperty -Filter "system.WebServer/security/access" -Name sslFlags -Value $Commands.SSLFlags[$siteKey] -Location $siteKey -PSPath IIS:\ -ErrorAction Stop
                            } catch {
                                Write-Host "Failed to set sslFlags for $env:COMPUTERNAME SITE: $siteKey with the value $($Commands.SSLFlags[$siteKey]). Inner Exception $_"
                                $setAllSslFlags = $false
                                $errorContext.Add($_)
                            }
                        }
                    } catch {
                        Write-Host "Failed to save application host file on server $env:COMPUTERNAME. Inner Exception $_"
                    }
                    return [PSCustomObject]@{
                        BackupSuccess       = $backupSuccessful
                        BackupLocation      = $backupLocation
                        SetAllTokenChecking = $setAllTokenChecking
                        SetAllSslFlags      = $setAllSslFlags
                        ErrorContext        = $errorContext
                    }
                } -ArgumentList $commandParameters

                Write-Verbose "Backup Success: $($results.BackupSuccess) SetAllTokenChecking: $($results.SetAllTokenChecking) SetAllSslFlags: $($results.SetAllSslFlags)"

                if ($results.BackupSuccess -and ($results.SetAllTokenChecking -and $results.SetAllSslFlags)) {
                    Write-Verbose "Backed up the file to $($results.BackupLocation)"
                    Write-Host "Successfully backed up and saved new application host config file."
                    $updatedServers.Add($serverExtendedProtection.ComputerName)
                    continue
                } elseif ($results.BackupSuccess -eq $false) {
                    $line = "Failed to backup the application host config file. No settings were applied."
                    Write-Verbose $line
                    Write-Warning $line
                } else {
                    $line = "Failed to properly set all the correct values on the server $($serverExtendedProtection.ComputerName) required for Extended Protection. Recommended to address!"
                    Write-Verbose $line
                    Write-Warning $line
                }
                $failedServers.Add($serverExtendedProtection.ComputerName)
                Start-Sleep 5 # Sleep to bring to attention to the customer
                Write-Host "Errors that occurred on the backup and set attempt:"
                # Not able to group the error from remote context, so need to display them all.
                $results.ErrorContext | ForEach-Object { Write-HostErrorInformation $_ }
                Write-Host ""
            } else {
                Write-Host "No change was made for the server $($serverExtendedProtection.ComputerName) - Exchange build supports Extended Protection? $($serverExtendedProtection.SupportedVersionForExtendedProtection)"
                $noChangesMadeServers.Add($serverExtendedProtection.ComputerName)
            }
        }
    } end {
        if ($failedServers.Count -gt 0) {
            $line = "These are the servers that failed to apply extended protection: $([string]::Join(", " ,$failedServers))"
            Write-Verbose $line
            Write-Warning $line
        }

        if ($noChangesMadeServers.Count -gt 0) {
            Write-Host "No changes were made to these servers: $([string]::Join(", " ,$noChangesMadeServers))"
        }

        if ($updatedServers.Count -gt 0 ) {
            Write-Host "Successfully updated all of the following servers for extended protection:  $([string]::Join(", " ,$updatedServers))"
        }
    }
}
