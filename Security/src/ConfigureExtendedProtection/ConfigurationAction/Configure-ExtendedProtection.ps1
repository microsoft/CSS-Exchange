# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\DataCollection\Get-ExtendedProtectionConfiguration.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

function Configure-ExtendedProtection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Work in progress - future adjustment')]
    param()

    if ($Rollback) {
        Write-Verbose "Rollback initialized"

        foreach ($server in $ExchangeServers) {
            Invoke-ScriptBlockHandler -ComputerName $server -ScriptBlock {
                try {
                    $saveToPath = "$($env:WINDIR)\System32\inetsrv\config\applicationHost.config"
                    $backupLocation = $saveToPath.Replace(".config", ".revert.cep.$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak")
                    $restoreFile = (Get-ChildItem "$($env:WINDIR)\System32\inetsrv\config\" -Filter "*applicationHost.cep.*.bak" | Sort-Object LastWriteTime | Select-Object -First 1).FullName

                    if ($null -eq $restoreFile) {
                        throw "Failed to find applicationHost.cep.*.bak file."
                    }

                    Copy-Item -Path $saveToPath -Destination $backupLocation -ErrorAction Stop
                    Write-Host "Restoring file $restoreFile on server $env:COMPUTERNAME"
                    Copy-Item -Path $restoreFile -Destination $saveToPath -Force -ErrorAction Stop
                    Write-Host "Successful restore of the application file"
                } catch {
                    Write-Host "Failed to restore application host file on server $env:COMPUTERNAME. Inner Exception $_"
                }
            }
        }

        return
    }

    $extendedProtectionConfigurations = $ExchangeServers | ForEach-Object { Get-ExtendedProtectionConfiguration -ComputerName $_ }

    foreach ($serverExtendedProtection in $extendedProtectionConfigurations) {
        # set the extended protection configuration to the expected and supported configuration if different
        #$saveRequired = $false
        #$locationPathList = ($serverExtendedProtection.ApplicationHostConfig.configuration.location.path).ToLower()
        #$location = $serverExtendedProtection.ApplicationHostConfig.configuration.location
        $saveInformation = @{}

        foreach ($virtualDirectory in $serverExtendedProtection.ExtendedProtectionConfiguration) {
            Write-Verbose "Virtual Directory Name: $($virtualDirectory.VirtualDirectoryName) Current Set Extended Protection: $($virtualDirectory.ExtendedProtection) Expected Value $($virtualDirectory.ExpectedExtendedConfiguration)"
            if ($virtualDirectory.ExtendedProtection -ne $virtualDirectory.ExpectedExtendedConfiguration) {

                $saveInformation.Add($virtualDirectory.VirtualDirectoryName, $virtualDirectory.ExpectedExtendedConfiguration)
                <# Can't do it this way due to the setting not being there originally in the configuration file. For now use the Set-WebConfigurationProperty
                $pathIndex = [array]::IndexOf($locationPathList, $virtualDirectory.Configuration.NodePath.ToLower())

                if ($pathIndex -ne -1) {
                    $configNode = $location[$pathIndex]
                    $configNode.'system.webServer'.security.authentication.windowsAuthentication.extendedProtection.tokenChecking = $virtualDirectory.ExpectedExtendedConfiguration
                    $saveRequired = $true
                }
                #>
            }
        }

        if ($saveInformation.Count -gt 0) {
            Write-Host "An update has occurred to the application host config file for server $($serverExtendedProtection.ComputerName). Going to backup the application host config file and update it."
            Invoke-ScriptBlockHandler -ComputerName $serverExtendedProtection.ComputerName -ScriptBlock {
                param(
                    [hashtable]$Commands
                )
                $saveToPath = "$($env:WINDIR)\System32\inetsrv\config\applicationHost.config"
                $backupLocation = $saveToPath.Replace(".config", ".cep.$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak")
                try {
                    Copy-Item -Path $saveToPath -Destination $backupLocation -ErrorAction Stop
                    Write-Host "Successful backup of the application host config file to $backupLocation"
                    foreach ($siteKey in $Commands.Keys) {
                        #TODO: Place in a try catch incase we have a failure on 1 setting.
                        Set-WebConfigurationProperty -Filter "system.WebServer/security/authentication/windowsAuthentication" -Name extendedProtection.tokenChecking -Value $Commands[$siteKey] -Location $siteKey -PSPath IIS:\
                        Write-Verbose "$env:COMPUTERNAME set the $siteKey with the tokenChecking value of $($Commands[$siteKey])"
                    }
                    Write-Host "Successfully backed up and saved new application host config file."
                } catch {
                    Write-Host "Failed to save application host file on server $env:COMPUTERNAME. Inner Exception $_"
                }
            } -ArgumentList $saveInformation
        } else {
            Write-Host "No change was made for the server $($serverExtendedProtection.ComputerName)"
        }
    }
}
