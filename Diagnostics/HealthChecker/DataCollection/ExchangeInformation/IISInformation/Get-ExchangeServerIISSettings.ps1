# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeIISConfigSettings.ps1
. $PSScriptRoot\Get-IISWebApplication.ps1
. $PSScriptRoot\Get-IISWebSite.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeWebSitesFromAd.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\IISFunctions\Get-ApplicationHostConfig.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\IISFunctions\Get-IISModules.ps1

function Get-ExchangeServerIISSettings {
    param(
        [string]$ComputerName,
        [bool]$IsLegacyOS = $false,
        [scriptblock]$CatchActionFunction
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $params = @{
            ComputerName        = $ComputerName
            CatchActionFunction = $CatchActionFunction
        }

        try {
            $exchangeWebSites = Get-ExchangeWebSitesFromAd -ComputerName $ComputerName
            if ($exchangeWebSites.Count -gt 2) {
                Write-Verbose "Multiple OWA/ECP virtual directories detected"
            }
            Write-Verbose "Exchange websites detected: $([string]::Join(", " ,$exchangeWebSites))"
        } catch {
            Write-Verbose "Failed to get the Exchange Web Sites from Ad."
            $exchangeWebSites = $null
            Invoke-CatchActions
        }

        # We need to wrap the array into another array as the -WebSitesToProcess parameter expects an array object
        $webSite = Invoke-ScriptBlockHandler @params -ScriptBlock ${Function:Get-IISWebSite} -ArgumentList (, $exchangeWebSites)
        $webApplication = Invoke-ScriptBlockHandler @params -ScriptBlock ${Function:Get-IISWebApplication}

        $configurationFiles = @($webSite.PhysicalPath)
        $configurationFiles += $webApplication.PhysicalPath | Select-Object -Unique
        $configurationFiles = $configurationFiles | ForEach-Object { [System.IO.Path]::Combine($_, "web.config") }

        $iisConfigParams = @{
            MachineName         = $ComputerName
            FilePath            = $configurationFiles
            CatchActionFunction = $CatchActionFunction
        }
        Write-Verbose "Trying to query the IIS configuration settings"
        $iisConfigurationSettings = Get-ExchangeIISConfigSettings @iisConfigParams

        Write-Verbose "Trying to query the 'applicationHost.config' file"
        $applicationHostConfig = Get-ApplicationHostConfig $ComputerName $CatchActionFunction

        if ($null -ne $applicationHostConfig) {
            Write-Verbose "Trying to query the modules which are loaded by IIS"
            $iisModulesParams = @{
                ApplicationHostConfig    = ([xml]$applicationHostConfig)
                SkipLegacyOSModulesCheck = $IsLegacyOS
                CatchActionFunction      = $CatchActionFunction
            }
            $iisModulesInformation = Get-IISModules @iisModulesParams
        } else {
            Write-Verbose "No 'applicationHost.config' file returned by previous call"
        }
    } end {
        return [PSCustomObject]@{
            applicationHostConfig    = $applicationHostConfig
            IISModulesInformation    = $iisModulesInformation
            IISConfigurationSettings = $iisConfigurationSettings
            IISWebSite               = $webSite
            IISWebApplication        = $webApplication
        }
    }
}
