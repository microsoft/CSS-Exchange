# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeIISConfigSettings.ps1
. $PSScriptRoot\Get-IISWebApplication.ps1
. $PSScriptRoot\Get-IISWebSite.ps1
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

        $webSite = Invoke-ScriptBlockHandler @params -ScriptBlock ${Function:Get-IISWebSite}
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
                ApplicationHostConfig    = $applicationHostConfig
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
