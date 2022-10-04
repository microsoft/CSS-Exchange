# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeIISConfigSettings.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\IISFunctions\Get-ApplicationHostConfig.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\IISFunctions\Get-IISModules.ps1

function Get-ExchangeServerIISSettings {
    param(
        [string]$ComputerName,
        [string]$ExchangeInstallPath,
        [bool]$IsLegacyOS = $false,
        [scriptblock]$CatchActionFunction
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $iisConfigParams = @{
            MachineName         = $ComputerName
            ExchangeInstallPath = $ExchangeInstallPath
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
        }
    }
}
