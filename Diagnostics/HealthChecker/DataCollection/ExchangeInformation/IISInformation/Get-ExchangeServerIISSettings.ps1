# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        $webSite = Invoke-ScriptBlockHandler @params -ScriptBlock ${Function:Get-IISWebSite} -ArgumentList (, $exchangeWebSites) -ScriptBlockDescription "Get-IISWebSite"
        $webApplication = Invoke-ScriptBlockHandler @params -ScriptBlock ${Function:Get-IISWebApplication} -ScriptBlockDescription "Get-IISWebApplication"

        # Get the shared web configuration files
        $sharedWebConfigPaths = $webApplication.ConfigurationFileInfo.LinkedConfigurationFilePath | Select-Object -Unique
        $sharedWebConfig = Invoke-ScriptBlockHandler @params -ScriptBlock {
            param ($ConfigFiles)
            $ConfigFiles | ForEach-Object {
                [PSCustomObject]@{
                    Location = $_
                    Exist    = $(Test-Path $_)
                    Content  = if (Test-Path $_) { Get-Content $_ } else { $null }
                }
            }
        } -ArgumentList (, $sharedWebConfigPaths) -ScriptBlockDescription "Getting Shared Web Config Files"

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
            ApplicationHostConfig    = $applicationHostConfig
            IISModulesInformation    = $iisModulesInformation
            IISConfigurationSettings = $iisConfigurationSettings
            IISWebSite               = $webSite
            IISWebApplication        = $webApplication
            IISSharedWebConfig       = $sharedWebConfig
        }
    }
}
