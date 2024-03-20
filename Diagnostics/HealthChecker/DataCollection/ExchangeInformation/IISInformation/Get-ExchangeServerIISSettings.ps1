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
        [ScriptBlock]$CatchActionFunction
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

        # Get the TokenCacheModule build information as we need it to perform version testing
        Write-Verbose "Trying to query TokenCacheModule version information"
        $tokenCacheModuleParams = @{
            ComputerName           = $Server
            ScriptBlockDescription = "Get TokenCacheModule version information"
            ScriptBlock            = { [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$env:windir\System32\inetsrv\cachtokn.dll") }
            CatchActionFunction    = ${Function:Invoke-CatchActions}
        }
        $tokenCacheModuleVersionInformation = Invoke-ScriptBlockHandler @tokenCacheModuleParams

        # Get the shared web configuration files
        $sharedWebConfigPaths = @($webApplication.ConfigurationFileInfo.LinkedConfigurationFilePath | Select-Object -Unique)
        $sharedWebConfig = $null

        if ($sharedWebConfigPaths.Count -gt 0) {
            $sharedWebConfig = Invoke-ScriptBlockHandler @params -ScriptBlock {
                param ($ConfigFiles)
                $ConfigFiles | ForEach-Object {
                    Write-Verbose "Working on shared config file: $_"
                    $validWebConfig = $false
                    $exist = Test-Path $_
                    $content = $null
                    try {
                        if ($exist) {
                            $content = (Get-Content $_ -Raw).Trim()
                            [xml]$content | Out-Null # test to make sure it is valid
                            $validWebConfig = $true
                        }
                    } catch {
                        # Inside of Invoke-Command, can't use Invoke-CatchActions
                        Write-Verbose "Failed to convert shared web config '$_' to xml. Exception: $($_.Exception)"
                    }

                    [PSCustomObject]@{
                        Location = $_
                        Exist    = $exist
                        Content  = $content
                        Valid    = $validWebConfig
                    }
                }
            } -ArgumentList (, $sharedWebConfigPaths) -ScriptBlockDescription "Getting Shared Web Config Files"
        }

        Write-Verbose "Trying to query the 'applicationHost.config' file"
        $applicationHostConfig = Get-ApplicationHostConfig $ComputerName $CatchActionFunction

        if ($null -ne $applicationHostConfig) {
            Write-Verbose "Trying to query the modules which are loaded by IIS"
            try {
                [xml]$xmlApplicationHostConfig = [xml]$applicationHostConfig
            } catch {
                Write-Verbose "Failed to convert the Application Host Config to XML"
                Invoke-CatchActions
                # Don't attempt to run Get-IISModules
                return
            }
            $iisModulesParams = @{
                ComputerName             = $ComputerName
                ApplicationHostConfig    = $xmlApplicationHostConfig
                SkipLegacyOSModulesCheck = $IsLegacyOS
                CatchActionFunction      = $CatchActionFunction
            }
            $iisModulesInformation = Get-IISModules @iisModulesParams
        } else {
            Write-Verbose "No 'applicationHost.config' file returned by previous call"
        }
    } end {
        return [PSCustomObject]@{
            ApplicationHostConfig          = $applicationHostConfig
            IISModulesInformation          = $iisModulesInformation
            IISTokenCacheModuleInformation = $tokenCacheModuleVersionInformation
            IISConfigurationSettings       = $iisConfigurationSettings
            IISWebSite                     = $webSite
            IISWebApplication              = $webApplication
            IISSharedWebConfig             = $sharedWebConfig
        }
    }
}
