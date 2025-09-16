# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-IISWebApplication.ps1
. $PSScriptRoot\Get-IISWebSite.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\IISFunctions\Get-IISModules.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Get-ExchangeServerIISSettings {
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [bool]$IsLegacyOS = $false,
        [ScriptBlock]$CatchActionFunction
    )
    begin {
        # Function for pester testing.
        # Extract for Pester Testing - Start
        function GetCachtoknVersionInfo {
            return [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$env:windir\System32\inetsrv\cachtokn.dll")
        }
        # Extract for Pester Testing - End
    }
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $webSite = $null
        $webApplication = $null
        Get-IISWebSite | Invoke-RemotePipelineHandler -Result ([ref]$webSite)
        Get-IISWebApplication | Invoke-RemotePipelineHandler -Result ([ref]$webApplication)

        # Get the TokenCacheModule build information as we need it to perform version testing
        Write-Verbose "Trying to query TokenCacheModule version information"
        $tokenCacheModuleVersionInformation = GetCachtoknVersionInfo
        # Get the shared web configuration files
        $sharedWebConfigPaths = @($webApplication.ConfigurationFileInfo.LinkedConfigurationFilePath | Select-Object -Unique)
        $sharedWebConfig = New-Object System.Collections.Generic.List[object]

        # This is to account for the code now being executed on the server itself now.
        foreach ($sharedWebConfigPath in $sharedWebConfigPaths) {
            Write-Verbose "Working on shared config file: $sharedWebConfigPath"
            $validWebConfig = $false
            $exist = Test-Path $sharedWebConfigPath
            $content = $null
            try {
                if ($exist) {
                    $content = (Get-Content $sharedWebConfigPath -Raw -Encoding UTF8).Trim()
                    [xml]$content | Out-Null # test to make sure it is valid
                    $validWebConfig = $true
                }
            } catch {
                Write-Verbose "Failed to convert shared web config '$sharedWebConfigPath' to xml. Exception: $($_.Exception)"
                Invoke-CatchActions
            }

            $sharedWebConfig.Add([PSCustomObject]@{
                    Location = $sharedWebConfigPath
                    Exist    = $exist
                    Content  = $content
                    Valid    = $validWebConfig
                })
        }

        if ($sharedWebConfig.Count -eq 0) { $sharedWebConfig = $null }

        try {
            Write-Verbose "Trying to query the 'applicationHost.config' file"
            $applicationHostConfig = (Get-Content "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config" -Raw -Encoding UTF8).Trim()
        } catch {
            Invoke-CatchActions
        }

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
                ApplicationHostConfig    = $xmlApplicationHostConfig
                SkipLegacyOSModulesCheck = $IsLegacyOS
                CatchActionFunction      = $CatchActionFunction
            }
            $iisModulesInformation = $null
            Get-IISModules @iisModulesParams | Invoke-RemotePipelineHandler -Result ([ref]$iisModulesInformation)
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
