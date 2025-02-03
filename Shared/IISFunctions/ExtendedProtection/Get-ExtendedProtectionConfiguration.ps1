# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Invoke-CatchActionError.ps1
. $PSScriptRoot\..\..\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\Write-ErrorInformation.ps1

function Get-ExtendedProtectionConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Xml.XmlNode]$ApplicationHostConfig,

        [Parameter(Mandatory = $false)]
        [System.Version]$ExSetupVersion,

        [Parameter(Mandatory = $false)]
        [bool]$IsMailboxServer = $true,

        [Parameter(Mandatory = $false)]
        [bool]$IsClientAccessServer = $true,

        [Parameter(Mandatory = $false)]
        [bool]$ExcludeEWS = $false,

        [Parameter(Mandatory = $false)]
        [bool]$ExcludeEWSFe,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Exchange Back End/EWS")]
        [string[]]$SiteVDirLocations,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {

        . $PSScriptRoot\Get-ExtendedProtectionConfigurationResult.ps1

        # Intended for inside of Invoke-Command.
        function GetApplicationHostConfig {
            $appHostConfig = New-Object -TypeName Xml
            try {
                $appHostConfigPath = "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config"
                $appHostConfig.Load($appHostConfigPath)
            } catch {
                Write-Verbose "Failed to loaded application host config file. $_"
                $appHostConfig = $null
            }
            return $appHostConfig
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $computerResult = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlock { return $env:COMPUTERNAME }
        $serverConnected = $null -ne $computerResult

        if ($null -eq $computerResult) {
            Write-Verbose "Failed to connect to server $ComputerName"
            return
        }

        if ($null -eq $ExSetupVersion) {
            [System.Version]$ExSetupVersion = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlock {
                (Get-Command ExSetup.exe |
                    ForEach-Object { $_.FileVersionInfo } |
                    Select-Object -First 1).FileVersion
            }

            if ($null -eq $ExSetupVersion) {
                throw "Failed to determine Exchange build number"
            }
        } else {
            # Hopefully the caller knows what they are doing, best be from the correct server!!
            Write-Verbose "Caller passed the ExSetupVersion information"
        }

        if ($null -eq $ApplicationHostConfig) {
            Write-Verbose "Trying to load the application host config from $ComputerName"
            $params = @{
                ComputerName        = $ComputerName
                ScriptBlock         = ${Function:GetApplicationHostConfig}
                CatchActionFunction = $CatchActionFunction
            }

            $ApplicationHostConfig = Invoke-ScriptBlockHandler @params

            if ($null -eq $ApplicationHostConfig) {
                throw "Failed to load application host config from $ComputerName"
            }
        } else {
            # Hopefully the caller knows what they are doing, best be from the correct server!!
            Write-Verbose "Caller passed the application host config."
        }
    }
    process {
        $params = @{
            ApplicationHostConfig = $ApplicationHostConfig
            ExSetupVersion        = $ExSetupVersion
            IsMailboxServer       = $IsMailboxServer
            IsClientAccessServer  = $IsClientAccessServer
            ExcludeEWS            = $ExcludeEWS
            ExcludeEWSFe          = $ExcludeEWSFe
            CatchActionFunction   = $CatchActionFunction
        }

        if ($null -ne $SiteVDirLocations) {
            $params.Add("SiteVDirLocations", $SiteVDirLocations)
        }
        $epResults = Get-ExtendedProtectionConfigurationResult @params
    }
    end {
        return [PSCustomObject]@{
            ComputerName                          = $ComputerName
            ServerConnected                       = $serverConnected
            SupportedVersionForExtendedProtection = $epResults.SupportedVersionForExtendedProtection
            ApplicationHostConfig                 = $ApplicationHostConfig
            ExtendedProtectionConfiguration       = $epResults.ExtendedProtectionConfiguration
            ExtendedProtectionConfigured          = $epResults.ExtendedProtectionConfigured
        }
    }
}
