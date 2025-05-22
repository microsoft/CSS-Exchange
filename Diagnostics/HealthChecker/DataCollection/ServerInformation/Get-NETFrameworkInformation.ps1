# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-DotNetDllFileVersions.ps1
. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-NETFrameworkVersion.ps1
. $PSScriptRoot\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Get-NETFrameworkInformation {
    [CmdletBinding()]
    param(
        [string]$Server
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $params = @{
            ComputerName        = $Server
            FileNames           = @("System.Data.dll", "System.Configuration.dll")
            CatchActionFunction = ${Function:Invoke-CatchActions}
        }
        $fileInformation = $null
        Get-DotNetDllFileVersions @params | Invoke-RemotePipelineHandler -Result ([ref]$fileInformation)
        $netFramework = $null
        Get-NETFrameworkVersion -MachineName $Server -CatchActionFunction ${Function:Invoke-CatchActions} | Invoke-RemotePipelineHandler -Result ([ref]$netFramework)
    } end {
        return [PSCustomObject]@{
            MajorVersion    = $netFramework.MinimumValue
            RegistryValue   = $netFramework.RegistryValue
            FriendlyName    = $netFramework.FriendlyName
            FileInformation = $fileInformation
        }
    }
}
