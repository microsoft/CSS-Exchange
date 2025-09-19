# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1
. $PSScriptRoot\Get-ServerOperatingSystemVersion.ps1
. $PSScriptRoot\Get-WmiObjectCriticalHandler.ps1

function Get-OperatingSystemBuildInformation {
    [CmdletBinding()]
    param()
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $win32_OperatingSystem = $null
        $serverOsVersionInformation = $null
        Get-WmiObjectCriticalHandler -Class Win32_OperatingSystem -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$win32_OperatingSystem)
        Get-ServerOperatingSystemVersion -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$serverOsVersionInformation)
    } end {
        return [PSCustomObject]@{
            BuildVersion     = [System.Version]$win32_OperatingSystem.Version
            MajorVersion     = $serverOsVersionInformation.MajorVersion
            InstallationType = $serverOsVersionInformation.InstallationType
            FriendlyName     = $serverOsVersionInformation.FriendlyName
            OperatingSystem  = $win32_OperatingSystem
        }
    }
}
