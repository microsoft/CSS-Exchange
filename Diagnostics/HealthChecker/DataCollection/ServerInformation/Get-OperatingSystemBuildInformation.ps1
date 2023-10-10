# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\Get-ServerOperatingSystemVersion.ps1
. $PSScriptRoot\Get-WmiObjectCriticalHandler.ps1

function Get-OperatingSystemBuildInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $win32_OperatingSystem = Get-WmiObjectCriticalHandler -ComputerName $Server -Class Win32_OperatingSystem -CatchActionFunction ${Function:Invoke-CatchActions}
        $serverOsVersionInformation = Get-ServerOperatingSystemVersion -ComputerName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
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
