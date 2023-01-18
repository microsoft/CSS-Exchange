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
    } end {
        return [PSCustomObject]@{
            VersionBuild    = $win32_OperatingSystem.Version
            MajorVersion    = (Get-ServerOperatingSystemVersion -OsCaption $win32_OperatingSystem.Caption)
            FriendlyName    = $win32_OperatingSystem.Caption
            OperatingSystem = $win32_OperatingSystem
        }
    }
}
