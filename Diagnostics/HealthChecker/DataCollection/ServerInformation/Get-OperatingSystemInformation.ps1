# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-ServerRebootPending.ps1
. $PSScriptRoot\..\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\TLS\Get-AllTlsSettings.ps1
. $PSScriptRoot\Get-AllNicInformation.ps1
. $PSScriptRoot\Get-NETFrameworkInformation.ps1
. $PSScriptRoot\Get-NetworkingInformation.ps1
. $PSScriptRoot\Get-OperatingSystemBuildInformation.ps1
. $PSScriptRoot\Get-OperatingSystemRegistryValues.ps1
. $PSScriptRoot\Get-PageFileInformation.ps1
. $PSScriptRoot\Get-PowerPlanSetting.ps1
. $PSScriptRoot\Get-Smb1ServerSettings.ps1
. $PSScriptRoot\Get-TimeZoneInformation.ps1

function Get-OperatingSystemInformation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $buildInformation = Get-OperatingSystemBuildInformation -Server $Server
        $currentDateTime = Get-Date
        $lastBootUpTime = [Management.ManagementDateTimeConverter]::ToDateTime($buildInformation.OperatingSystem.LastBootUpTime)
        $serverBootUp = [PSCustomObject]@{
            Days    = ($currentDateTime - $lastBootUpTime).Days
            Hours   = ($currentDateTime - $lastBootUpTime).Hours
            Minutes = ($currentDateTime - $lastBootUpTime).Minutes
            Seconds = ($currentDateTime - $lastBootUpTime).Seconds
        }

        $powerPlan = Get-PowerPlanSetting -Server $Server
        $pageFile = Get-PageFileInformation -Server $Server
        $networkInformation = Get-NetworkingInformation -Server $Server
        $hotFixes = (Get-HotFix -ComputerName $Server -ErrorAction SilentlyContinue) #old school check still valid and faster and a failsafe
        $serverPendingReboot = (Get-ServerRebootPending -ServerName $Server -CatchActionFunction ${Function:Invoke-CatchActions})
        $timeZoneInformation = Get-TimeZoneInformation -MachineName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $tlsSettings = Get-AllTlsSettings -MachineName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $vcRedistributable = Get-VisualCRedistributableInstalledVersion -ComputerName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $smb1ServerSettings = Get-Smb1ServerSettings -ServerName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $registryValues = Get-OperatingSystemRegistryValues -MachineName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $netFrameworkInformation = Get-NETFrameworkInformation -Server $Server
    } end {
        Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
        return [PSCustomObject]@{
            BuildInformation    = $buildInformation
            NetworkInformation  = $networkInformation
            PowerPlan           = $powerPlan
            PageFile            = $pageFile
            ServerPendingReboot = $serverPendingReboot
            TimeZone            = $timeZoneInformation
            TLSSettings         = $tlsSettings
            ServerBootUp        = $serverBootUp
            VcRedistributable   = [array]$vcRedistributable
            RegistryValues      = $registryValues
            Smb1ServerSettings  = $smb1ServerSettings
            HotFixes            = $hotFixes
            NETFramework        = $netFrameworkInformation
        }
    }
}
