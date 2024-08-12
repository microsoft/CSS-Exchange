# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-ServerRebootPending.ps1
. $PSScriptRoot\..\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\TLS\Get-AllTlsSettings.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-AllNicInformation.ps1
. $PSScriptRoot\Get-EventLogInformation.ps1
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

        try {
            $hotFixes = (Get-HotFix -ComputerName $Server -ErrorAction Stop) #old school check still valid and faster and a failsafe
        } catch {
            Write-Verbose "Failed to run Get-HotFix"
            Invoke-CatchActions
        }

        $credentialGuardCimInstance = $false
        try {
            $params = @{
                ClassName    = "Win32_DeviceGuard"
                Namespace    = "root\Microsoft\Windows\DeviceGuard"
                ErrorAction  = "Stop"
                ComputerName = $Server
            }
            $credentialGuardCimInstance = (Get-CimInstance @params).SecurityServicesRunning
        } catch {
            Write-Verbose "Failed to run Get-CimInstance for Win32_DeviceGuard"
            Invoke-CatchActions
            $credentialGuardCimInstance = "Unknown"
        }

        try {
            $windowsFeature = Get-WindowsFeature -ComputerName $Server -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to run Get-WindowsFeature for the server $server. Inner Exception: $_"
            Invoke-CatchActions
        }

        $params = @{
            MachineName       = $Server
            Counter           = @(
                "\Hyper-V Dynamic Memory Integration Service\Maximum Memory, MBytes", # This is used to determine if dynamic memory is set on the Hyper-V machine.
                "\Processor(_Total)\% Processor Time",
                "\VM Memory\Memory Reservation in MB" # used to determine if dynamic memory is set on the VMware machine.
            )
            CustomErrorAction = "SilentlyContinue" # Required because not all counters would be there.
        }

        $counters = Get-LocalizedCounterSamples @params
        $serverPendingReboot = (Get-ServerRebootPending -ServerName $Server -CatchActionFunction ${Function:Invoke-CatchActions})
        $timeZoneInformation = Get-TimeZoneInformation -MachineName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $tlsSettings = Get-AllTlsSettings -MachineName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $vcRedistributable = Get-VisualCRedistributableInstalledVersion -ComputerName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $smb1ServerSettings = Get-Smb1ServerSettings -ServerName $Server -GetWindowsFeature $windowsFeature -CatchActionFunction ${Function:Invoke-CatchActions}
        $registryValues = Get-OperatingSystemRegistryValues -MachineName $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $eventLogInformation = Get-EventLogInformation -Server $Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $netFrameworkInformation = Get-NETFrameworkInformation -Server $Server
    } end {
        Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
        return [PSCustomObject]@{
            BuildInformation           = $buildInformation
            NetworkInformation         = $networkInformation
            PowerPlan                  = $powerPlan
            PageFile                   = $pageFile
            ServerPendingReboot        = $serverPendingReboot
            TimeZone                   = $timeZoneInformation
            TLSSettings                = $tlsSettings
            ServerBootUp               = $serverBootUp
            VcRedistributable          = [array]$vcRedistributable
            RegistryValues             = $registryValues
            Smb1ServerSettings         = $smb1ServerSettings
            HotFixes                   = $hotFixes
            NETFramework               = $netFrameworkInformation
            CredentialGuardCimInstance = $credentialGuardCimInstance
            WindowsFeature             = $windowsFeature
            EventLogInformation        = $eventLogInformation
            PerformanceCounters        = $counters
        }
    }
}
