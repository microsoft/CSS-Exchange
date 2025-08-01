# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-JobOperatingSystemInformation {
    [CmdletBinding()]
    param()
    begin {
        # Extract for Pester Testing - Start
        # Build Process to add functions.
        . $PSScriptRoot\..\..\..\..\Shared\Get-ServerRebootPending.ps1
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
        # Extract for Pester Testing - End

        $jobStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $buildInformation = $null
        $currentDateTime = Get-Date
        $powerPlan = $null
        $pageFile = $null
        $networkInformation = $null
        $credentialGuardCimInstance = $false
        $counters = $null
        $serverPendingReboot = $null
        $timeZoneInformation = $null
        $tlsSettings = $null
        $vcRedistributable = $null
        $smb1ServerSettings = $null
        $registryValues = $null
        $eventLogInformation = $null
        $netFrameworkInformation = $null

        if ($PSSenderInfo) {
            $Script:ErrorsExcluded = @()
        }
    }
    process {

        Get-OperatingSystemBuildInformation | Invoke-RemotePipelineHandler -Result ([ref]$buildInformation)
        $lastBootUpTime = [Management.ManagementDateTimeConverter]::ToDateTime($buildInformation.OperatingSystem.LastBootUpTime)
        $serverBootUp = [PSCustomObject]@{
            Days    = ($currentDateTime - $lastBootUpTime).Days
            Hours   = ($currentDateTime - $lastBootUpTime).Hours
            Minutes = ($currentDateTime - $lastBootUpTime).Minutes
            Seconds = ($currentDateTime - $lastBootUpTime).Seconds
        }

        Get-PowerPlanSetting | Invoke-RemotePipelineHandler -Result ([ref]$powerPlan)
        Get-PageFileInformation | Invoke-RemotePipelineHandler -Result ([ref]$pageFile)
        Get-NetworkingInformation | Invoke-RemotePipelineHandler -Result ([ref]$networkInformation)

        try {
            $hotFixes = Get-HotFix -ErrorAction Stop #old school check still valid and faster and a failsafe
        } catch {
            Write-Verbose "Failed to run Get-HotFix"
            Invoke-CatchActions
        }

        try {
            $params = @{
                ClassName   = "Win32_DeviceGuard"
                Namespace   = "root\Microsoft\Windows\DeviceGuard"
                ErrorAction = "Stop"
            }
            $credentialGuardCimInstance = (Get-CimInstance @params).SecurityServicesRunning
        } catch {
            Write-Verbose "Failed to run Get-CimInstance for Win32_DeviceGuard"
            Invoke-CatchActions
            $credentialGuardCimInstance = "Unknown"
        }

        try {
            $windowsFeature = Get-WindowsFeature -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to run Get-WindowsFeature for the server $($env:COMPUTERNAME). Inner Exception: $_"
            Invoke-CatchActions
        }

        $params = @{
            MachineName       = $env:COMPUTERNAME
            Counter           = @(
                "\Hyper-V Dynamic Memory Integration Service\Maximum Memory, MBytes", # This is used to determine if dynamic memory is set on the Hyper-V machine.
                "\Processor(_Total)\% Processor Time",
                "\VM Memory\Memory Reservation in MB" # used to determine if dynamic memory is set on the VMware machine.
            )
            CustomErrorAction = "SilentlyContinue" # Required because not all counters would be there.
        }
        Get-LocalizedCounterSamples @params | Invoke-RemotePipelineHandler -Result ([ref]$counters)
        Get-ServerRebootPending -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$serverPendingReboot)
        Get-TimeZoneInformation -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$timeZoneInformation)
        Get-AllTlsSettings -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$tlsSettings)
        Get-VisualCRedistributableInstalledVersion -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$vcRedistributable)
        Get-Smb1ServerSettings -GetWindowsFeature $windowsFeature -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$smb1ServerSettings)
        Get-OperatingSystemRegistryValues -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$registryValues)
        Get-EventLogInformation -CatchActionFunction ${Function:Invoke-CatchActions} |
            Invoke-RemotePipelineHandler -Result ([ref]$eventLogInformation)
        Get-NETFrameworkInformation | Invoke-RemotePipelineHandler -Result ([ref]$netFrameworkInformation)

        if ($PSSenderInfo) {
            $jobHandledErrors = $Script:ErrorsExcluded
        }
    }
    end {
        Write-Verbose "Completed: $($MyInvocation.MyCommand) and took $($jobStopWatch.Elapsed.TotalSeconds) seconds"
        [PSCustomObject]@{
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
            RemoteJob                  = $true -eq $PSSenderInfo
            JobHandledErrors           = $jobHandledErrors
        }
    }
}
