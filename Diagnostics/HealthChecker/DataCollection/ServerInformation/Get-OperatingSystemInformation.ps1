# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ServerRebootPending.ps1
. $PSScriptRoot\..\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\Get-AllTlsSettingsFromRegistry.ps1
. $PSScriptRoot\Get-AllNicInformation.ps1
. $PSScriptRoot\Get-CredentialGuardEnabled.ps1
. $PSScriptRoot\Get-HttpProxySetting.ps1
. $PSScriptRoot\Get-LmCompatibilityLevelInformation.ps1
. $PSScriptRoot\Get-PageFileInformation.ps1
. $PSScriptRoot\Get-ServerOperatingSystemVersion.ps1
. $PSScriptRoot\Get-Smb1ServerSettings.ps1
. $PSScriptRoot\Get-TimeZoneInformationRegistrySettings.ps1
. $PSScriptRoot\Get-WmiObjectCriticalHandler.ps1
. $PSScriptRoot\Get-WmiObjectHandler.ps1
. $PSScriptRoot\..\..\Helpers\Get-CounterSamples.ps1
Function Get-OperatingSystemInformation {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    [HealthChecker.OperatingSystemInformation]$osInformation = New-Object HealthChecker.OperatingSystemInformation
    $win32_OperatingSystem = Get-WmiObjectCriticalHandler -ComputerName $Script:Server -Class Win32_OperatingSystem -CatchActionFunction ${Function:Invoke-CatchActions}
    $win32_PowerPlan = Get-WmiObjectHandler -ComputerName $Script:Server -Class Win32_PowerPlan -Namespace 'root\cimv2\power' -Filter "isActive='true'" -CatchActionFunction ${Function:Invoke-CatchActions}
    $currentDateTime = Get-Date
    $lastBootUpTime = [Management.ManagementDateTimeConverter]::ToDateTime($win32_OperatingSystem.lastbootuptime)
    $osInformation.BuildInformation.VersionBuild = $win32_OperatingSystem.Version
    $osInformation.BuildInformation.MajorVersion = (Get-ServerOperatingSystemVersion -OsCaption $win32_OperatingSystem.Caption)
    $osInformation.BuildInformation.FriendlyName = $win32_OperatingSystem.Caption
    $osInformation.BuildInformation.OperatingSystem = $win32_OperatingSystem
    $osInformation.ServerBootUp.Days = ($currentDateTime - $lastBootUpTime).Days
    $osInformation.ServerBootUp.Hours = ($currentDateTime - $lastBootUpTime).Hours
    $osInformation.ServerBootUp.Minutes = ($currentDateTime - $lastBootUpTime).Minutes
    $osInformation.ServerBootUp.Seconds = ($currentDateTime - $lastBootUpTime).Seconds

    if ($null -ne $win32_PowerPlan) {

        if ($win32_PowerPlan.InstanceID -eq "Microsoft:PowerPlan\{8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}") {
            Write-Verbose "High Performance Power Plan is set to true"
            $osInformation.PowerPlan.HighPerformanceSet = $true
        } else { Write-Verbose "High Performance Power Plan is NOT set to true" }
        $osInformation.PowerPlan.PowerPlanSetting = $win32_PowerPlan.ElementName
    } else {
        Write-Verbose "Power Plan Information could not be read"
        $osInformation.PowerPlan.PowerPlanSetting = "N/A"
    }
    $osInformation.PowerPlan.PowerPlan = $win32_PowerPlan
    $osInformation.PageFile = Get-PageFileInformation
    $osInformation.NetworkInformation.NetworkAdapters = (Get-AllNicInformation -ComputerName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions} -ComputerFQDN $Script:ServerFQDN)
    foreach ($adapter in $osInformation.NetworkInformation.NetworkAdapters) {

        if (!$adapter.IPv6Enabled) {
            $osInformation.NetworkInformation.IPv6DisabledOnNICs = $true
            break
        }
    }

    $osInformation.NetworkInformation.IPv6DisabledComponents = Get-RemoteRegistryValue -MachineName $Script:Server `
        -SubKey "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
        -GetValue "DisabledComponents" `
        -ValueType "DWord" `
        -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.NetworkInformation.TCPKeepAlive = Get-RemoteRegistryValue -MachineName $Script:Server `
        -SubKey "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -GetValue "KeepAliveTime" `
        -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.NetworkInformation.RpcMinConnectionTimeout = Get-RemoteRegistryValue -MachineName $Script:Server `
        -SubKey "Software\Policies\Microsoft\Windows NT\RPC\" `
        -GetValue "MinimumConnectionTimeout" `
        -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.NetworkInformation.HttpProxy = Get-HttpProxySetting
    $osInformation.InstalledUpdates.HotFixes = (Get-HotFix -ComputerName $Script:Server -ErrorAction SilentlyContinue) #old school check still valid and faster and a failsafe
    $osInformation.LmCompatibility = Get-LmCompatibilityLevelInformation
    $counterSamples = (Get-CounterSamples -MachineNames $Script:Server -Counters "\Network Interface(*)\Packets Received Discarded")

    if ($null -ne $counterSamples) {
        $osInformation.NetworkInformation.PacketsReceivedDiscarded = $counterSamples
    }

    $osInformation.ServerPendingReboot = (Get-ServerRebootPending -ServerName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions})
    $timeZoneInformation = Get-TimeZoneInformationRegistrySettings -MachineName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.TimeZone.DynamicDaylightTimeDisabled = $timeZoneInformation.DynamicDaylightTimeDisabled
    $osInformation.TimeZone.TimeZoneKeyName = $timeZoneInformation.TimeZoneKeyName
    $osInformation.TimeZone.StandardStart = $timeZoneInformation.StandardStart
    $osInformation.TimeZone.DaylightStart = $timeZoneInformation.DaylightStart
    $osInformation.TimeZone.DstIssueDetected = $timeZoneInformation.DstIssueDetected
    $osInformation.TimeZone.ActionsToTake = $timeZoneInformation.ActionsToTake
    $osInformation.TimeZone.CurrentTimeZone = Invoke-ScriptBlockHandler -ComputerName $Script:Server `
        -ScriptBlock { ([System.TimeZone]::CurrentTimeZone).StandardName } `
        -ScriptBlockDescription "Getting Current Time Zone" `
        -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.TLSSettings = Get-AllTlsSettingsFromRegistry -MachineName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.VcRedistributable = Get-VisualCRedistributableInstalledVersion -ComputerName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions}
    $osInformation.CredentialGuardEnabled = Get-CredentialGuardEnabled
    $osInformation.RegistryValues.CurrentVersionUbr = Get-RemoteRegistryValue `
        -MachineName $Script:Server `
        -SubKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
        -GetValue "UBR" `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    $osInformation.RegistryValues.LanManServerDisabledCompression = Get-RemoteRegistryValue `
        -MachineName $Script:Server `
        -SubKey "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -GetValue "DisableCompression" `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    $osInformation.Smb1ServerSettings = Get-Smb1ServerSettings -ServerName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions}

    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    return $osInformation
}
