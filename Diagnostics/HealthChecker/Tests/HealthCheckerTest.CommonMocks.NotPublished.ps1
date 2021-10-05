# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

Mock Get-WmiObjectHandler {
    param (
        [string]$ComputerName,
        [string]$Class,
        [string]$Filter,
        [string]$Namespace
    )

    switch ($Class) {
        "Win32_ComputerSystem" { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\HyperV_Win32_ComputerSystem.xml" }
        "Win32_PhysicalMemory" { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\HyperV_Win32_PhysicalMemory.xml" }
        "Win32_Processor" { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\HyperV_Win32_Processor.xml" }
        "Win32_OperatingSystem" { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_OperatingSystem.xml" }
        "Win32_PowerPlan" { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PowerPlan.xml" }
        "Win32_PageFileSetting" { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PageFileSetting.xml" }
        "Win32_NetworkAdapterConfiguration" { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_NetworkAdapterConfiguration.xml" }
        "Win32_NetworkAdapter" { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_NetworkAdapter.xml" }
        Default { throw "Failed to find class" }
    }
}

Mock Invoke-ScriptBlockHandler -ParameterFilter { $ScriptBlockDescription -eq "Trying to get the System.Environment ProcessorCount" } -MockWith { return 4 }
Mock Invoke-ScriptBlockHandler -ParameterFilter { $ScriptBlockDescription -eq "Getting Current Time Zone" } -MockWith { return "Pacific Standard Time" }
Mock Invoke-ScriptBlockHandler -ParameterFilter { $ScriptBlockDescription -eq "Test EEMS pattern service connectivity" } -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\WebRequest_getexchangemitigations.xml" }
Mock Invoke-ScriptBlockHandler -ParameterFilter { $ScriptBlockDescription -eq "Getting Exchange Bin Directory" } -MockWith { return "hi" }


Mock Get-RemoteRegistryValue {
    param(
        [string]$SubKey,
        [string]$GetValue
    )

    switch ($GetValue) {
        "DisabledComponents" { return $null }
        "KeepAliveTime" { return 90000 }
        "MinimumConnectionTimeout" { return 0 }
        "LmCompatibilityLevel" { return $null }
        "UBR" { return 720 }
        "DisableCompression" { return 0 }
        "CtsProcessorAffinityPercentage" { return 0 }
        "Enabled" { return 0 }
        Default { throw "Failed to find GetValue: $GetValue" }
    }
}

Mock Get-NETFrameworkVersion {
    return [PSCustomObject]@{
        FriendlyName  = "4.8"
        RegistryValue = 528040
        MinimumValue  = 528040
    }
}

Mock Get-DotNetDllFileVersions {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetDotNetDllFileVersions.xml"
}

Mock Get-NicPnpCapabilitiesSetting {
    return [PSCustomObject]@{
        PnPCapabilities   = 24
        SleepyNicDisabled = $true
    }
}

Mock Get-NetIPConfiguration {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetNetIPConfiguration.xml"
}

Mock Get-DnsClient {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetDnsClient.xml"
}

Mock Get-NetAdapterRss {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetNetAdapterRss.xml"
}

Mock Get-HotFix {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetHotFix.xml"
}

Mock Get-CounterSamples {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetCounterSamples.xml"
}

Mock Get-ServerRebootPending {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetServerRebootPending.xml"
}

Mock Get-TimeZoneInformationRegistrySettings {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetTimeZoneInformationRegistrySettings.xml"
}

Mock Get-AllTlsSettingsFromRegistry {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetAllTlsSettingsFromRegistry.xml"
}

Mock Get-VisualCRedistributableInstalledVersion {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetVisualCRedistributableInstalledVersion.xml"
}

Mock Get-CredentialGuardEnabled {
    return $false
}

Mock Get-Smb1ServerSettings {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetSmb1ServerSettings.xml"
}

Mock Get-ExchangeAppPoolsInformation {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeAppPoolsInformation.xml"
}

Mock Get-ExchangeApplicationConfigurationFileValidation {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeApplicationConfigurationFileValidation.xml"
}

Mock Get-ExchangeUpdates {
    return $null
}

Mock Get-ExchangeAdSchemaClass {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeAdSchemaClass_ms-Exch-Storage-Group.xml"
}

Mock Get-HttpProxySetting {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetHttpProxySetting.xml"
}

# Do nothing
Mock Invoke-CatchActions { }

# Need to use function instead of Mock for Exchange cmdlets
Function Get-ExchangeServer {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeServer.xml"
}

Function Get-ExchangeCertificate {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeCertificate.xml"
}

Function Get-AuthConfig {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetAuthConfig.xml"
}

Function Get-ExSetupDetails {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\ExSetup.xml"
}

Function Get-MailboxServer {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetMailboxServer.xml"
}

Function Get-OwaVirtualDirectory {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOwaVirtualDirectory.xml"
}

Function Get-WebServicesVirtualDirectory {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetWebServicesVirtualDirectory.xml"
}

Function Get-OrganizationConfig {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOrganizationConfig.xml"
}

Function Get-HybridConfiguration { return $null }

# Needs to be a function as PS core doesn't have -ComputerName parameter
Function Get-Service {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetServiceMitigation.xml"
}

Function Get-ServerComponentState {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetServerComponentState.xml"
}

Function Test-ServiceHealth {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\TestServiceHealth.xml"
}
