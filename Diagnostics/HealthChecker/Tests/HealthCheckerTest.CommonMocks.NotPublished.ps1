# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

#region Script Functions

Mock Invoke-DefaultConnectExchangeShell -MockWith { return }

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
        default { throw "Failed to find class" }
    }
}

Mock GetCurrentTimeZone -MockWith { return "Pacific Standard Time" }
Mock GetProcessorCount -MockWith { return 4 }

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
        "ProductName" { return Import-Clixml "$Script:MockDataCollectionRoot\OS\RemoteRegistryValueProductName.xml" }
        "InstallationType" { return Import-Clixml "$Script:MockDataCollectionRoot\OS\RemoteRegistryValueInstallationType.xml" }
        "DisableCompression" { return 0 }
        "CtsProcessorAffinityPercentage" { return 0 }
        "Enabled" { return 0 }
        "DisableGranularReplication" { return 0 }
        "DisableAsyncNotification" { return 0 }
        "MsiInstallPath" { return "C:\Program Files\Microsoft\Exchange Server\V15" }
        "AllowInsecureRenegoClients" { return 0 }
        "AllowInsecureRenegoServers" { return 0 }
        "EnableSerializationDataSigning" { return 0 }
        "LsaCfgFlags" { return 0 }
        "DynamicDaylightTimeDisabled" { return 0 }
        "TimeZoneKeyName" { return "Pacific Standard Time" }
        "StandardStart" { return @(0, 0, 11, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0) }
        "DaylightStart" { return @(0, 0, 3, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0) }
        "DisableBaseTypeCheckForDeserialization" { return $null }
        "DisablePreservation" { return 0 }
        "DisableRootAutoUpdate" { return $null }
        "DatabasePath" { return "$Script:MockDataCollectionRoot\Exchange" }
        "SuppressExtendedProtection" { return 0 }
        "EnableEccCertificateSupport" { return $null }
        "ProductName" { return "Windows Server 2019" }
        "ReleaseID" { return 2009 }
        "CurrentBuild" { return 26100 }
        default { throw "Failed to find GetValue: $GetValue" }
    }
}

Mock Get-RemoteRegistrySubKey {
    param(
        [string]$MachineName,
        [string]$SubKey
    )

    switch ($SubKey) {
        "SOFTWARE\Microsoft\Updates\Exchange 2013" { return $null }
        "SOFTWARE\Microsoft\Updates\Exchange 2016" { return $null }
        "SOFTWARE\Microsoft\Updates\Exchange 2019" { return $null }
        default { throw "Failed to find SubKey: $SubKey" }
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

Mock Get-LocalizedCounterSamples -ParameterFilter { $Counter -eq "\Network Interface(*)\Packets Received Discarded" } `
    -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetCounterSamples.xml" }
Mock Get-LocalizedCounterSamples {
    $objList = New-Object System.Collections.Generic.List[object]
    $objList.Add(([PSCustomObject]@{
                OriginalCounterLookup = "\Processor(_Total)\% Processor Time"
                CookedValue           = 55.55555
            }))
    $objList.Add(([PSCustomObject]@{
                OriginalCounterLookup = "\Hyper-V Dynamic Memory Integration Service\Maximum Memory, MBytes"
                CookedValue           = 6144
            }))
    return $objList
}

Mock Get-ServerRebootPending {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetServerRebootPending.xml"
}

Mock Get-AllTlsSettings {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetAllTlsSettings.xml"
}

Mock Get-VisualCRedistributableInstalledVersion {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetVisualCRedistributableInstalledVersion.xml"
}

Mock Get-ExchangeAppPoolsInformation {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeAppPoolsInformation.xml"
}

Mock Get-ExchangeAdSchemaClass -ParameterFilter { $SchemaClassName -eq "ms-Exch-Storage-Group" } {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeAdSchemaClass_ms-Exch-Storage-Group.xml"
}

Mock Get-ExchangeAdSchemaClass -ParameterFilter { $SchemaClassName -eq "ms-Exch-Schema-Version-Pt" } {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeAdSchemaClass_ms-Exch-Schema-Version-Pt.xml"
}

Mock Get-ExchangeDomainsAclPermissions {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeDomainsAclPermissions.xml"
}

Mock Get-ExchangeWellKnownSecurityGroups {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeWellKnownSecurityGroups.xml"
}

# Builds an object shaped like a System.DirectoryServices.SearchResult so the real
# Get-ExchangeLegacySecurityGroups parsing logic (scope decode, member count, DN handling) is tested.
# An absent 'member' (empty array) mimics the GC not replicating membership for Global/Domain Local groups.
function NewMockAdSearchResult {
    [CmdletBinding()]
    param(
        [string]$DistinguishedName,
        [string]$SamAccountName,
        [int]$GroupType,
        [int]$MemberCount = 0
    )

    $members = @()
    if ($MemberCount -gt 0) {
        $members = @(1..$MemberCount | ForEach-Object { "CN=Member$_,CN=Users,DC=contoso,DC=com" })
    }

    return [PSCustomObject]@{
        Properties = @{
            distinguishedName = @($DistinguishedName)
            sAMAccountName    = @($SamAccountName)
            groupType         = @($GroupType)
            member            = $members
        }
    }
}

# Default: the legacy Exchange security groups are not present. Specific tests override this with a
# -ParameterFilter on $Filter to return mock search results for the legacy groups query.
Mock Search-AllActiveDirectoryDomains {
    return @()
}

Mock Get-HttpProxySetting {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetHttpProxySetting.xml"
}

Mock Get-FIPFSScanEngineVersionState {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetFIPFSScanEngineVersionState.xml"
}

Mock Get-ExchangeADSplitPermissionsEnabled {
    return $false
}

Mock Get-ExchangeProtocolContainer {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeProtocolContainer.xml"
}

Mock Get-ExSetupFileVersionInfo {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\ExSetup.xml"
}

Mock GetExchangeServerADInformation {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeServerADInformation.xml"
}

# Do nothing
Mock Invoke-CatchActions { }

#endregion Script Functions

#region OS Cmdlets

Mock Get-WinEvent -ParameterFilter { $LogName -eq "Application" -and $Oldest -eq $true -and $MaxEvents -eq 1 } -MockWith {
    $r = Import-Clixml "$Script:MockDataCollectionRoot\OS\GetWinEventOldestApplication.xml"
    $r.TimeCreated = ((Get-Date).AddDays(-8))
    return $r
}
Mock Get-WinEvent -ParameterFilter { $LogName -eq "System" -and $Oldest -eq $true -and $MaxEvents -eq 1 } -MockWith {
    $r = Import-Clixml "$Script:MockDataCollectionRoot\OS\GetWinEventOldestSystem.xml"
    $r.TimeCreated = ((Get-Date).AddDays(-8))
    return $r
}
Mock Get-WinEvent -ParameterFilter { $ListLog -eq "Application" } -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetWinEventApplication.xml" }
Mock Get-WinEvent -ParameterFilter { $ListLog -eq "System" } -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetWinEventSystem.xml" }

Mock Get-CimInstance -ParameterFilter { $ClassName -eq "Win32_DeviceGuard" } -MockWith { return [PSCustomObject]@{ SecurityServicesRunning = @(0 , 0) } }

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

Mock Get-SmbServerConfiguration {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetSmbServerConfiguration.xml"
}

# Needs to be a function stub as PS core doesn't have -ComputerName parameter
function Get-Service {
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [string]$Name
    )
    throw "no mock detected"
}

Mock Get-Service -ParameterFilter { $Name -eq "MSExchangeMitigation" } -MockWith {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetServiceMitigation.xml"
}
Mock Get-Service {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetService.xml"
}

function Get-WindowsFeature { throw "no mock detected" }
Mock Get-WindowsFeature {
    return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetWindowsFeature.xml"
}

Mock Get-LocalGroupMember {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetLocalGroupMember.xml"
}

#endregion OS Cmdlets

#region IIS Functions

function Get-WebSite { param($Name) }
Mock Get-WebSite -ParameterFilter { $null -eq $Name } -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\IIS\GetWebSite.xml" }

Mock Test-Path -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\SharedWebConfig.config" } -MockWith { return $true }
Mock Test-Path -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess\SharedWebConfig.config" } -MockWith { return $true }
Mock Test-Path -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\EdgeTransport.exe.config" } -MockWith { return $true }
Mock Test-Path -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\Runtime\1.0\noderunner.exe.config" } -MockWith { return $true }
Mock Test-Path -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\Monitoring\Config\AntiMalware.xml" } -MockWith { return $true }

Mock Get-Content -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\SharedWebConfig.config" } -MockWith { Get-Content "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite_SharedWebConfig.config" -Raw -Encoding UTF8 }
Mock Get-Content -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess\SharedWebConfig.config" } -MockWith { Get-Content "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd_SharedWebConfig.config" -Raw -Encoding UTF8 }
Mock Get-Content -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\EdgeTransport.exe.config" } -MockWith { Get-Content "$Script:MockDataCollectionRoot\Exchange\EdgeTransport.exe.config" -Raw -Encoding UTF8 }
Mock Get-Content -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\Runtime\1.0\noderunner.exe.config" } -MockWith { Get-Content "$Script:MockDataCollectionRoot\Exchange\noderunner.exe.config" -Raw -Encoding UTF8 }
Mock Get-Content -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\Monitoring\Config\AntiMalware.xml" } -MockWith { Get-Content "$Script:MockDataCollectionRoot\Exchange\AntiMalware.xml" -Raw -Encoding UTF8 }
Mock Get-Content -ParameterFilter { $Path -eq "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config" } -MockWith { return Get-Content "$Script:MockDataCollectionRoot\Exchange\IIS\applicationHost.config" -Raw -Encoding UTF8 }

function Get-WebApplication { throw "no mock detected" }
Mock Get-WebApplication { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\IIS\GetWebApplication.xml" }

function Get-WebBinding { throw "no mock detected" }
Mock Get-WebBinding { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\IIS\GetWebBinding.xml" }

function Get-WebConfigFile {
    param (
        [string[]]$PSPath
    )
    throw "no mock detected"
}

Mock Get-WebConfigFile {
    # return the object with FullName as that is all it is used for pointing to the file we want to test against
    switch ($PSPath) {
        "IIS:\Sites\Default Web Site" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite_web.config" } }
        "IIS:\Sites\Exchange Back End" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\applicationHost.config" } }
        "IIS:\Sites\Default Web Site/API" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite-Rest_web.config" } }
        { $_ -like "IIS:\Sites\Default Web Site/owa*" } { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite-OWA_web.config" } }
        "IIS:\Sites\Default Web Site/ecp" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite-ECP_web.config" } }
        "IIS:\Sites\Default Web Site/EWS" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite-EWS_web.config" } }
        "IIS:\Sites\Default Web Site/Autodiscover" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite-AutoD_web.config" } }
        "IIS:\Sites\Default Web Site/Microsoft-Server-ActiveSync" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite-EAS_web.config" } }
        "IIS:\Sites\Default Web Site/OAB" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite-OAB_web.config" } }
        "IIS:\Sites\Default Web Site/PowerShell" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite-PowerShell_web.config" } }
        "IIS:\Sites\Default Web Site/mapi" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite-MAPI_web.config" } }
        "IIS:\Sites\Default Web Site/rpc" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite-rpc_web.config" } }
        "IIS:\Sites\Exchange Back End/API" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-Rest_web.config" } }
        "IIS:\Sites\Exchange Back End/PowerShell" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-PowerShell_web.config" } }
        "IIS:\Sites\Exchange Back End/mapi/emsmdb" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-MapiEmsmdb_web.config" } }
        "IIS:\Sites\Exchange Back End/mapi/nspi" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-MapiNspi_web.config" } }
        "IIS:\Sites\Exchange Back End/PushNotifications" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-Push_web.config" } }
        { $_ -like "IIS:\Sites\Exchange Back End/owa*" } { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-OWA_web.config" } }
        "IIS:\Sites\Exchange Back End/OAB" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-OAB_web.config" } }
        "IIS:\Sites\Exchange Back End/ecp" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-Ecp_web.config" } }
        { $_ -like "IIS:\Sites\Exchange Back End/Autodiscover*" } { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-AutoD_web.config" } }
        "IIS:\Sites\Exchange Back End/Microsoft-Server-ActiveSync" { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-EAS_web.config" } }
        { $_ -like "IIS:\Sites\Exchange Back End/EWS*" } { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-EWS_web.config" } }
        { $_ -like "IIS:\Sites\Exchange Back End/Rpc*" } { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ExchangeBackEnd-Rpc_web.config" } }
        default { throw "Failed to find $PSPath" }
    }
}

Mock GetCachtoknVersionInfo -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\IIS\GetVersionInformationCachTokn.xml" }

Mock Get-IISModules {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetIISModules.xml"
}

#endregion IIS Functions

#region Exchange Cmdlets

function Get-ExchangeDiagnosticInfo { param($Argument, $Component, $Process, $Server) }

Mock Get-ExchangeDiagnosticInfo -ParameterFilter { $Process -eq "Microsoft.Exchange.Directory.TopologyService" -and $Component -eq "VariantConfiguration" -and $Argument -eq "Overrides" } `
    -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeDiagnosticInfo_ADTopVariantConfiguration.xml" }
Mock Get-ExchangeDiagnosticInfo -ParameterFilter { $Process -eq "EdgeTransport" -and $Component -eq "ResourceThrottling" } `
    -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeDiagnosticInfo_EdgeTransportResourceThrottling.xml" }

function Get-ExchangeServer { throw "no mock detected" }
Mock Get-ExchangeServer {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeServer.xml"
}

function Get-ExchangeCertificate { throw "no mock detected" }
Mock Get-ExchangeCertificate {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeCertificate.xml"
}

function Get-AuthConfig { throw "no mock detected" }
Mock Get-AuthConfig {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetAuthConfig.xml"
}

function Get-MailboxServer { throw "no mock detected" }
Mock Get-MailboxServer {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetMailboxServer.xml"
}

function Get-OwaVirtualDirectory { throw "no mock detected" }
Mock Get-OwaVirtualDirectory {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOwaVirtualDirectory.xml"
}

function Get-WebServicesVirtualDirectory { throw "no mock detected" }
Mock Get-WebServicesVirtualDirectory {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetWebServicesVirtualDirectory.xml"
}

function Get-OrganizationConfig { throw "no mock detected" }
Mock Get-OrganizationConfig {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOrganizationConfig.xml"
}

function Get-DynamicDistributionGroup { throw "no mock detected" }
Mock Get-DynamicDistributionGroup {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetDynamicDistributionGroupPfMailboxes.xml"
}

function Get-IRMConfiguration { throw "no mock detected" }
Mock Get-IRMConfiguration {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetIrmConfiguration.xml"
}

function Get-ActiveSyncVirtualDirectory { throw "no mock detected" }
Mock Get-ActiveSyncVirtualDirectory { return $null }

function Get-AutodiscoverVirtualDirectory { throw "no mock detected" }
Mock Get-AutodiscoverVirtualDirectory { return $null }

function Get-EcpVirtualDirectory { throw "no mock detected" }
Mock Get-EcpVirtualDirectory { return $null }

function Get-MapiVirtualDirectory { throw "no mock detected" }
Mock Get-MapiVirtualDirectory { return $null }

function Get-OutlookAnywhere { throw "no mock detected" }
Mock Get-OutlookAnywhere { return $null }

function Get-PowerShellVirtualDirectory { throw "no mock detected" }
Mock Get-PowerShellVirtualDirectory { return $null }

function Get-HybridConfiguration { throw "no mock detected" }
Mock Get-HybridConfiguration { return $null }

function Get-PartnerApplication { throw "no mock detected" }
Mock Get-PartnerApplication { return $null }

function Get-ServerComponentState { throw "no mock detected" }
Mock Get-ServerComponentState {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetServerComponentState.xml"
}

function Test-ServiceHealth { throw "no mock detected" }
Mock Test-ServiceHealth {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\TestServiceHealth.xml"
}

function Get-SettingOverride { throw "no mock detected" }
Mock Get-SettingOverride {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetSettingOverride.xml"
}

function Get-AcceptedDomain { throw "no mock detected" }
Mock Get-AcceptedDomain {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetAcceptedDomain.xml"
}

function Get-ReceiveConnector { throw "no mock detected" }
Mock Get-ReceiveConnector {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetReceiveConnector.xml"
}

function Get-SendConnector { throw "no mock detected" }
Mock Get-SendConnector {
    return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetSendConnector.xml"
}

function Get-GlobalMonitoringOverride { throw "no mock detected" }
Mock Get-GlobalMonitoringOverride { return $null }

function Get-ServerMonitoringOverride { throw "no mock detected" }
Mock Get-ServerMonitoringOverride { return $null }

function Get-TransportService {
    param($Identity)
    throw "no mock detected"
}

Mock Get-TransportService {
    $data = Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetTransportService.xml"

    # Deserialized Exchange types (Unlimited<Int32>, etc.) can't be cast to native types
    # on the original object due to retained type constraints. Build a fresh PSCustomObject
    # copying all properties, then override the problematic ones with correct types.
    $fixedProps = @{
        InternalTransportCertificateThumbprint = [string]$data.InternalTransportCertificateThumbprint
        MaxPerDomainOutboundConnections        = [int]([string]$data.MaxPerDomainOutboundConnections)
        MessageRetryInterval                   = [System.TimeSpan]::Parse([string]$data.MessageRetryInterval)
    }

    $hash = [ordered]@{}
    foreach ($prop in $data.PSObject.Properties) {
        if ($fixedProps.ContainsKey($prop.Name)) {
            $hash[$prop.Name] = $fixedProps[$prop.Name]
        } else {
            $hash[$prop.Name] = $prop.Value
        }
    }

    return [PSCustomObject]$hash
}

function Get-AuthServer { throw "no mock detected" }

# Set to "ACS" in test scenarios to simulate missing EvoSTS auth server
$Script:GetAuthServerMockDataType = "All"

Mock Get-AuthServer {
    $returnListObject = New-Object System.Collections.Generic.List[object]

    $orgId = $((New-Guid).Guid)
    $tenantId = $((New-Guid).Guid)
    $applicationId = $((New-Guid).Guid)

    $acs = [PSCustomObject]@{
        Name                           = "ACS - $orgId"
        Id                             = "ACS - $orgId"
        IssuerIdentifier               = "00000001-0000-0000-c000-000000000000"
        Realm                          = $tenantId
        TokenIssuingEndpoint           = "https://accounts.accesscontrol.windows.net/$tenantId/tokens/OAuth/2"
        AuthorizationEndpoint          = $null
        ApplicationIdentifier          = $null
        AuthMetadataUrl                = "https://accounts.accesscontrol.windows.net/$tenantId/metadata/json/1"
        DomainName                     = @("contoso.mail.onmicrosoft.com", "contoso.com")
        Type                           = "MicrosoftACS"
        Enabled                        = $true
        IsDefaultAuthorizationEndpoint = $false
    }

    $evoSts = [PSCustomObject]@{
        Name                           = "EvoSts - $orgId"
        Id                             = "EvoSts - $orgId"
        IssuerIdentifier               = "https://sts.windows.net/$tenantId/"
        Realm                          = $tenantId
        TokenIssuingEndpoint           = "https://login.windows.net/common/oauth2/token"
        AuthorizationEndpoint          = "https://login.windows.net/common/oauth2/authorize"
        ApplicationIdentifier          = $applicationId
        AuthMetadataUrl                = "https://login.windows.net/$tenantId/federationmetadata/2007-06/federationmetadata.xml"
        DomainName                     = @("contoso.mail.onmicrosoft.com")
        Type                           = "AzureAD"
        Enabled                        = $true
        IsDefaultAuthorizationEndpoint = $true
    }

    switch ($Script:GetAuthServerMockDataType) {
        "ACS" { $returnListObject.Add($acs) }
        "All" { $returnListObject.AddRange(@($acs, $evoSts)) }
    }

    return $returnListObject
}

#endregion Exchange Cmdlets
