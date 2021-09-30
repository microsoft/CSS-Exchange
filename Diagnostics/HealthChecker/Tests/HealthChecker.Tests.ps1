# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    . $PSScriptRoot\..\..\..\.build\BuildFunctions\Get-ExpandedScriptContent.ps1
    . $PSScriptRoot\..\Helpers\Class.ps1
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:PesterExtract = "# Extract for Pester Testing - Start"
}

Describe "Testing Analyzer" {

    BeforeAll {

        $scriptContent = Get-ExpandedScriptContent -File "$Script:parentPath\Analyzer\Invoke-AnalyzerEngine.ps1"
        $scriptContentString = [string]::Empty
        $scriptContent | ForEach-Object { $scriptContentString += "$($_)`n" }
        Invoke-Expression $scriptContentString

        $internalFunctions = New-Object 'System.Collections.Generic.List[string]'
        $scriptContent = Get-ExpandedScriptContent -File "$Script:parentPath\DataCollection\ExchangeInformation\Get-HealthCheckerExchangeServer.ps1"
        $startIndex = $scriptContent.Trim().IndexOf($Script:PesterExtract)
        for ($i = $startIndex + 1; $i -lt $scriptContent.Count; $i++) {
            if ($scriptContent[$i].Trim().Contains($Script:PesterExtract.Replace("Start", "End"))) {
                $endIndex = $i
                break
            }
            $internalFunctions.Add($scriptContent[$i])
        }

        $scriptContent.RemoveRange($startIndex, $endIndex - $startIndex)
        $scriptContentString = [string]::Empty
        $internalFunctionsString = [string]::Empty
        $scriptContent | ForEach-Object { $scriptContentString += "$($_)`n" }
        $internalFunctions | ForEach-Object { $internalFunctionsString += "$($_)`n" }
        Invoke-Expression $scriptContentString
        Invoke-Expression $internalFunctionsString

        Function SetActiveDisplayGrouping {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true, Position = 1)]
                [string]$Name
            )
            $key = $Script:results.DisplayResults.Keys | Where-Object { $_.Name -eq $Name }
            $Script:ActiveGrouping = $Script:results.DisplayResults[$key]
        }

        Function GetObject {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true, Position = 1)]
                [string]$Name
            )

            ($Script:ActiveGrouping | Where-Object { $_.Name -eq $Name }).TestingValue
        }

        Function GetWriteTypeObject {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true, Position = 1)]
                [string]$Name
            )

            ($Script:ActiveGrouping | Where-Object { $_.Name -eq $Name }).WriteType
        }

        Function TestObjectMatch {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true, Position = 1)]
                [string]$Name,

                [Parameter(Mandatory = $true, Position = 2)]
                [object]$ResultValue,

                [Parameter(Position = 3)]
                [string]$WriteType = "Grey"
            )

            GetObject $Name |
                Should -Be $ResultValue
            GetWriteTypeObject $Name |
                Should -Be $WriteType
        }
    }

    Context "Basic Exchange 2019 CU11 Testing" {
        BeforeAll {
            $Script:Server = $env:COMPUTERNAME
            $Script:MockDataCollectionRoot = "$Script:parentPath\Tests\DataCollection"

            Function Invoke-CatchActions {}

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
            Mock Invoke-ScriptBlockHandler -ParameterFilter { $ScriptBlockDescription -like "Getting * Http Proxy Value" } -MockWith { return "<None>" }
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

            $hc = Get-HealthCheckerExchangeServer
            $hc | Export-Clixml Debug_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc
        }

        It "Display Results - Exchange Information" {
            SetActiveDisplayGrouping "Exchange Information"

            TestObjectMatch "Name" $env:COMPUTERNAME
            TestObjectMatch "Version" "Exchange 2019 CU11"
            TestObjectMatch "Build Number" "15.2.986.5"
            TestObjectMatch "Server Role" "Mailbox"
            TestObjectMatch "DAG Name" "Standalone Server"
            TestObjectMatch "AD Site" "Default-First-Site-Name"
            TestObjectMatch "MAPI/HTTP Enabled" $true
            TestObjectMatch "Exchange Server Maintenance" "Server is not in Maintenance Mode" -WriteType "Green"
            $Script:ActiveGrouping.Count | Should -Be 9
        }

        It "Display Results - Operating System Information" {
            SetActiveDisplayGrouping "Operating System Information"

            TestObjectMatch "Version" "Microsoft Windows Server 2019 Datacenter"
            TestObjectMatch "Time Zone" "Pacific Standard Time"
            TestObjectMatch "Dynamic Daylight Time Enabled" $true
            TestObjectMatch ".NET Framework" "4.8" -WriteType "Green"
            TestObjectMatch "Power Plan" "Balanced --- Error" -WriteType "Red"
            TestObjectMatch "Http Proxy Setting" "<None>"
            TestObjectMatch "Visual C++ 2012" "184610406 Version is current" -WriteType "Green"
            TestObjectMatch "Visual C++ 2013" "Redistributable is outdated" -WriteType "Yellow"
            TestObjectMatch "Server Pending Reboot" $false

            $pageFile = GetObject "Page File Size"
            $pageFile.TotalPhysicalMemory | Should -Be 6442450944
            $pageFile.MaxPageSize | Should -Be 0
            $pageFile.MultiPageFile | Should -Be $false
            $pageFile.RecommendedPageFile | Should -Be 0

            $Script:ActiveGrouping.Count | Should -Be 12
        }

        It "Display Results - Process/Hardware Information" {
            SetActiveDisplayGrouping "Processor/Hardware Information"

            TestObjectMatch "Type" "HyperV"
            TestObjectMatch "Processor" "Intel(R) Xeon(R) CPU E5-2430 0 @ 2.20GHz"
            TestObjectMatch "Number of Processors" 1
            TestObjectMatch "Number of Physical Cores" 2 -WriteType "Green"
            TestObjectMatch "Number of Logical Cores" 4 -WriteType "Green"
            TestObjectMatch "All Processor Cores Visible" "Passed" -WriteType "Green"
            TestObjectMatch "Max Processor Speed" 2200
            TestObjectMatch "Physical Memory" 6 -WriteType "Yellow"

            $Script:ActiveGrouping.Count | Should -Be 9
        }

        It "Display Results - NIC Settings" {
            SetActiveDisplayGrouping "NIC Settings Per Active Adapter"

            TestObjectMatch "Interface Description" "Microsoft Hyper-V Network Adapter [Ethernet]"
            TestObjectMatch "Driver Date" "2006-06-21"
            TestObjectMatch "MTU Size" 1500
            TestObjectMatch "Max Processors" 2
            TestObjectMatch "Max Processor Number" 2
            TestObjectMatch "Number of Receive Queues" 2
            TestObjectMatch "RSS Enabled" $true -WriteType "Green"
            TestObjectMatch "Link Speed" "10000 Mbps"
            TestObjectMatch "IPv6 Enabled" $true
            TestObjectMatch "Address" "192.168.11.11\24 Gateway: 192.168.11.1"
            TestObjectMatch "Registered In DNS" $true
            TestObjectMatch "Packets Received Discarded" 0 -WriteType "Green"

            $Script:ActiveGrouping.Count | Should -Be 16
        }

        It "Display Results - Frequent Configuration Issues" {
            SetActiveDisplayGrouping "Frequent Configuration Issues"

            TestObjectMatch "TCP/IP Settings" 90000 -WriteType "Yellow"
            TestObjectMatch "RPC Min Connection Timeout" 0
            TestObjectMatch "FIPS Algorithm Policy Enabled" 0
            TestObjectMatch "CTS Processor Affinity Percentage" 0 -WriteType "Green"
            TestObjectMatch "Credential Guard Enabled" $false
            TestObjectMatch "EdgeTransport.exe.config Present" $true -WriteType "Green"

            $Script:ActiveGrouping.Count | Should -Be 6
        }

        It "Display Results - Security Settings" {
            SetActiveDisplayGrouping "Security Settings"

            TestObjectMatch "LmCompatibilityLevel Settings" 3
            TestObjectMatch "SMB1 Installed" $true -WriteType "Green"
            TestObjectMatch "SMB1 Blocked" "True" -WriteType "Green"
            TestObjectMatch "Exchange Emergency Mitigation Service" "Enabled" -WriteType "Green"
            TestObjectMatch "Windows service" "Running"
            TestObjectMatch "Pattern service" "200 - Reachable"
            TestObjectMatch "Telemetry enabled" "False"

            $Script:ActiveGrouping.Count | Should -Be 71
        }

        It "Display Results - Security Vulnerability" {
            SetActiveDisplayGrouping "Security Vulnerability"

            $cveTests = $Script:ActiveGrouping.TestingValue | Where-Object { $_.StartsWith("CVE") }
            $cveTests.Contains("CVE-2020-1147") | Should -Be $true
            $cveTests.Contains("CVE-2021-1730") | Should -Be $true
        }
    }
}
