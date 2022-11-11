# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

Describe "Testing Health Checker by Mock Data Imports" {

    BeforeAll {
        . $PSScriptRoot\HealthCheckerTests.ImportCode.NotPublished.ps1
        $Script:Server = $env:COMPUTERNAME
        $Script:MockDataCollectionRoot = "$Script:parentPath\Tests\DataCollection\E19"
        . $PSScriptRoot\HealthCheckerTest.CommonMocks.NotPublished.ps1
    }

    Context "Basic Exchange 2019 CU11 Testing HyperV" {
        BeforeAll {
            $org = Get-OrganizationInformation -EdgeServer $false
            $hc = Get-HealthCheckerExchangeServer -ServerName $Script:Server -OrganizationConfig $org.GetOrganizationConfig
            $hc.OrganizationInformation = $org
            $hc | Export-Clixml $PSScriptRoot\Debug_HyperV_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc
        }

        It "Display Results - Exchange Information" {
            SetActiveDisplayGrouping "Exchange Information"

            TestObjectMatch "Name" $env:COMPUTERNAME
            TestObjectMatch "Version" "Exchange 2019 CU11"
            TestObjectMatch "Build Number" "15.02.0986.005"
            TestObjectMatch "Server Role" "Mailbox"
            TestObjectMatch "DAG Name" "Standalone Server"
            TestObjectMatch "AD Site" "Default-First-Site-Name"
            TestObjectMatch "MAPI/HTTP Enabled" "True"
            TestObjectMatch "MRS Proxy Enabled" "False"
            TestObjectMatch "Exchange Server Maintenance" "Server is not in Maintenance Mode" -WriteType "Green"
            TestObjectMatch "Internet Web Proxy" "Not Set"
            TestObjectMatch "Setting Overrides Detected" $false
            $Script:ActiveGrouping.Count | Should -Be 13
        }

        It "Display Results - Operating System Information" {
            SetActiveDisplayGrouping "Operating System Information"

            TestObjectMatch "Version" "Microsoft Windows Server 2019 Datacenter"
            TestObjectMatch "Time Zone" "Pacific Standard Time"
            TestObjectMatch "Dynamic Daylight Time Enabled" "True"
            TestObjectMatch ".NET Framework" "4.8" -WriteType "Green"
            TestObjectMatch "Power Plan" "Balanced --- Error" -WriteType "Red"
            $httpProxy = GetObject "Http Proxy Setting"
            $httpProxy.ProxyAddress | Should -Be "None"
            TestObjectMatch "Visual C++ 2012" "184610406 Version is current" -WriteType "Green"
            TestObjectMatch "Visual C++ 2013" "Redistributable is outdated" -WriteType "Yellow"
            TestObjectMatch "Server Pending Reboot" $false

            $pageFile = GetObject "PageFile Size 0"
            $pageFile.Name | Should -Be ""
            $pageFile.TotalPhysicalMemory | Should -Be 6144
            $pageFile.MaxPageSize | Should -Be 0
            $pageFile.MultiPageFile | Should -Be $false
            $pageFile.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be "Error: On Exchange 2019, the recommended PageFile size is 25% (1536MB) of the total system memory (6144MB)."

            $Script:ActiveGrouping.Count | Should -Be 14
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
            TestObjectMatch "RSS Enabled" "True" -WriteType "Green"
            TestObjectMatch "Link Speed" "10000 Mbps"
            TestObjectMatch "IPv6 Enabled" "True"
            TestObjectMatch "Address" "192.168.11.11\24 Gateway: 192.168.11.1"
            TestObjectMatch "Registered In DNS" "True"
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
            TestObjectMatch "EdgeTransport.exe.config Present" "True" -WriteType "Green"
            TestObjectMatch "Open Relay Wild Card Domain" "Not Set"

            $Script:ActiveGrouping.Count | Should -Be 8
        }

        It "Display Results - Security Settings" {
            SetActiveDisplayGrouping "Security Settings"

            TestObjectMatch "LmCompatibilityLevel Settings" 3
            TestObjectMatch "SMB1 Installed" "False" -WriteType "Green"
            TestObjectMatch "SMB1 Blocked" "True" -WriteType "Green"
            TestObjectMatch "Exchange Emergency Mitigation Service" "Enabled" -WriteType "Green"
            TestObjectMatch "Windows service" "Running"
            TestObjectMatch "Pattern service" "200 - Reachable"
            TestObjectMatch "Telemetry enabled" "False"

            $Script:ActiveGrouping.Count | Should -Be 67
        }

        It "Display Results - Security Vulnerability" {
            SetActiveDisplayGrouping "Security Vulnerability"

            $cveTests = GetObject "Security Vulnerability"
            $cveTests.Contains("CVE-2020-1147") | Should -Be $true
            $cveTests.Count | Should -Be 21
            $downloadDomains = GetObject "CVE-2021-1730"
            $downloadDomains.DownloadDomainsEnabled | Should -Be "False"
        }
    }

    Context "Basic Exchange 2019 CU11 Testing Physical" {
        BeforeAll {
            $Script:date = Get-Date
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_ComputerSystem" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\Physical_Win32_ComputerSystem.xml" }
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PhysicalMemory" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\Physical_Win32_PhysicalMemory.xml" }
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_Processor" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\Physical_Win32_Processor.xml" }
            $org = Get-OrganizationInformation -EdgeServer $false
            $hc = Get-HealthCheckerExchangeServer -ServerName $Script:Server -OrganizationConfig $org.GetOrganizationConfig
            $hc.OrganizationInformation = $org
            $hc | Export-Clixml $PSScriptRoot\Debug_Physical_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc
        }

        It "Display Results - Operating System Information" {
            SetActiveDisplayGrouping "Operating System Information"

            $pageFile = GetObject "PageFile Size 0"
            $pageFile.TotalPhysicalMemory | Should -Be 98304
        }

        It "Display Results - Process/Hardware Information" {
            SetActiveDisplayGrouping "Processor/Hardware Information"

            TestObjectMatch "Type" "Physical"
            TestObjectMatch "Number of Processors" 2 -WriteType "Green"
            TestObjectMatch "Number of Physical Cores" 12 -WriteType "Green"
            TestObjectMatch "Number of Logical Cores" 24 -WriteType "Green"
            TestObjectMatch "All Processor Cores Visible" "Failed" -WriteType "Red"
            TestObjectMatch "Max Processor Speed" 2201
            TestObjectMatch "Physical Memory" 96 -WriteType "Yellow"
            TestObjectMatch "Manufacturer" "My Custom PC"
            TestObjectMatch "Model" "CHG-GG"

            $Script:ActiveGrouping.Count | Should -Be 11
        }

        It "Display Results - NIC Settings" {
            SetActiveDisplayGrouping "NIC Settings Per Active Adapter"

            TestObjectMatch "Sleepy NIC Disabled" "True"

            $Script:ActiveGrouping.Count | Should -Be 18
        }
    }

    Context "Mocked Calls" {

        It "Testing Standard Mock Calls" {
            $Script:ErrorCount = 0
            Mock Invoke-CatchActions { $Script:ErrorCount++ }
            #redo change to a mock call for Exchange cmdlets
            Mock Get-ExchangeServer { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeServer.xml" }
            Mock Get-ExchangeCertificate { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeCertificate.xml" }
            Mock Get-AuthConfig { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetAuthConfig.xml" }
            Mock Get-ExSetupDetails { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\ExSetup.xml" }
            Mock Get-MailboxServer { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetMailboxServer.xml" }
            Mock Get-OwaVirtualDirectory { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOwaVirtualDirectory.xml" }
            Mock Get-WebServicesVirtualDirectory { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetWebServicesVirtualDirectory.xml" }
            Mock Get-OrganizationConfig { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOrganizationConfig.xml" }
            Mock Get-HybridConfiguration { return $null }
            # do not need to match the function. Only needed really to test the Assert-MockCalled
            Mock Get-Service { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetServiceMitigation.xml" }
            Mock Get-SettingOverride { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetSettingOverride.xml" }
            Mock Get-ServerComponentState { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetServerComponentState.xml" }
            Mock Test-ServiceHealth { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\TestServiceHealth.xml" }
            Mock Get-AcceptedDomain { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetAcceptedDomain.xml" }
            Mock Get-ReceiveConnector { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetReceiveConnector.xml" }
            Mock Get-SendConnector { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetSendConnector.xml" }

            $Error.Clear()
            $org = Get-OrganizationInformation -EdgeServer $false
            Get-HealthCheckerExchangeServer -ServerName $Script:Server -OrganizationConfig $org.GetOrganizationConfig | Out-Null
            $Error.Count | Should -Be $Script:ErrorCount
            # Hard coded to know if this ever changes.
            Assert-MockCalled Invoke-CatchActions -Exactly 1

            Assert-MockCalled Get-ExchangeAdSchemaClass -Exactly 1
            Assert-MockCalled Get-WmiObjectHandler -Exactly 6
            Assert-MockCalled Invoke-ScriptBlockHandler -Exactly 4
            Assert-MockCalled Get-RemoteRegistryValue -Exactly 11
            Assert-MockCalled Get-NETFrameworkVersion -Exactly 1
            Assert-MockCalled Get-DotNetDllFileVersions -Exactly 1
            Assert-MockCalled Get-NicPnpCapabilitiesSetting -Exactly 1
            Assert-MockCalled Get-NetIPConfiguration -Exactly 1
            Assert-MockCalled Get-DnsClient -Exactly 1
            Assert-MockCalled Get-NetAdapterRss -Exactly 1
            Assert-MockCalled Get-HotFix -Exactly 1
            Assert-MockCalled Get-LocalizedCounterSamples -Exactly 1
            Assert-MockCalled Get-ServerRebootPending -Exactly 1
            Assert-MockCalled Get-TimeZoneInformationRegistrySettings -Exactly 1
            Assert-MockCalled Get-AllTlsSettings -Exactly 1
            Assert-MockCalled Get-CredentialGuardEnabled -Exactly 1
            Assert-MockCalled Get-Smb1ServerSettings -Exactly 1
            Assert-MockCalled Get-ExchangeAppPoolsInformation -Exactly 1
            Assert-MockCalled Get-ExchangeApplicationConfigurationFileValidation -Exactly 1
            Assert-MockCalled Get-ExchangeUpdates -Exactly 1
            Assert-MockCalled Get-ExchangeDomainsAclPermissions -Exactly 1
            Assert-MockCalled Get-ExtendedProtectionConfiguration -Exactly 1
            Assert-MockCalled Get-ExchangeAdSchemaClass -Exactly 1
            Assert-MockCalled Get-ExchangeServer -Exactly 1
            Assert-MockCalled Get-ExchangeCertificate -Exactly 1
            Assert-MockCalled Get-AuthConfig -Exactly 1
            Assert-MockCalled Get-ExSetupDetails -Exactly 1
            Assert-MockCalled Get-MailboxServer -Exactly 1
            Assert-MockCalled Get-OwaVirtualDirectory -Exactly 1
            Assert-MockCalled Get-WebServicesVirtualDirectory -Exactly 1
            Assert-MockCalled Get-OrganizationConfig -Exactly 1
            Assert-MockCalled Get-HybridConfiguration -Exactly 1
            Assert-MockCalled Get-Service -Exactly 2
            Assert-MockCalled Get-SettingOverride -Exactly 1
            Assert-MockCalled Get-ServerComponentState -Exactly 1
            Assert-MockCalled Test-ServiceHealth -Exactly 1
            Assert-MockCalled Get-AcceptedDomain -Exactly 1
            Assert-MockCalled Get-FIPFSScanEngineVersionState -Exactly 1
            Assert-MockCalled Get-ReceiveConnector -Exactly 1
            Assert-MockCalled Get-SendConnector -Exactly 1
            Assert-MockCalled Get-IISModules -Exactly 1
            Assert-MockCalled Get-ExchangeSettingOverride -Exactly 1
        }
    }

    Context "Checking Scenarios 1" {
        BeforeAll {
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "KeepAliveTime" } -MockWith { return 0 }
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "CtsProcessorAffinityPercentage" } -MockWith { return 10 }
            Mock Get-CredentialGuardEnabled -MockWith { return $true }
            Mock Get-ExchangeApplicationConfigurationFileValidation { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeApplicationConfigurationFileValidation1.xml" }
            Mock Get-ServerRebootPending { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetServerRebootPending1.xml" }
            Mock Get-AllTlsSettings { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetAllTlsSettings1.xml" }
            Mock Get-Smb1ServerSettings { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetSmb1ServerSettings1.xml" }
            Mock Get-OrganizationConfig { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOrganizationConfig1.xml" }
            Mock Get-OwaVirtualDirectory { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOwaVirtualDirectory1.xml" }
            Mock Get-HttpProxySetting { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetHttpProxySetting1.xml" }
            Mock Get-AcceptedDomain { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetAcceptedDomain_Problem.xml" }
            Mock Get-ExchangeIISConfigSettings { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeIISConfigSettings1.xml" }
            Mock Get-ExchangeSettingOverride { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeSettingOverride1.xml" }
            Mock Get-Service {
                param(
                    [string]$ComputerName,
                    [string]$Name
                )
                if ($Name -eq "MSExchangeMitigation") { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetServiceMitigation.xml" }
                return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetService1.xml"
            }

            $org = Get-OrganizationInformation -EdgeServer $false
            $hc = Get-HealthCheckerExchangeServer -ServerName $Script:Server -OrganizationConfig $org.GetOrganizationConfig
            $hc.OrganizationInformation = $org
            $hc | Export-Clixml $PSScriptRoot\Debug_Scenario1_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc
        }

        It "Dependent Services" {
            SetActiveDisplayGrouping "Exchange Information"
            $displayFormat = "{0} - Status: {1} - StartType: {2}"
            TestObjectMatch "Critical Pla" ($displayFormat -f "pla", "Stopped", "Manual") -WriteType "Red"
            TestObjectMatch "Critical HostControllerService" ($displayFormat -f "HostControllerService", "Stopped", "Disabled") -WriteType "Red"
            TestObjectMatch "Common MSExchangeDagMgmt" ($displayFormat -f "MSExchangeDagMgmt", "Stopped", "Automatic") -WriteType "Yellow"
            TestObjectMatch "Setting Overrides Detected" $true
        }

        It "Http Proxy Settings" {
            SetActiveDisplayGrouping "Operating System Information"
            $httpProxy = GetObject "Http Proxy Setting"
            $httpProxy.ProxyAddress | Should -Be "proxy.contoso.com:8080"
            $httpProxy.ByPassList | Should -Be "localhost;*.contoso.com;*microsoft.com"
            $httpProxy.HttpProxyDifference | Should -Be "False"
            $httpProxy.HttpByPassDifference | Should -Be "False"
        }

        It "TCP Keep Alive Time" {
            SetActiveDisplayGrouping "Frequent Configuration Issues"
            TestObjectMatch "TCP/IP Settings" 0 -WriteType "Red"
        }

        It "CTS Processor Affinity Percentage" {
            TestObjectMatch "CTS Processor Affinity Percentage" 10 -WriteType "Red"
        }

        It "Credential Guard Enabled" {
            TestObjectMatch "Credential Guard Enabled" "True" -WriteType "Red"
        }

        It "EdgeTransport.exe.config Present" {
            TestObjectMatch "EdgeTransport.exe.config Present" "False --- Error" -WriteType "Red"
        }

        It "Open Relay Wild Card Domain" {
            TestObjectMatch "Open Relay Wild Card Domain" "Error --- Accepted Domain `"Problem Accepted Domain`" is set to a Wild Card (*) Domain Name with a domain type of InternalRelay. This is not recommended as this is an open relay for the entire environment.`r`n`t`tMore Information: https://aka.ms/HC-OpenRelayDomain" -WriteType "Red"
        }

        It "Testing Missing Configuration File" {
            TestObjectMatch "Missing Configuration File" $true -WriteType "Red"
        }

        It "Testing Default Variable Detected" {
            TestObjectMatch "Default Variable Detected" $true -WriteType "Red"
        }

        It "Testing Bin Search Folder Not Found" {
            TestObjectMatch "Bin Search Folder Not Found" $true -WriteType "Red"
        }

        It "Server Pending Reboot" {
            SetActiveDisplayGrouping "Operating System Information"
            TestObjectMatch "Server Pending Reboot" "True" -WriteType "Yellow"
            TestObjectMatch "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations" "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations" -WriteType "Yellow"
            TestObjectMatch "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -WriteType "Yellow"
            TestObjectMatch "HKLM:\Software\Microsoft\Updates\UpdateExeVolatile\Flags" "HKLM:\Software\Microsoft\Updates\UpdateExeVolatile\Flags" -WriteType "Yellow"
            TestObjectMatch "Reboot More Information" "True" -WriteType "Yellow"
        }

        It "TLS Settings" {
            SetActiveDisplayGrouping "Security Settings"
            TestObjectMatch "TLS 1.0" "Misconfigured" -WriteType "Red"
            TestObjectMatch "TLS 1.1" "Misconfigured" -WriteType "Red"
            TestObjectMatch "TLS 1.2" "Enabled" -WriteType "Green"
            TestObjectMatch "TLS 1.3" "Disabled" -WriteType "Green"

            TestObjectMatch "Display Link to Docs Page" "True" -WriteType "Yellow"

            TestObjectMatch "Detected TLS Mismatch Display More Info" "True" -WriteType "Yellow"

            $tlsCipherSuite = (GetObject "TLS Cipher Suite Group")
            $tlsCipherSuite.Count | Should -Be 8
        }

        It "SMB Settings" {
            TestObjectMatch "SMB1 Installed" "True" -WriteType "Red"
            TestObjectMatch "SMB1 Blocked" "False" -WriteType "Red"
        }

        It "Enabled Domains" {
            SetActiveDisplayGrouping "Security Vulnerability"
            $downloadDomains = GetObject "CVE-2021-1730"
            $downloadDomains.DownloadDomainsEnabled | Should -Be "True"
            $downloadDomains.ExternalDownloadHostName | Should -Be "Set to the same as Internal Or External URL as OWA."
            $downloadDomains.InternalDownloadHostName | Should -Be "Set to the same as Internal Or External URL as OWA."
        }

        It "AMSI Enabled" {
            SetActiveDisplayGrouping "Security Settings"
            TestObjectMatch "AMSI Enabled" "False" -WriteType "Yellow"
        }

        It "EEMS Enabled And OCS Reachable" {
            SetActiveDisplayGrouping "Security Settings"
            TestObjectMatch "Exchange Emergency Mitigation Service" "Enabled" -WriteType "Green"
            TestObjectMatch "Windows service" "Running"
            TestObjectMatch "Pattern service" "200 - Reachable"
            TestObjectMatch "Telemetry enabled" "False"
        }
    }

    Context "Checking Scenarios 2" {
        BeforeAll {
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "KeepAliveTime" } -MockWith { return 1800000 }
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "DisableGranularReplication" } -MockWith { return 1 }
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "DisableAsyncNotification" } -MockWith { return 1 }
            Mock Get-AllTlsSettings { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetAllTlsSettings2.xml" }
            Mock Get-OrganizationConfig { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOrganizationConfig1.xml" }
            Mock Get-OwaVirtualDirectory { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOwaVirtualDirectory2.xml" }
            Mock Get-AcceptedDomain { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetAcceptedDomain_Bad.xml" }
            Mock Get-DnsClient { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetDnsClient1.xml" }
            $org = Get-OrganizationInformation -EdgeServer $false
            $hc = Get-HealthCheckerExchangeServer -ServerName $Script:Server -OrganizationConfig $org.GetOrganizationConfig
            $hc.OrganizationInformation = $org
            $hc | Export-Clixml $PSScriptRoot\Debug_Scenario2_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc
        }

        It "TCP Keep Alive Time" {
            SetActiveDisplayGrouping "Frequent Configuration Issues"

            TestObjectMatch "TCP/IP Settings" 1800000 -WriteType "Green"
        }

        It "Open Relay Wild Card Domain" {
            TestObjectMatch "Open Relay Wild Card Domain" "Error --- Accepted Domain `"Bad Accepted Domain`" is set to a Wild Card (*) Domain Name with a domain type of ExternalRelay. This is not recommended as this is an open relay for the entire environment.`r`n`t`tMore Information: https://aka.ms/HC-OpenRelayDomain" -WriteType "Red"
        }

        It "DisableGranularReplication" {
            TestObjectMatch "DisableGranularReplication" $true -WriteType "Red"
        }

        It "Disable Async Notification" {
            TestObjectMatch "Disable Async Notification" $true -WriteType "Yellow"
        }

        It "TLS Settings" {
            SetActiveDisplayGrouping "Security Settings"
            TestObjectMatch "TLS 1.0" "Misconfigured" -WriteType "Red"
            TestObjectMatch "TLS 1.1" "Misconfigured" -WriteType "Red"
            TestObjectMatch "TLS 1.2" "Enabled" -WriteType "Green"
            TestObjectMatch "TLS 1.3" "Enabled" -WriteType "Red"

            TestObjectMatch "TLS 1.3 not disabled" $true -WriteType "Red"

            TestObjectMatch "Display Link to Docs Page" "True" -WriteType "Yellow"

            TestObjectMatch "Detected TLS Mismatch Display More Info" "True" -WriteType "Yellow"

            $tlsCipherSuite = (GetObject "TLS Cipher Suite Group")
            $tlsCipherSuite.Count | Should -Be 8
        }

        It "Enabled Domains" {
            SetActiveDisplayGrouping "Security Vulnerability"
            $downloadDomains = GetObject "CVE-2021-1730"
            $downloadDomains.DownloadDomainsEnabled | Should -Be "True"
            $downloadDomains.ExternalDownloadHostName | Should -Be "Set Correctly."
            $downloadDomains.InternalDownloadHostName | Should -Be "Not Configured"
        }

        It "No Register in DNS" {
            SetActiveDisplayGrouping "NIC Settings Per Active Adapter"
            TestObjectMatch "No NIC Registered In DNS" "Error: This will cause server to crash and odd mail flow issues. Exchange Depends on the primary NIC to have the setting Registered In DNS set." -WriteType "Red"
        }
    }

    Context "Checking Scenario 3 - Physical" {
        BeforeAll {
            $Script:date = Get-Date
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_ComputerSystem" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\Physical_Win32_ComputerSystem1.xml" }
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PhysicalMemory" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\Physical_Win32_PhysicalMemory.xml" }
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_Processor" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\Physical_Win32_Processor1.xml" }
            $org = Get-OrganizationInformation -EdgeServer $false
            $hc = Get-HealthCheckerExchangeServer -ServerName $Script:Server -OrganizationConfig $org.GetOrganizationConfig
            $hc.OrganizationInformation = $org
            $hc | Export-Clixml $PSScriptRoot\Debug_Scenario3_Physical_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc
        }

        It "Number of Processors" {
            SetActiveDisplayGrouping "Processor/Hardware Information"
            TestObjectMatch "Number of Processors" 4 -WriteType "Red"
        }

        It "Number of Physical Cores" {
            TestObjectMatch "Number of Physical Cores" 48 -WriteType "Green"
        }

        It "Number of Logical Cores" {
            TestObjectMatch "Number of Logical Cores" "96 - Error" -WriteType "Red"
        }

        It "Hyper-Threading" {
            TestObjectMatch "Hyper-Threading" "True" -WriteType "Red"
        }

        It "NUMA Group Size Optimization" {
            TestObjectMatch "NUMA Group Size Optimization" "Clustered" -WriteType "Red"
        }

        It "Current Processor Speed" {
            TestObjectMatch "Current Processor Speed" 2200 -WriteType "Red"
        }

        It "HighPerformanceSet" {
            TestObjectMatch "HighPerformanceSet" $false -WriteType "Red"
        }
    }

    Context "Checking PageFile Scenarios" {

        It "PageFile Configured As Expected" {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PageFileWellConfigured.xml" }
            $org = Get-OrganizationInformation -EdgeServer $false
            $hc = Get-HealthCheckerExchangeServer -ServerName $Script:Server -OrganizationConfig $org.GetOrganizationConfig
            $hc.OrganizationInformation = $org
            $hc | Export-Clixml $PSScriptRoot\Debug_PageFile_Well_Scenario_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc

            SetActiveDisplayGrouping "Operating System Information"
            $pageFile = GetObject "PageFile Size 0"
            $pageFile.Name | Should -Be "c:\pagefile.sys"
            $pageFile.TotalPhysicalMemory | Should -Be 6144
            $pageFile.MaxPageSize | Should -Be 1536
            $pageFile.MultiPageFile | Should -Be $false
            $pageFile.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be $null
        }

        It "PageFile Oversized" {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PageFileOverSized.xml" }
            $hc = Get-HealthCheckerExchangeServer -ServerName $Script:Server
            $hc | Export-Clixml $PSScriptRoot\Debug_PageFile_OverSized_Scenario_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc

            SetActiveDisplayGrouping "Operating System Information"
            $pageFile = GetObject "PageFile Size 0"
            $pageFile.Name | Should -Be "c:\pagefile.sys"
            $pageFile.TotalPhysicalMemory | Should -Be 6144
            $pageFile.MaxPageSize | Should -Be 2025
            $pageFile.MultiPageFile | Should -Be $false
            $pageFile.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be "Warning: On Exchange 2019, the recommended PageFile size is 25% (1536MB) of the total system memory (6144MB)."
        }

        It "PageFile System-managed" {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PageFileSystemManaged.xml" }
            $org = Get-OrganizationInformation -EdgeServer $false
            $hc = Get-HealthCheckerExchangeServer -ServerName $Script:Server -OrganizationConfig $org.GetOrganizationConfig
            $hc.OrganizationInformation = $org
            $hc | Export-Clixml $PSScriptRoot\Debug_PageFile_SystemManaged_Scenario_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc

            SetActiveDisplayGrouping "Operating System Information"
            $pageFile = GetObject "PageFile Size 0"
            $pageFile.Name | Should -Be ""
            $pageFile.TotalPhysicalMemory | Should -Be 6144
            $pageFile.MaxPageSize | Should -Be 0
            $pageFile.MultiPageFile | Should -Be $false
            $pageFile.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be "Error: On Exchange 2019, the recommended PageFile size is 25% (1536MB) of the total system memory (6144MB)."
        }

        It "PageFiles One System Managed, One Static" {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_MultiplePageFilesOneSystemManaged.xml" }
            $org = Get-OrganizationInformation -EdgeServer $false
            $hc = Get-HealthCheckerExchangeServer -ServerName $Script:Server -OrganizationConfig $org.GetOrganizationConfig
            $hc.OrganizationInformation = $org
            $hc | Export-Clixml $PSScriptRoot\Debug_PageFile_Multiple_PageFiles_Scenario1_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc

            SetActiveDisplayGrouping "Operating System Information"
            $pageFile1 = GetObject "PageFile Size 0"
            $pageFile1.Name | Should -Be "c:\pagefile.sys"
            $pageFile1.TotalPhysicalMemory | Should -Be 6144
            $pageFile1.MaxPageSize | Should -Be 1536
            $pageFile1.MultiPageFile | Should -Be $true
            $pageFile1.RecommendedPageFile | Should -Be 1536

            $pageFile2 = GetObject "PageFile Size 1"
            $pageFile2.Name | Should -Be "d:\pagefile.sys"
            $pageFile2.TotalPhysicalMemory | Should -Be 6144
            $pageFile2.MaxPageSize | Should -Be 0
            $pageFile2.MultiPageFile | Should -Be $true
            $pageFile2.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be "Error: On Exchange 2019, the recommended PageFile size is 25% (1536MB) of the total system memory (6144MB)."

            $multiPageFileWarning = GetObject "Multiple PageFile Detected"
            $multiPageFileWarning | Should -Be $true
        }

        It "PageFiles One Correct, One OverSized" {
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_MultiplePageFilesOneOverSized.xml" }
            $org = Get-OrganizationInformation -EdgeServer $false
            $hc = Get-HealthCheckerExchangeServer -ServerName $Script:Server -OrganizationConfig $org.GetOrganizationConfig
            $hc.OrganizationInformation = $org
            $hc | Export-Clixml $PSScriptRoot\Debug_PageFile_Multiple_PageFiles_Scenario1_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc

            SetActiveDisplayGrouping "Operating System Information"
            $pageFile1 = GetObject "PageFile Size 0"
            $pageFile1.Name | Should -Be "c:\pagefile.sys"
            $pageFile1.TotalPhysicalMemory | Should -Be 6144
            $pageFile1.MaxPageSize | Should -Be 1536
            $pageFile1.MultiPageFile | Should -Be $true
            $pageFile1.RecommendedPageFile | Should -Be 1536

            $pageFile2 = GetObject "PageFile Size 1"
            $pageFile2.Name | Should -Be "d:\pagefile.sys"
            $pageFile2.TotalPhysicalMemory | Should -Be 6144
            $pageFile2.MaxPageSize | Should -Be 2024
            $pageFile2.MultiPageFile | Should -Be $true
            $pageFile2.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be "Warning: On Exchange 2019, the recommended PageFile size is 25% (1536MB) of the total system memory (6144MB)."

            $multiPageFileWarning = GetObject "Multiple PageFile Detected"
            $multiPageFileWarning | Should -Be $true
        }
    }

    Context "Testing Throws" {
        BeforeAll {
            #This causes a RuntimeException because of issue #743 when not fixed
            Mock Get-MailboxServer { throw "Pester testing" }
            $org = Get-OrganizationInformation -EdgeServer $false
            $hc = Get-HealthCheckerExchangeServer -ServerName $Script:Server -OrganizationConfig $org.GetOrganizationConfig
            $hc.OrganizationInformation = $org
            $hc | Export-Clixml $PSScriptRoot\Debug_TestingThrow_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc
        }

        It "Verify we still analyze the data from throw Get-MailboxServer" {
            SetActiveDisplayGrouping "Exchange Information"
            TestObjectMatch "DAG Name" "Standalone Server"
        }
    }

    Context "Failing HC" {
        It "WMI Critical" {

            $Error.Clear()
            Mock Get-WmiObjectHandler { return $null }
            try {
                Get-HealthCheckerExchangeServer -ServerName $Script:Server
            } catch {
                $_ | Should -Be "Failed to get critical information. Stopping the script. InnerException: "
            }
        }
    }
}
