# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

Describe "Testing Health Checker by Mock Data Imports" {

    BeforeAll {
        . $PSScriptRoot\HealthCheckerTests.ImportCode.NotPublished.ps1
        $Script:MockDataCollectionRoot = "$Script:parentPath\Tests\DataCollection\E19"
        . $PSScriptRoot\HealthCheckerTest.CommonMocks.NotPublished.ps1
    }

    Context "Basic Exchange 2019 CU11 Testing HyperV" {
        BeforeAll {
            SetDefaultRunOfHealthChecker "Debug_HyperV_Results.xml"
        }

        It "Display Results - Exchange Information" {
            SetActiveDisplayGrouping "Exchange Information"

            TestObjectMatch "Name" $env:COMPUTERNAME
            TestObjectMatch "Version" "Exchange 2019 CU11"
            TestObjectMatch "Build Number" "15.02.0986.005"
            TestObjectMatch "Server Role" "Mailbox"
            TestObjectMatch "DAG Name" "Standalone Server"
            TestObjectMatch "AD Site" "Default-First-Site-Name"
            TestObjectMatch "MRS Proxy Enabled" "False"
            TestObjectMatch "Exchange Server Maintenance" "Server is not in Maintenance Mode" -WriteType "Green"
            TestObjectMatch "Internet Web Proxy" "Not Set"
            TestObjectMatch "Extended Protection Enabled (Any VDir)" $false
            TestObjectMatch "Setting Overrides Detected" $false
            TestObjectMatch "Out of Date" $true -WriteType "Red"
            $Script:ActiveGrouping.Count | Should -Be 14
        }

        It "Display Results - Organization Information" {
            SetActiveDisplayGrouping "Organization Information"

            TestObjectMatch "MAPI/HTTP Enabled" "True"
            TestObjectMatch "Enable Download Domains" "False"
            TestObjectMatch "AD Split Permissions" "False"
            TestObjectMatch "Dynamic Distribution Group Public Folder Mailboxes Count" 1 -WriteType "Green"

            $Script:ActiveGrouping.Count | Should -Be 5
        }

        It "Display Results - Operating System Information" {
            SetActiveDisplayGrouping "Operating System Information"

            TestObjectMatch "Version" "Windows Server 2019 Datacenter (Server Core)"
            TestObjectMatch "Time Zone" "Pacific Standard Time"
            TestObjectMatch "Dynamic Daylight Time Enabled" "True"
            TestObjectMatch ".NET Framework" "4.8" -WriteType "Green"
            TestObjectMatch "Power Plan" "Balanced --- Error" -WriteType "Red"
            $httpProxy = GetObject "Http Proxy Setting"
            $httpProxy.ProxyAddress | Should -Be "None"
            TestObjectMatch "Visual C++ 2012 x64" "11.0.61030 Version is current" -WriteType "Green"
            TestObjectMatch "Visual C++ 2013 x64" "Redistributable (12.0.21005) is outdated" -WriteType "Yellow"
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
            TestObjectMatch "Processor" "Intel(R) XeOn(R) CPU E5-2430 0 @ 2.20GHz"
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
            TestObjectMatch "Address" "192.168.11.11/24 Gateway: 192.168.11.1"
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
            TestObjectMatch "Disable Async Notification" $false
            TestObjectMatch "Credential Guard Enabled" $false
            TestObjectMatch "EdgeTransport.exe.config Present" "True" -WriteType "Green"
            TestObjectMatch "NodeRunner.exe memory limit" "0 MB" -WriteType "Green"
            TestObjectMatch "Open Relay Wild Card Domain" "Not Set"
            TestObjectMatch "EXO Connector Present" "True" # Custom EXO Connector with no TlsDomain TlsAuthLevel

            $Script:ActiveGrouping.Count | Should -Be 13
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
            TestObjectMatch "AMSI Enabled" "True" -WriteType "Green"
            TestObjectMatch "Strict Mode disabled" "False" -WriteType "Green"
            TestObjectMatch "BaseTypeCheckForDeserialization disabled" "False" -WriteType "Green"
            TestObjectMatch "AES256-CBC Protected Content Support" "Not Supported Build" -WriteType "Red"
            TestObjectMatch "SerializedDataSigning Enabled" "Unsupported Version" -WriteType "Red"

            $Script:ActiveGrouping.Count | Should -Be 81
        }

        It "Display Results - Security Vulnerability" {
            SetActiveDisplayGrouping "Security Vulnerability"

            $cveTests = GetObject "Security Vulnerability"
            $cveTests.Contains("CVE-2020-1147") | Should -Be $true
            $cveTests.Contains("CVE-2023-36434") | Should -Be $true
            $cveTests.Contains("CVE-2023-36039") | Should -Be $true
            $cveTests.Contains("ADV24199947") | Should -Be $true
            $cveTests.Count | Should -Be 51
            $downloadDomains = GetObject "CVE-2021-1730"
            $downloadDomains.DownloadDomainsEnabled | Should -Be "False"
            TestObjectMatch "Extended Protection Vulnerable" "True" -WriteType "Red"
            TestObjectMatch "Extended Protection Vulnerable Details" "Your Exchange server is at risk. Install the latest SU and enable Extended Protection" -WriteType "Red"
        }

        It "Display Results - Exchange IIS Information" {
            SetActiveDisplayGrouping "Exchange IIS Information"
            $tokenCacheModuleInformation = GetObject "TokenCacheModule loaded"
            $tokenCacheModuleInformation | Should -Be $null # null because we are loaded and only display if we aren't loaded.
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
            Mock Get-ExSetupFileVersionInfo { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\ExSetup1.xml" }
            Mock Get-WebSite -ParameterFilter { $Name -eq "Default Web Site" } -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\IIS\GetWebSite_DefaultWebSite1.xml" }
            Mock Get-WebConfigFile -ParameterFilter { $PSPath -eq "IIS:\Sites\Default Web Site" } -MockWith { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite_web2.config" } }
            Mock Invoke-ScriptBlockHandler -ParameterFilter { $ScriptBlockDescription -eq "Getting applicationHost.config" } -MockWith { return Get-Content "$Script:MockDataCollectionRoot\Exchange\IIS\applicationHost2.config" -Raw }
            Mock Get-DynamicDistributionGroup { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetDynamicDistributionGroupPfMailboxes1.xml" }
            Mock Invoke-ScriptBlockHandler -ParameterFilter { $ScriptBlockDescription -eq "Get TokenCacheModule version information" } -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\IIS\GetVersionInformationCachToknPatched.xml" }

            SetDefaultRunOfHealthChecker "Debug_Physical_Results.xml"
        }

        It "Dynamic Public Folder Mailboxes" {
            SetActiveDisplayGrouping "Organization Information"
            TestObjectMatch "Dynamic Distribution Group Public Folder Mailboxes Count" 2 -WriteType "Red"
        }

        It "Extended Protection Enabled" {
            SetActiveDisplayGrouping "Exchange Information"
            TestObjectMatch "Version" "Exchange 2019 CU12 Feb23SU"
            TestObjectMatch "Build Number" "15.02.1118.025"
            TestObjectMatch "Extended Protection Enabled (Any VDir)" $true
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

            $Script:ActiveGrouping.Count | Should -Be 12
        }

        It "Display Results - NIC Settings" {
            SetActiveDisplayGrouping "NIC Settings Per Active Adapter"

            TestObjectMatch "Sleepy NIC Disabled" "True"

            $Script:ActiveGrouping.Count | Should -Be 18
        }

        It "Display Results - Security Settings" {
            SetActiveDisplayGrouping "Security Settings"
            TestObjectMatch "AMSI Enabled" "True" -WriteType "Green"
            TestObjectMatch "SerializedDataSigning Enabled" "False" -WriteType "Red"
        }

        It "Display Results - Security Vulnerability" {
            SetActiveDisplayGrouping "Security Vulnerability"

            $cveEntries = GetObject "Security Vulnerability"
            $cveEntries.Contains("CVE-2023-36434") | Should -Be $false # false because loaded module with greater than patch value.
        }

        It "Extended Protection" {
            TestObjectMatch "Extended Protection Vulnerable" "True" -WriteType "Red"
            TestObjectMatch "Extended Protection Vulnerable Details" "Extended Protection isn't configured as expected" -WriteType "Red"
        }

        It "Display Results - Exchange IIS Information" {
            SetActiveDisplayGrouping "Exchange IIS Information"
            $tokenCacheModuleInformation = GetObject "TokenCacheModule loaded"
            $tokenCacheModuleInformation | Should -Be $null # null because we are loaded

            TestObjectMatch "hsts-Enabled-Default Web Site" $true -WriteType "Green"
            TestObjectMatch "hsts-max-age-Default Web Site" 300 -WriteType "Yellow"
            TestObjectMatch "hsts-includeSubDomains-Default Web Site" $false
            TestObjectMatch "hsts-preload-Default Web Site" $false
            TestObjectMatch "hsts-redirectHttpToHttps-Default Web Site" $false
            TestObjectMatch "hsts-conflict" $true -WriteType "Yellow"
            TestObjectMatch "hsts-MoreInfo" $true -WriteType "Yellow"
        }
    }

    Context "Testing Throws" {
        BeforeAll {
            #This causes a RuntimeException because of issue #743 when not fixed
            Mock Get-MailboxServer { throw "Pester testing" }

            SetDefaultRunOfHealthChecker "Debug_TestingThrow_Results.xml"
        }

        It "Verify we still analyze the data from throw Get-MailboxServer" {
            SetActiveDisplayGrouping "Exchange Information"
            TestObjectMatch "DAG Name" "Standalone Server"
        }
    }
}
