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
            $Script:ActiveGrouping.Count | Should -Be 13
        }

        It "Display Results - Organization Information" {
            SetActiveDisplayGrouping "Organization Information"

            TestObjectMatch "MAPI/HTTP Enabled" "True"
            TestObjectMatch "Enable Download Domains" "False"
            TestObjectMatch "AD Split Permissions" "False"

            $Script:ActiveGrouping.Count | Should -Be 4
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

            $Script:ActiveGrouping.Count | Should -Be 77
        }

        It "Display Results - Security Vulnerability" {
            SetActiveDisplayGrouping "Security Vulnerability"

            $cveTests = GetObject "Security Vulnerability"
            $cveTests.Contains("CVE-2020-1147") | Should -Be $true
            $cveTests.Count | Should -Be 25
            $downloadDomains = GetObject "CVE-2021-1730"
            $downloadDomains.DownloadDomainsEnabled | Should -Be "False"
            TestObjectMatch "Extended Protection Vulnerable" "True" -WriteType "Red"
            TestObjectMatch "Extended Protection Vulnerable Details" "Your Exchange server is at risk. Install the latest SU and enable Extended Protection" -WriteType "Red"
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
            Mock Get-ExSetupDetails { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\ExSetup1.xml" }
            Mock Invoke-ScriptBlockHandler -ParameterFilter { $ScriptBlockDescription -eq "Getting applicationHost.config" } -MockWith { return Get-Content "$Script:MockDataCollectionRoot\Exchange\GetApplicationHostConfig2.config" }

            SetDefaultRunOfHealthChecker "Debug_Physical_Results.xml"
        }

        It "Extended Protection Enabled" {
            SetActiveDisplayGrouping "Exchange Information"
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

        It "Extended Protection" {
            SetActiveDisplayGrouping "Security Vulnerability"
            TestObjectMatch "Extended Protection Vulnerable" "True" -WriteType "Red"
            TestObjectMatch "Extended Protection Vulnerable Details" "Extended Protection isn't configured as expected" -WriteType "Red"
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
