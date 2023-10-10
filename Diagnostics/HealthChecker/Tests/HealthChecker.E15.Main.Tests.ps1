# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

Describe "Testing Health Checker by Mock Data Imports - Exchange 2013" {

    BeforeAll {
        . $PSScriptRoot\HealthCheckerTests.ImportCode.NotPublished.ps1
        $Script:MockDataCollectionRoot = "$Script:parentPath\Tests\DataCollection\E15"
        . $PSScriptRoot\HealthCheckerTest.CommonMocks.NotPublished.ps1
    }

    Context "Basic Exchange 2013 CU23 Testing" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -ParameterFilter { $ScriptBlockDescription -eq "Test EEMS pattern service connectivity" } -MockWith { return $null }
            SetDefaultRunOfHealthChecker "Debug_E15_Results.xml"
        }

        It "Display Results - Exchange Information" {
            SetActiveDisplayGrouping "Exchange Information"

            TestObjectMatch "Name" $env:COMPUTERNAME
            TestObjectMatch "Version" "Exchange 2013 CU23"
            TestObjectMatch "Build Number" "15.00.1497.002"
            TestObjectMatch "Server Role" "MultiRole"
            TestObjectMatch "DAG Name" "Standalone Server"
            TestObjectMatch "AD Site" "Default-First-Site-Name"
            TestObjectMatch "MRS Proxy Enabled" "False"
            TestObjectMatch "MAPI Front End App Pool GC Mode" "Workstation --- Warning" -WriteType "Yellow"
            TestObjectMatch "Internet Web Proxy" "Not Set"
            TestObjectMatch "Extended Protection Enabled (Any VDir)" $false
            TestObjectMatch "Setting Overrides Detected" $false
            $Script:ActiveGrouping.Count | Should -Be 16
        }

        It "Display Results - Organization Information" {
            SetActiveDisplayGrouping "Organization Information"

            TestObjectMatch "MAPI/HTTP Enabled" "True"
            TestObjectMatch "Enable Download Domains" "Unknown"
            TestObjectMatch "AD Split Permissions" "False"
            TestObjectMatch "Dynamic Distribution Group Public Folder Mailboxes Count" 1 -WriteType "Green"

            $Script:ActiveGrouping.Count | Should -Be 6
        }

        It "Display Results - Operating System Information" {
            SetActiveDisplayGrouping "Operating System Information"

            TestObjectMatch "Version" "Windows Server 2012 R2 Datacenter"
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
            $pageFile.RecommendedPageFile | Should -Be 0

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be "Error: PageFile is not set to total system memory plus 10MB which should be 6154MB."

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
            TestObjectMatch "Physical Memory" 6

            $Script:ActiveGrouping.Count | Should -Be 9
        }

        It "Display Results - NIC Settings" {
            SetActiveDisplayGrouping "NIC Settings Per Active Adapter"

            TestObjectMatch "Interface Description" "Microsoft Hyper-V Network Adapter [Ethernet]"
            TestObjectMatch "Driver Date" "2006-06-21"
            TestObjectMatch "MTU Size" 1500
            TestObjectMatch "Max Processors" 2
            TestObjectMatch "Max Processor Number" 2
            TestObjectMatch "Number of Receive Queues" 0
            TestObjectMatch "RSS Enabled" $false -WriteType "Yellow"
            TestObjectMatch "Link Speed" "10000 Mbps"
            TestObjectMatch "IPv6 Enabled" "True"
            TestObjectMatch "Address" "192.168.9.11/24 Gateway: 192.168.9.1"
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
            TestObjectMatch "HSTS Enabled" "False"

            $Script:ActiveGrouping.Count | Should -Be 10
        }

        It "Display Results - Security Settings" {
            SetActiveDisplayGrouping "Security Settings"

            TestObjectMatch "LmCompatibilityLevel Settings" 3
            TestObjectMatch "SMB1 Installed" "True" -WriteType "Red"
            TestObjectMatch "SMB1 Blocked" "False" -WriteType "Red"

            $Script:ActiveGrouping.Count | Should -Be 83
        }

        It "Display Results - Security Vulnerability" {
            SetActiveDisplayGrouping "Security Vulnerability"

            $cveTests = $Script:ActiveGrouping.TestingValue | Where-Object { ($_.GetType().Name -eq "String") -and ($_.StartsWith("CVE")) }
            $cveTests.Contains("CVE-2020-1147") | Should -Be $true
            $cveTests.Count | Should -Be 54
        }
    }
}
