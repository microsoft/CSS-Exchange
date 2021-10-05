# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()
BeforeAll {
    . $PSScriptRoot\..\..\..\.build\BuildFunctions\Get-ExpandedScriptContent.ps1
    . $PSScriptRoot\..\Helpers\Class.ps1
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:PesterExtract = "# Extract for Pester Testing - Start"
}

Describe "Testing Health Checker by Mock Data Imports - Exchange 2016" {

    BeforeAll {
        . $PSScriptRoot\HealthCheckerTests.ImportCode.NotPublished.ps1
        $Script:Server = $env:COMPUTERNAME
        $Script:MockDataCollectionRoot = "$Script:parentPath\Tests\DataCollection\E16"
        . $PSScriptRoot\HealthCheckerTest.CommonMocks.NotPublished.ps1
    }

    Context "Basic Exchange 2016 CU22 Testing" {
        BeforeAll {
            Mock Invoke-ScriptBlockHandler -ParameterFilter { $ScriptBlockDescription -eq "Test EEMS pattern service connectivity" } -MockWith { return $null }
            $hc = Get-HealthCheckerExchangeServer
            $hc | Export-Clixml $PSScriptRoot\Debug_E16_Results.xml -Depth 6 -Encoding utf8
            $Script:results = Invoke-AnalyzerEngine $hc
        }

        It "Display Results - Exchange Information" {
            SetActiveDisplayGrouping "Exchange Information"

            TestObjectMatch "Name" $env:COMPUTERNAME
            TestObjectMatch "Version" "Exchange 2016 CU22"
            TestObjectMatch "Build Number" "15.01.2375.007"
            TestObjectMatch "Server Role" "Mailbox"
            TestObjectMatch "DAG Name" "Standalone Server"
            TestObjectMatch "AD Site" "Default-First-Site-Name"
            TestObjectMatch "MAPI/HTTP Enabled" "True"
            TestObjectMatch "Exchange Server Maintenance" "Server is not in Maintenance Mode" -WriteType "Green"
            TestObjectMatch "Internet Web Proxy" "Not Set"
            $Script:ActiveGrouping.Count | Should -Be 10
        }

        It "Display Results - Operating System Information" {
            SetActiveDisplayGrouping "Operating System Information"

            TestObjectMatch "Version" "Microsoft Windows Server 2016 Datacenter"
            TestObjectMatch "Time Zone" "Pacific Standard Time"
            TestObjectMatch "Dynamic Daylight Time Enabled" "True"
            TestObjectMatch ".NET Framework" "4.8" -WriteType "Green"
            TestObjectMatch "Power Plan" "Balanced --- Error"-WriteType "Red"
            $httpProxy = GetObject "Http Proxy Setting"
            $httpProxy.ProxyAddress | Should -Be "None"
            TestObjectMatch "Visual C++ 2012" "Redistributable is outdated" -WriteType "Yellow"
            TestObjectMatch "Visual C++ 2013" "Redistributable is outdated" -WriteType "Yellow"
            TestObjectMatch "Server Pending Reboot" $false

            $pageFile = GetObject "Page File Size 0"
            $pageFile.TotalPhysicalMemory | Should -Be 6144
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
            TestObjectMatch "Number of Physical Cores" 3 -WriteType "Green"
            TestObjectMatch "Number of Logical Cores" 6 -WriteType "Green"
            TestObjectMatch "All Processor Cores Visible" "Failed" -WriteType "Red"
            TestObjectMatch "Max Processor Speed" 2200
            TestObjectMatch "Physical Memory" 6

            $Script:ActiveGrouping.Count | Should -Be 9
        }

        It "Display Results - NIC Settings" {
            SetActiveDisplayGrouping "NIC Settings Per Active Adapter"

            TestObjectMatch "Interface Description" "Microsoft Hyper-V Network Adapter [Ethernet]"
            TestObjectMatch "Driver Date" "2006-06-21"
            TestObjectMatch "MTU Size" 1500
            TestObjectMatch "Max Processors" 3
            TestObjectMatch "Max Processor Number" 4
            TestObjectMatch "Number of Receive Queues" 3
            TestObjectMatch "RSS Enabled" "True" -WriteType "Green"
            TestObjectMatch "Link Speed" "10000 Mbps"
            TestObjectMatch "IPv6 Enabled" "True"
            TestObjectMatch "Address" "192.168.5.11\24 Gateway: 192.168.5.1"
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

            $Script:ActiveGrouping.Count | Should -Be 6
        }

        It "Display Results - Security Settings" {
            SetActiveDisplayGrouping "Security Settings"

            TestObjectMatch "LmCompatibilityLevel Settings" 3
            TestObjectMatch "SMB1 Installed" "True" -WriteType "Red"
            TestObjectMatch "SMB1 Blocked" "False" -WriteType "Red"
            TestObjectMatch "Windows service" "Running"
            TestObjectMatch "Pattern service" "Unreachable`r`n`t`tMore information: https://aka.ms/HelpConnectivityEEMS" -WriteType "Yellow"
            TestObjectMatch "Telemetry enabled" "False"

            $Script:ActiveGrouping.Count | Should -Be 72
        }

        It "Display Results - Security Vulnerability" {
            SetActiveDisplayGrouping "Security Vulnerability"

            $cveTests = GetObject "Security Vulnerability"
            $cveTests.Contains("CVE-2020-1147") | Should -Be $true
            $downlaodDomains = GetObject "CVE-2021-1730"
            $downlaodDomains.DownloadDomainsEnabled | Should -Be "false"

            $Script:ActiveGrouping.Count | Should -Be 2
        }
    }
}
