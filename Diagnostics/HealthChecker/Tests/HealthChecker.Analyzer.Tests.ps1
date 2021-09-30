# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    . $PSScriptRoot\..\..\..\.build\BuildFunctions\Get-ExpandedScriptContent.ps1
    . $PSScriptRoot\..\Helpers\Class.ps1
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
}

Describe "Testing Analyzer" {

    BeforeAll {
        $scriptContent = Get-ExpandedScriptContent -File "$Script:parentPath\Analyzer\Invoke-AnalyzerEngine.ps1"
        $scriptContentString = [string]::Empty
        $scriptContent | ForEach-Object { $scriptContentString += "$($_)`n" }

        Invoke-Expression $scriptContentString

        Function SetActiveDisplayGrouping {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true, Position = 1)]
                [string]$Name
            )
            $key = $results.DisplayResults.Keys | Where-Object { $_.Name -eq $Name }
            $Script:ActiveGrouping = $results.DisplayResults[$key]
        }

        Function GetObject {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true, Position = 1)]
                [string]$Name
            )

            ($Script:ActiveGrouping | Where-Object { $_.TestingName -eq $Name }).TestingValue
        }

        Function GetWriteTypeObject {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true, Position = 1)]
                [string]$Name
            )

            ($Script:ActiveGrouping | Where-Object { $_.TestingName -eq $Name }).WriteType
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

    Context "Testing Exchange 2013 CU23" {

        BeforeAll {
            $Script:results = Invoke-AnalyzerEngine (Import-Clixml "$Script:parentPath\Tests\Analyzer\E15_CU23.xml")
        }

        It "Display Results - Exchange Information" {
            SetActiveDisplayGrouping "Exchange Information"

            TestObjectMatch "Name" "SOLO-E15A"
            TestObjectMatch "Version" "Exchange 2013 CU23"
            TestObjectMatch "Build Number" "15.0.1497.2"
            TestObjectMatch "Server Role" "MultiRole"
            TestObjectMatch "DAG Name" "Standalone Server"
            TestObjectMatch "AD Site" "Default-First-Site-Name"
            TestObjectMatch "MAPI/HTTP Enabled" $true
            TestObjectMatch "MAPI Front End App Pool GC Mode" "Workstation --- Warning" -WriteType "Yellow"
            $Script:ActiveGrouping.Count | Should -Be 11
        }

        It "Display Results - Operating System Information" {
            SetActiveDisplayGrouping "Operating System Information"

            TestObjectMatch "Version" "Microsoft Windows Server 2012 R2 Datacenter"
            TestObjectMatch "Time Zone" "Pacific Standard Time"
            TestObjectMatch "Dynamic Daylight Time Enabled" $true
            TestObjectMatch ".NET Framework" "4.8" -WriteType "Green"
            TestObjectMatch "Power Plan" "Balanced --- Error" -WriteType "Red"
            TestObjectMatch "Http Proxy Setting" "<None>"
            TestObjectMatch "Visual C++ 2012" "184610406 Version is current" -WriteType "Green"
            TestObjectMatch "Visual C++ 2013" "Redistributable is outdated" -WriteType "Yellow"
            TestObjectMatch "Server Pending Reboot" $false

            $upTime = GetObject "System Up Time"
            $upTime.Days | Should -Be 0
            $upTime.Hours | Should -Be 2
            $upTime.Minutes | Should -Be 58
            $upTime.Seconds | Should -Be 40

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
            TestObjectMatch "IPv6 Enabled" $true
            TestObjectMatch "Address" "192.168.9.11\24 Gateway: 192.168.9.1"
            TestObjectMatch "Registered In DNS" $true
            TestObjectMatch "Packets Received Discarded" 0 -WriteType "Green"

            $Script:ActiveGrouping.Count | Should -Be 16
        }

        It "Display Results - Frequent Configuration Issues" {
            SetActiveDisplayGrouping "Frequent Configuration Issues"

            TestObjectMatch "TCP/IP Settings" 800000 -WriteType "Yellow"
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
            TestObjectMatch "SMB1 Installed" $true -WriteType "Red"
            TestObjectMatch "SMB1 Blocked" "False" -WriteType "Red"

            $Script:ActiveGrouping.Count | Should -Be 72
        }

        It "Display Results - Security Vulnerability" {
            SetActiveDisplayGrouping "Security Vulnerability"

            $cveTests = $Script:ActiveGrouping.TestingValue | Where-Object { $_.StartsWith("CVE") }
            $cveTests.Contains("CVE-2020-1147") | Should -Be $true
        }
    }

    Context "Testing Exchange 2016 CU18" {

        BeforeAll {
            $Script:results = Invoke-AnalyzerEngine (Import-Clixml "$Script:parentPath\Tests\Analyzer\E16_CU18.xml")
        }

        It "Display Results - Exchange Information" {
            SetActiveDisplayGrouping "Exchange Information"

            TestObjectMatch "Name" "SOLO-E16A"
            TestObjectMatch "Version" "Exchange 2016 CU18"
            TestObjectMatch "Build Number" "15.1.2106.2"
            TestObjectMatch "Server Role" "Mailbox"
            TestObjectMatch "DAG Name" "Standalone Server"
            TestObjectMatch "AD Site" "Default-First-Site-Name"
            TestObjectMatch "MAPI/HTTP Enabled" $true
            TestObjectMatch "Exchange Server Maintenance" "Server is not in Maintenance Mode" -WriteType "Green"
            TestObjectMatch "Out of Date" $true -WriteType "Red"
            $Script:ActiveGrouping.Count | Should -Be 10
        }

        It "Display Results - Operating System Information" {
            SetActiveDisplayGrouping "Operating System Information"

            TestObjectMatch "Version" "Microsoft Windows Server 2016 Datacenter"
            TestObjectMatch "Time Zone" "Central Standard Time"
            TestObjectMatch "Dynamic Daylight Time Enabled" $false -WriteType "Red"
            TestObjectMatch ".NET Framework" "4.8" -WriteType "Green"
            TestObjectMatch "Power Plan" "Balanced --- Error"-WriteType "Red"
            TestObjectMatch "Http Proxy Setting" "<None>"
            TestObjectMatch "Visual C++ 2012" "Redistributable is outdated" -WriteType "Yellow"
            TestObjectMatch "Visual C++ 2013" "Redistributable is outdated" -WriteType "Yellow"
            TestObjectMatch "Server Pending Reboot" $false

            $upTime = GetObject "System Up Time"
            $upTime.Days | Should -Be 0
            $upTime.Hours | Should -Be 2
            $upTime.Minutes | Should -Be 14
            $upTime.Seconds | Should -Be 57

            $pageFile = GetObject "Page File Size"
            $pageFile.TotalPhysicalMemory | Should -Be 6442450944
            $pageFile.MaxPageSize | Should -Be 0
            $pageFile.MultiPageFile | Should -Be $false
            $pageFile.RecommendedPageFile | Should -Be 0

            $Script:ActiveGrouping.Count | Should -Be 13
        }

        It "Display Results - Process/Hardware Information" {
            SetActiveDisplayGrouping "Processor/Hardware Information"

            TestObjectMatch "Type" "HyperV"
            TestObjectMatch "Processor" "Intel(R) Xeon(R) CPU E5-2430 0 @ 2.20GHz"
            TestObjectMatch "Number of Processors" 1
            TestObjectMatch "Number of Physical Cores" 24 -WriteType "Yellow"
            TestObjectMatch "Number of Logical Cores" 48 -WriteType "Yellow"
            TestObjectMatch "All Processor Cores Visible" "Failed" -WriteType "Red"
            TestObjectMatch "Max Processor Speed" 2200
            TestObjectMatch "Current Processor Speed" 0 -WriteType "Red"
            TestObjectMatch "Physical Memory" 6

            $Script:ActiveGrouping.Count | Should -Be 11
        }

        It "Display Results - NIC Settings" {
            SetActiveDisplayGrouping "NIC Settings Per Active Adapter"

            TestObjectMatch "Interface Description" "Microsoft Hyper-V Network Adapter [Ethernet]"
            TestObjectMatch "Driver Date" "2006-06-21"
            TestObjectMatch "MTU Size" 1500
            TestObjectMatch "Max Processors" 3
            TestObjectMatch "Max Processor Number" 4
            TestObjectMatch "Number of Receive Queues" 3
            TestObjectMatch "RSS Enabled" $true -WriteType "Green"
            TestObjectMatch "Link Speed" "10000 Mbps"
            TestObjectMatch "IPv6 Enabled" $true
            TestObjectMatch "Address" "192.168.5.11\24 Gateway: 192.168.5.1"
            TestObjectMatch "Registered In DNS" $true
            TestObjectMatch "Packets Received Discarded" 0 -WriteType "Green"

            $Script:ActiveGrouping.Count | Should -Be 16
        }

        It "Display Results - Frequent Configuration Issues" {
            SetActiveDisplayGrouping "Frequent Configuration Issues"

            TestObjectMatch "TCP/IP Settings" 900000 -WriteType "Green"
            TestObjectMatch "RPC Min Connection Timeout" 0
            TestObjectMatch "FIPS Algorithm Policy Enabled" 0
            TestObjectMatch "CTS Processor Affinity Percentage" 10 -WriteType "Red"
            TestObjectMatch "Credential Guard Enabled" $false
            TestObjectMatch "EdgeTransport.exe.config Present" "False --- Error" -WriteType "Red"

            $Script:ActiveGrouping.Count | Should -Be 6
        }

        It "Display Results - Security Settings" {
            SetActiveDisplayGrouping "Security Settings"

            TestObjectMatch "LmCompatibilityLevel Settings" 3
            TestObjectMatch "SMB1 Installed" $true -WriteType "Red"
            TestObjectMatch "SMB1 Blocked" "False" -WriteType "Red"

            $Script:ActiveGrouping.Count | Should -Be 71
        }

        It "Display Results - Security Vulnerability" {
            SetActiveDisplayGrouping "Security Vulnerability"

            $cveTests = $Script:ActiveGrouping.TestingValue | Where-Object { $_.StartsWith("CVE") }
            $cveTests.Contains("CVE-2020-16969") | Should -Be $true
            $cveTests.Contains("CVE-2020-17083") | Should -Be $true
            $cveTests.Contains("CVE-2020-17084") | Should -Be $true
            $cveTests.Contains("CVE-2020-17085") | Should -Be $true
            $cveTests.Contains("CVE-2020-17117") | Should -Be $true
            $cveTests.Contains("CVE-2020-17132") | Should -Be $true
            $cveTests.Contains("CVE-2020-17141") | Should -Be $true
            $cveTests.Contains("CVE-2020-17142") | Should -Be $true
            $cveTests.Contains("CVE-2020-17143") | Should -Be $true
            $cveTests.Contains("CVE-2021-24085") | Should -Be $true
            $cveTests.Contains("CVE-2021-26855") | Should -Be $true
            $cveTests.Contains("CVE-2021-26857") | Should -Be $true
            $cveTests.Contains("CVE-2021-26858") | Should -Be $true
            $cveTests.Contains("CVE-2021-27065") | Should -Be $true
            $cveTests.Contains("CVE-2021-26412") | Should -Be $true
            $cveTests.Contains("CVE-2021-27078") | Should -Be $true
            $cveTests.Contains("CVE-2021-26854") | Should -Be $true
            $cveTests.Contains("CVE-2021-28480") | Should -Be $true
            $cveTests.Contains("CVE-2021-28481") | Should -Be $true
            $cveTests.Contains("CVE-2021-28482") | Should -Be $true
            $cveTests.Contains("CVE-2021-28483") | Should -Be $true
            $cveTests.Contains("CVE-2021-31195") | Should -Be $true
            $cveTests.Contains("CVE-2021-31198") | Should -Be $true
            $cveTests.Contains("CVE-2021-31207") | Should -Be $true
            $cveTests.Contains("CVE-2021-31209") | Should -Be $true
            $cveTests.Contains("CVE-2021-31206") | Should -Be $true
            $cveTests.Contains("CVE-2021-31196") | Should -Be $true
            $cveTests.Contains("CVE-2021-33768") | Should -Be $true
            $cveTests.Contains("CVE-2020-1147") | Should -Be $true
            $cveTests.Contains("CVE-2021-34470") | Should -Be $true
            $cveTests.Contains("CVE-2021-1730") | Should -Be $true

            $Script:ActiveGrouping.Count | Should -Be 31
        }
    }

    Context "Testing Exchange 2019 CU11" {

        BeforeAll {
            $Script:results = Invoke-AnalyzerEngine (Import-Clixml "$Script:parentPath\Tests\Analyzer\E19_CU11.xml")
        }

        It "Display Results - Exchange Information" {
            SetActiveDisplayGrouping "Exchange Information"

            TestObjectMatch "Name" "SOLO-E19A"
            TestObjectMatch "Version" "Exchange 2019 CU11"
            TestObjectMatch "Build Number" "15.2.986.5"
            TestObjectMatch "Server Role" "Mailbox"
            TestObjectMatch "DAG Name" "Standalone Server"
            TestObjectMatch "AD Site" "Default-First-Site-Name"
            TestObjectMatch "MAPI/HTTP Enabled" $true
            $Script:ActiveGrouping.Count | Should -Be 11
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

            $upTime = GetObject "System Up Time"
            $upTime.Days | Should -Be 0
            $upTime.Hours | Should -Be 2
            $upTime.Minutes | Should -Be 15
            $upTime.Seconds | Should -Be 56

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

            TestObjectMatch "TCP/IP Settings" 0 -WriteType "Red"
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
            TestObjectMatch "Pattern service" "Unreachable`r`n`t`tMore information: https://aka.ms/HelpConnectivityEEMS" -WriteType "Yellow"
            TestObjectMatch "Telemetry enabled" "False"

            $Script:ActiveGrouping.Count | Should -Be 74
        }

        It "Display Results - Security Vulnerability" {
            SetActiveDisplayGrouping "Security Vulnerability"

            $cveTests = $Script:ActiveGrouping.TestingValue | Where-Object { $_.StartsWith("CVE") }
            $cveTests.Contains("CVE-2020-1147") | Should -Be $true
            $cveTests.Contains("CVE-2021-1730") | Should -Be $true
        }
    }

    Context "Testing Exchange 2019 CU11" {

        BeforeAll {
            $Script:results = Invoke-AnalyzerEngine (Import-Clixml "$Script:parentPath\Tests\Analyzer\E19_Edge_CU9.xml")
        }

        It "Display Results - Exchange Information" {
            SetActiveDisplayGrouping "Exchange Information"

            TestObjectMatch "Server Role" "Edge"
            $Script:ActiveGrouping.Count | Should -Be 9
        }

        It "Display Results - Operating System Information" {
            SetActiveDisplayGrouping "Operating System Information"
            $Script:ActiveGrouping.Count | Should -Be 10
        }

        It "Display Results - Process/Hardware Information" {
            SetActiveDisplayGrouping "Processor/Hardware Information"
            $Script:ActiveGrouping.Count | Should -Be 9
        }

        It "Display Results - NIC Settings" {
            SetActiveDisplayGrouping "NIC Settings Per Active Adapter"
            $Script:ActiveGrouping.Count | Should -Be 16
        }

        It "Display Results - Frequent Configuration Issues" {
            SetActiveDisplayGrouping "Frequent Configuration Issues"
            $Script:ActiveGrouping.Count | Should -Be 6
        }

        It "Display Results - Security Settings" {
            SetActiveDisplayGrouping "Security Settings"
            $Script:ActiveGrouping.Count | Should -Be 54
        }
    }
}
