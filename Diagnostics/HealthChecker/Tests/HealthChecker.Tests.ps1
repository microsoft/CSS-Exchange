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
    }

    Context "Testing Exchange 2016 CU18" {

        BeforeAll {
            $Script:results = Invoke-AnalyzerEngine (Import-Clixml "$Script:parentPath\Tests\Analyzer\E16_CU18.xml")

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

                ($Script:ActiveGrouping | Where-Object { $_.Name -eq $Name }).TestingValue
            }

            Function TestObjectMatch {
                [CmdletBinding()]
                param(
                    [Parameter(Mandatory = $true, Position = 1)]
                    [string]$Name,

                    [Parameter(Mandatory = $true, Position = 2)]
                    [object]$ResultValue
                )

                GetObject $Name |
                    Should -Be $ResultValue
            }
        }

        It "Display Results - Exchange Information" {
            SetActiveDisplayGrouping "Exchange Information"

            TestObjectMatch "Name" "SOLO-E16A"
            TestObjectMatch "Version" "Exchange 2016 CU18"
            TestObjectMatch "Build Number" "15.1.2106.2"
            TestObjectMatch "DAG Name" "Standalone Server"
            TestObjectMatch "AD Site" "Default-First-Site-Name"
            TestObjectMatch "MAPI/HTTP Enabled" $true
            TestObjectMatch "Exchange Server Maintenance" "Server is not in Maintenance Mode"
            $Script:ActiveGrouping.Count | Should -Be 10
        }

        It "Display Results - Operating System Information" {
            SetActiveDisplayGrouping "Operating System Information"

            TestObjectMatch "Version" "Microsoft Windows Server 2016 Datacenter"
            TestObjectMatch "Time Zone" "Central Standard Time"
            TestObjectMatch "Dynamic Daylight Time Enabled" $true
            TestObjectMatch ".NET Framework" "4.8"
            TestObjectMatch "Power Plan" "Balanced --- Error"
            TestObjectMatch "Http Proxy Setting" "<None>"
            TestObjectMatch "Visual C++ 2012" "Redistributable is outdated"
            TestObjectMatch "Visual C++ 2013" "Redistributable is outdated"
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

            $Script:ActiveGrouping.Count | Should -Be 12
        }

        It "Display Results - Process/Hardware Information" {
            SetActiveDisplayGrouping "Processor/Hardware Information"

            TestObjectMatch "Type" "HyperV"
            TestObjectMatch "Processor" "Intel(R) Xeon(R) CPU E5-2430 0 @ 2.20GHz"
            TestObjectMatch "Number of Processors" 1
            TestObjectMatch "Number of Physical Cores" 3
            TestObjectMatch "Number of Logical Cores" 6
            TestObjectMatch "All Processor Cores Visible" "Passed"
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
            TestObjectMatch "RSS Enabled" $true
            TestObjectMatch "Link Speed" "10000 Mbps"
            TestObjectMatch "IPv6 Enabled" $true
            TestObjectMatch "Address" "192.168.5.11\24 Gateway: 192.168.5.1"
            TestObjectMatch "Registered In DNS" $true
            TestObjectMatch "Packets Received Discarded" 0

            $Script:ActiveGrouping.Count | Should -Be 16
        }

        It "Display Results - Frequent Configuration Issues" {
            SetActiveDisplayGrouping "Frequent Configuration Issues"

            TestObjectMatch "TCP/IP Settings" 0
            TestObjectMatch "RPC Min Connection Timeout" 0
            TestObjectMatch "FIPS Algorithm Policy Enabled" 0
            TestObjectMatch "CTS Processor Affinity Percentage" 0
            TestObjectMatch "Credential Guard Enabled" $false
            TestObjectMatch "EdgeTransport.exe.config Present" $true

            $Script:ActiveGrouping.Count | Should -Be 6
        }

        It "Display Results - Security Settings" {
            SetActiveDisplayGrouping "Security Settings"

            TestObjectMatch "LmCompatibilityLevel Settings" 3
            TestObjectMatch "SMB1 Installed" $true
            TestObjectMatch "SMB1 Blocked" "False"

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
}
