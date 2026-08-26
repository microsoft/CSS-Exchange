# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# PesterPriority: High
# Scenario testing for Exchange SE - consolidated from E19 scenario patterns
# Each context packs multiple non-conflicting mock overrides into a single
# SetDefaultRunOfHealthChecker call to minimize pipeline execution count.
[CmdletBinding()]
param()

Describe "Exchange SE Scenarios Testing" {

    BeforeAll {
        . $PSScriptRoot\HealthCheckerTests.ImportCode.NotPublished.ps1
        $Script:MockDataCollectionRoot = "$Script:parentPath\Tests\DataCollection\ExchangeSE"
        . $PSScriptRoot\HealthCheckerTest.CommonMocks.NotPublished.ps1

        $Script:guidRegEx = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    }

    Context "Comprehensive Problem Scenario" {
        BeforeAll {
            # Windows Server 2025 ships with .NET 4.8.1
            Mock Get-NETFrameworkVersion {
                return [PSCustomObject]@{
                    FriendlyName  = "4.8.1"
                    RegistryValue = 533320
                    MinimumValue  = 533320
                }
            }

            # Fold in the Get-MailboxServer throw test (replaces separate context in Main)
            Mock Get-MailboxServer { throw "Pester testing" }

            # Registry overrides
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "KeepAliveTime" } -MockWith { return 0 }
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "CtsProcessorAffinityPercentage" } -MockWith { return 10 }
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "LsaCfgFlags" } -MockWith { return 1 }
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "DisableRootAutoUpdate" } -MockWith { return 1 }

            # Missing config files
            Mock Test-Path -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\EdgeTransport.exe.config" } -MockWith { return $false }
            Mock Test-Path -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\Runtime\1.0\noderunner.exe.config" } -MockWith { return $false }
            Mock Get-Content -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\EdgeTransport.exe.config" } -MockWith { return $null }
            Mock Get-Content -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\Runtime\1.0\noderunner.exe.config" } -MockWith { return $null }

            # OS state overrides
            Mock Get-ServerRebootPending { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetServerRebootPending1.xml" }
            Mock Get-HttpProxySetting { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetHttpProxySetting1.xml" }

            # TLS misconfiguration
            Mock Get-AllTlsSettings { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetAllTlsSettings1.xml" }

            # Exchange overrides
            Mock Get-OrganizationConfig { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOrganizationConfig1.xml" }
            Mock Get-OwaVirtualDirectory { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOwaVirtualDirectory1.xml" }
            Mock Get-AcceptedDomain { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetAcceptedDomain_Problem.xml" }

            # Missing shared config
            Mock Test-Path -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\SharedWebConfig.config" } -MockWith { return $false }

            # IIS overrides
            Mock Get-WebSite -ParameterFilter { $null -eq $Name } -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\IIS\GetWebSite2.xml" }
            Mock Get-WebConfigFile -ParameterFilter { $PSPath -eq "IIS:\Sites\Exchange Back End/ecp" } -MockWith { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\ClientAccess\ecp\web.config" } }
            Mock Get-WebConfigFile -ParameterFilter { $PSPath -eq "IIS:\Sites\Default Web Site/ecp" } -MockWith { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite_web.config" } }
            Mock Get-Content -ParameterFilter { $Path -eq "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config" } -MockWith { return Get-Content "$Script:MockDataCollectionRoot\Exchange\IIS\applicationHost1.config" -Raw -Encoding UTF8 }

            # Variant configuration / diagnostics
            Mock Get-ExchangeDiagnosticInfo -ParameterFilter { $Process -eq "Microsoft.Exchange.Directory.TopologyService" -and $Component -eq "VariantConfiguration" -and $Argument -eq "Overrides" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeDiagnosticInfo_ADTopVariantConfiguration1.xml" }
            Mock Get-ExchangeDiagnosticInfo -ParameterFilter { $Process -eq "EdgeTransport" -and $Component -eq "ResourceThrottling" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeDiagnosticInfo_EdgeTransportResourceThrottling1.xml" }

            # TokenCacheModule not loaded
            Mock Get-IISModules { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetIISModulesNoTokenCacheModule.xml" }

            # Exchange membership failed
            Mock GetExchangeServerADInformation { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeServerADInformation2.xml" }
            Mock Get-LocalGroupMember { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetLocalGroupMember2.xml" }

            # Windows features (MSMQ installed) # cspell:ignore MSMQ
            Mock Get-WindowsFeature { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetWindowsFeature1.xml" }

            # SMB misconfiguration
            Mock Get-SmbServerConfiguration { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetSmbServerConfiguration1.xml" }

            # Monitoring overrides
            Mock Get-GlobalMonitoringOverride { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetGlobalMonitoringOverride.xml" }
            Mock Get-ServerMonitoringOverride { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetServerMonitoringOverride.xml" }

            # Event log entries too recent (only 1 day old)
            Mock Get-WinEvent -ParameterFilter { $LogName -eq "Application" -and $Oldest -eq $true -and $MaxEvents -eq 1 } -MockWith {
                $r = Import-Clixml "$Script:MockDataCollectionRoot\OS\GetWinEventOldestApplication.xml"
                $r.TimeCreated = ((Get-Date).AddDays(-1))
                return $r
            }
            Mock Get-WinEvent -ParameterFilter { $LogName -eq "System" -and $Oldest -eq $true -and $MaxEvents -eq 1 } -MockWith {
                $r = Import-Clixml "$Script:MockDataCollectionRoot\OS\GetWinEventOldestSystem.xml"
                $r.TimeCreated = ((Get-Date).AddDays(-1))
                return $r
            }

            # Services: MSExchangeMitigation variant + stopped services
            Mock Get-Service {
                param(
                    [string]$ComputerName,
                    [string]$Name
                )
                if ($Name -eq "MSExchangeMitigation") { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetServiceMitigation.xml" }
                return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetService1.xml"
            }

            # Dynamic memory detection
            Mock Get-LocalizedCounterSamples {
                $objList = New-Object System.Collections.Generic.List[object]
                $objList.Add(([PSCustomObject]@{
                            OriginalCounterLookup = "\Processor(_Total)\% Processor Time"
                            CookedValue           = 55.55555
                        }))
                $objList.Add(([PSCustomObject]@{
                            OriginalCounterLookup = "\Hyper-V Dynamic Memory Integration Service\Maximum Memory, MBytes"
                            CookedValue           = 24576
                        }))
                return $objList
            }

            # PageFile well-configured (tests correct PageFile path)
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PageFileWellConfigured.xml" }

            # Hybrid S3: AuthServer missing — HybridConfig + SO2 + AuthServer returns ACS only
            # (packed — SO2 mock change does not affect "Setting Overrides Detected", which comes from VariantConfiguration)
            Mock Get-HybridConfiguration -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetHybridConfiguration.xml" }
            Mock Get-SettingOverride -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetSettingOverride2.xml" }
            $Script:GetAuthServerMockDataType = "ACS"

            SetDefaultRunOfHealthChecker "Debug_SE_Scenario1_Results.xml"
        }

        It "Pipeline survives Get-MailboxServer throw" {
            SetActiveDisplayGrouping "Exchange Information"
            TestObjectMatch "DAG Name" "Standalone Server"
        }

        It "Generic Exchange Information" {
            SetActiveDisplayGrouping "Exchange Information"
            TestObjectMatch "Setting Overrides Detected" $true
            TestObjectMatch "Extended Protection Enabled (Any VDir)" $true
            TestObjectMatch "Transport Back Pressure" "--ERROR-- The following resources are causing back pressure: DatabaseUsedSpace" -WriteType "Red"
            TestObjectMatch "Exchange Server Membership" "Failed" -WriteType "Red"
            TestObjectMatch "Exchange Trusted Subsystem - Local System Membership" "Exchange Trusted Subsystem - Local System Membership" -WriteType "Red"
            TestObjectMatch "Exchange Trusted Subsystem - AD Group Membership" "Exchange Trusted Subsystem - AD Group Membership" -WriteType "Red"
            TestObjectMatch "Monitoring Overrides Detected" $true
        }

        It "Dependent Services" {
            $displayFormat = "{0} - Status: {1} - StartType: {2}"
            TestObjectMatch "Critical Pla" ($displayFormat -f "pla", "Stopped", "Manual") -WriteType "Red"
            TestObjectMatch "Critical HostControllerService" ($displayFormat -f "HostControllerService", "Stopped", "Disabled") -WriteType "Red"
            TestObjectMatch "Common MSExchangeDagMgmt" ($displayFormat -f "MSExchangeDagMgmt", "Stopped", "Automatic") -WriteType "Yellow"
        }

        It "Dynamic Memory Set" {
            SetActiveDisplayGrouping "Processor/Hardware Information"
            TestObjectMatch "Dynamic Memory Detected" "True 24GB is the allowed dynamic memory of the server. Not supported to have dynamic memory configured." -WriteType "Red"
        }

        It "Http Proxy Settings" {
            SetActiveDisplayGrouping "Operating System Information"
            $httpProxy = GetObject "Http Proxy Setting"
            $httpProxy.ProxyAddress | Should -Be "proxy.contoso.com:8080"
            $httpProxy.ByPassList | Should -Be "localhost;*.contoso.com;*microsoft.com"
            $httpProxy.HttpProxyDifference | Should -Be "False"
            $httpProxy.HttpByPassDifference | Should -Be "False"
        }

        It "PageFile Configured As Expected" {
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

        It "Message Queuing Feature" {
            TestObjectMatch "Messaging Queuing Feature" $true -WriteType "Yellow"
        }

        It "Event Log Size Test" {
            GetObject "Event Log - Application" |
                Should -BeLike "--ERROR-- Not enough logs to cover 7 days. Oldest log entry is at *. This could cause issues with determining Root Cause Analysis."
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

        It "Trusted Root Certificates Auto Update Disabled" {
            TestObjectMatch "Trusted Root Certificates Auto Update Disabled" $true -WriteType "Yellow"
        }

        It "EdgeTransport.exe.config Present" {
            TestObjectMatch "EdgeTransport.exe.config Present" "False --- Error" -WriteType "Red"
        }

        It "noderunner.exe.config Present" {
            TestObjectMatch "noderunner.exe.config Present" "False --- Error" -WriteType "Red"
        }

        It "Open Relay Wild Card Domain" {
            TestObjectMatch "Open Relay Wild Card Domain" "Error --- Accepted Domain `"Problem Accepted Domain`" is set to a Wild Card (*) Domain Name with a domain type of InternalRelay. This is not recommended as this is an open relay for the entire environment.`r`n`t`tMore Information: https://aka.ms/HC-OpenRelayDomain" -WriteType "Red"
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

        It "EEMS Enabled And OCS Reachable" {
            SetActiveDisplayGrouping "Security Settings"
            TestObjectMatch "Exchange Emergency Mitigation Service" "Enabled" -WriteType "Green"
            TestObjectMatch "Windows service" "Running"
            TestObjectMatch "Pattern service" "200 - Reachable"
            TestObjectMatch "Telemetry enabled" $true
        }

        It "Download Domains" {
            SetActiveDisplayGrouping "Security Vulnerability"
            $downloadDomains = GetObject "CVE-2021-1730"
            $downloadDomains.DownloadDomainsEnabled | Should -Be "True"
            $downloadDomains.ExternalDownloadHostName | Should -Be "Set to the same as Internal Or External URL as OWA."
            $downloadDomains.InternalDownloadHostName | Should -Be "Set to the same as Internal Or External URL as OWA."
        }

        It "CVE-2023-36434 Test - Module Not loaded" {
            SetActiveDisplayGrouping "Security Vulnerability"
            $cveEntries = GetObject "Security Vulnerability"
            $cveEntries.Contains("CVE-2023-36434") | Should -Be $false
            SetActiveDisplayGrouping "Exchange IIS Information"
            TestObjectMatch "TokenCacheModule loaded" $true -WriteType "Yellow"
        }

        It "Missing Web Application Configuration File" {
            SetActiveDisplayGrouping "Exchange IIS Information"
            TestObjectMatch "Missing Web Application Configuration File" $true -WriteType "Red"
            TestObjectMatch "Web Application: 'Default Web Site/ecp'" "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite_web.config" -WriteType "Red"
        }

        It "Testing Missing Shared Configuration File" {
            TestObjectMatch "Missing Shared Configuration File" $true -WriteType "Red"
        }

        It "Testing Default Variable Detected" {
            TestObjectMatch "Default Variable Detected" $true -WriteType "Red"
        }

        It "Testing Bin Search Folder Not Found" {
            TestObjectMatch "Bin Search Folder Not Found" $true -WriteType "Red"
        }

        It "Testing Native HSTS Default Web Site" {
            TestObjectMatch "hsts-Enabled-Default Web Site" $true -WriteType "Green"
            TestObjectMatch "hsts-max-age-Default Web Site" 300 -WriteType "Yellow"
            TestObjectMatch "hsts-includeSubDomains-Default Web Site" $false
            TestObjectMatch "hsts-preload-Default Web Site" $false
            TestObjectMatch "hsts-redirectHttpToHttps-Default Web Site" $false
        }

        It "Testing Native HSTS Exchange Back End" {
            TestObjectMatch "hsts-Enabled-Exchange Back End" $true -WriteType "Red"
            TestObjectMatch "hsts-max-age-Exchange Back End" 31536000 -WriteType "Green"
            TestObjectMatch "hsts-includeSubDomains-Exchange Back End" $false
            TestObjectMatch "hsts-preload-Exchange Back End" $false
            TestObjectMatch "hsts-redirectHttpToHttps-Exchange Back End" $true -WriteType "Red"
            TestObjectMatch "hsts-BackendNotSupported" $true -WriteType "Red"

            TestObjectMatch "hsts-MoreInfo" $true -WriteType "Yellow"
        }

        It "Dedicated Hybrid App Configured But AuthServer Is Missing" {
            SetActiveDisplayGrouping "Hybrid Information"
            GetObject "NoValidAuthServer" | Should -Be $true
            GetObject "DedicatedHybridAppShowMoreInformation" | Should -Be $true
        }
    }

    Context "Alternate Configuration Scenario" {
        BeforeAll {
            # SettingOverride with SerializedDataSigning enabled (no AMSI override at org level)
            Mock Get-SettingOverride { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetSettingOverride1.xml" }
            # VariantConfiguration2: AMSI override removed from per-server data (tests AMSI=True/Green)
            Mock Get-ExchangeDiagnosticInfo -ParameterFilter { $Process -eq "Microsoft.Exchange.Directory.TopologyService" -and $Component -eq "VariantConfiguration" -and $Argument -eq "Overrides" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeDiagnosticInfo_ADTopVariantConfiguration2.xml" }

            # Registry overrides
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "KeepAliveTime" } -MockWith { return 1800000 }
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "DisableGranularReplication" } -MockWith { return 1 }
            Mock Get-RemoteRegistryValue -ParameterFilter { $GetValue -eq "DisableAsyncNotification" } -MockWith { return 1 }

            # TLS with 1.3 enabled
            Mock Get-AllTlsSettings { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetAllTlsSettings2.xml" }

            # Exchange overrides
            Mock Get-OrganizationConfig { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOrganizationConfig1.xml" }
            Mock Get-OwaVirtualDirectory { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOwaVirtualDirectory2.xml" }
            Mock Get-AcceptedDomain { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetAcceptedDomain_Bad.xml" }

            # NIC with no DNS registration
            Mock Get-DnsClient { return Import-Clixml "$Script:MockDataCollectionRoot\OS\GetDnsClient1.xml" }

            # IIS configuration
            Mock Get-Content -ParameterFilter { $Path -eq "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config" } -MockWith { return Get-Content "$Script:MockDataCollectionRoot\Exchange\IIS\applicationHost1.config" -Raw -Encoding UTF8 }

            # NodeRunner with 1024 MB memory limit
            Mock Get-Content -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\Runtime\1.0\noderunner.exe.config" } -MockWith { Get-Content "$Script:MockDataCollectionRoot\Exchange\noderunner.exe1.config" -Raw -Encoding UTF8 }

            # EdgeTransport with invalid config
            Mock Get-Content -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\EdgeTransport.exe.config" } -MockWith { Get-Content "$Script:MockDataCollectionRoot\Exchange\EdgeTransport.exe1.config" -Raw -Encoding UTF8 }

            # PageFile oversized
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PageFileSetting" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\OS\Win32_PageFileOverSized.xml" }

            SetDefaultRunOfHealthChecker "Debug_SE_Scenario2_Results.xml"
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

        It "Noderunner.exe.config memory limit" {
            TestObjectMatch "NodeRunner.exe memory limit" "1024 MB will limit the performance of search and can be more impactful than helpful if not configured correctly for your environment." -WriteType "Yellow"
        }

        It "EdgeTransport.exe.config invalid config" {
            TestObjectMatch "EdgeTransport.exe.config Invalid Config Format" $true -WriteType "Red"
        }

        It "EdgeTransport.exe.config invalid config for UnifiedContent" {
            TestObjectMatch "UnifiedContent Auto Cleanup Configured" "Error - EdgeTransport.exe.config Invalid Config Format" -WriteType "Red"
        }

        It "TLS Settings" {
            SetActiveDisplayGrouping "Security Settings"
            TestObjectMatch "TLS 1.0" "Misconfigured" -WriteType "Red"
            TestObjectMatch "TLS 1.1" "Misconfigured" -WriteType "Red"
            TestObjectMatch "TLS 1.2" "Enabled" -WriteType "Green"
            # SE + Windows Server 2025 supports TLS 1.3 — Enabled is Green (not Red like E19)
            TestObjectMatch "TLS 1.3" "Enabled" -WriteType "Green"

            TestObjectMatch "Display Link to Docs Page" "True" -WriteType "Yellow"
            TestObjectMatch "Detected TLS Mismatch Display More Info" "True" -WriteType "Yellow"

            $tlsCipherSuite = (GetObject "TLS Cipher Suite Group")
            $tlsCipherSuite.Count | Should -Be 8
        }

        It "AMSI Enabled" {
            SetActiveDisplayGrouping "Security Settings"
            # VariantConfiguration2 has no AMSI override → AMSI defaults to enabled
            TestObjectMatch "AMSI Enabled" "True" -WriteType "Green"
        }

        It "Enabled Domains" {
            SetActiveDisplayGrouping "Security Vulnerability"
            $downloadDomains = GetObject "CVE-2021-1730"
            $downloadDomains.DownloadDomainsEnabled | Should -Be "True"
            $downloadDomains.ExternalDownloadHostName | Should -Be "Set Correctly."
            $downloadDomains.InternalDownloadHostName | Should -Be "Not Configured"
        }

        It "Extended Protection" {
            $testFind = GetObject "Extended Protection Vulnerable"
            $testFind | Should -Be $null
        }

        It "No Register in DNS" {
            SetActiveDisplayGrouping "NIC Settings Per Active Adapter"
            TestObjectMatch "No NIC Registered In DNS" "Error: This will cause server to crash and odd mail flow issues. Exchange Depends on the primary NIC to have the setting Registered In DNS set." -WriteType "Red"
        }

        It "PageFile Oversized" {
            SetActiveDisplayGrouping "Operating System Information"
            $pageFile = GetObject "PageFile Size 0"
            $pageFile.Name | Should -Be "c:\pagefile.sys"
            $pageFile.TotalPhysicalMemory | Should -Be 6144
            $pageFile.MaxPageSize | Should -Be 2025
            $pageFile.MultiPageFile | Should -Be $false
            $pageFile.RecommendedPageFile | Should -Be 1536

            $pageFileAdditional = GetObject "PageFile Additional Information"
            $pageFileAdditional | Should -Be "Warning: On Exchange SE RTM, the recommended PageFile size is 25% (1536MB) of the total system memory (6144MB)."
        }
    }

    Context "Physical Hardware Scenario" {
        BeforeAll {
            # Physical server hardware mocks
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_ComputerSystem" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\Physical_Win32_ComputerSystem1.xml" }
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_PhysicalMemory" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\Physical_Win32_PhysicalMemory.xml" }
            Mock Get-WmiObjectHandler -ParameterFilter { $Class -eq "Win32_Processor" } `
                -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Hardware\Physical_Win32_Processor1.xml" }

            # IIS with mixed EP configuration (some vDirs not properly secured)
            Mock Get-Content -ParameterFilter { $Path -eq "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config" } -MockWith { return Get-Content "$Script:MockDataCollectionRoot\Exchange\IIS\applicationHost2.config" -Raw -Encoding UTF8 }

            # HSTS conflict: native IIS HSTS enabled (GetWebSite2) + Strict-Transport-Security customHeader (web2.config)
            Mock Get-WebSite -ParameterFilter { $null -eq $Name } -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\IIS\GetWebSite2.xml" }
            Mock Get-WebConfigFile -ParameterFilter { $PSPath -eq "IIS:\Sites\Default Web Site" } -MockWith { return [PSCustomObject]@{ FullName = "$Script:MockDataCollectionRoot\Exchange\IIS\DefaultWebSite_web2.config" } }

            # AntiMalware with mismatched UnifiedContent cleanup paths
            Mock Get-Content -ParameterFilter { $Path -eq "C:\Program Files\Microsoft\Exchange Server\V15\Bin\Monitoring\Config\AntiMalware.xml" } -MockWith { Get-Content "$Script:MockDataCollectionRoot\Exchange\Antimalware1.xml" -Raw -Encoding UTF8 }

            # Multiple dynamic distribution group PF mailboxes (count=2, triggers Red)
            Mock Get-DynamicDistributionGroup { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetDynamicDistributionGroupPfMailboxes1.xml" }

            # Hybrid S2: Dedicated hybrid app configured — HybridConfig + SO2
            # (packed — no SettingOverride assertions in this context)
            Mock Get-HybridConfiguration -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetHybridConfiguration.xml" }
            Mock Get-SettingOverride -MockWith { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetSettingOverride2.xml" }

            # Reset AuthServer to return both ACS + EvoSTS (S1 sets it to "ACS")
            $Script:GetAuthServerMockDataType = "All"

            # Legacy Exchange security groups present (security best practice cleanup).
            # Mock the underlying AD search so the real Get-ExchangeLegacySecurityGroups logic runs.
            Mock Search-AllActiveDirectoryDomains -ParameterFilter { $Filter -like "*Exchange Domain Servers*" } -MockWith {
                return @(
                    (NewMockAdSearchResult -DistinguishedName "CN=Exchange Domain Servers,CN=Users,DC=contoso,DC=com" -SamAccountName "Exchange Domain Servers" -GroupType -2147483646),
                    (NewMockAdSearchResult -DistinguishedName "CN=Exchange Enterprise Servers,CN=Users,DC=contoso,DC=com" -SamAccountName "Exchange Enterprise Servers" -GroupType -2147483644),
                    (NewMockAdSearchResult -DistinguishedName "CN=Exchange Recipient Administrators,OU=Microsoft Exchange Security Groups,DC=contoso,DC=com" -SamAccountName "Exchange Recipient Administrators" -GroupType -2147483640 -MemberCount 3)
                )
            }

            SetDefaultRunOfHealthChecker "Debug_SE_Scenario3_Physical_Results.xml"
        }

        It "Dynamic Public Folder Mailboxes" {
            SetActiveDisplayGrouping "Organization Information"
            TestObjectMatch "Dynamic Distribution Group Public Folder Mailboxes Count" 2 -WriteType "Red"
        }

        It "Legacy Exchange Security Groups Detected" {
            SetActiveDisplayGrouping "Organization Information"
            TestObjectMatch "Legacy Exchange Security Groups" $true -WriteType "Yellow"
        }

        It "Legacy Exchange Security Groups Parsed Correctly" {
            # Directly exercises the real Get-ExchangeLegacySecurityGroups parsing (scope decode from
            # groupType, member count, DN) against the mocked Search-AllActiveDirectoryDomains data.
            $legacyGroups = @(Get-ExchangeLegacySecurityGroups | Where-Object { $null -ne $_.DistinguishedName })
            $legacyGroups.Count | Should -Be 3

            $domainServers = $legacyGroups | Where-Object { $_.Name -eq "Exchange Domain Servers" }
            $domainServers.Scope | Should -Be "Global"
            $domainServers.MemberCount | Should -Be 0
            $domainServers.DistinguishedName | Should -Be "CN=Exchange Domain Servers,CN=Users,DC=contoso,DC=com"

            $enterpriseServers = $legacyGroups | Where-Object { $_.Name -eq "Exchange Enterprise Servers" }
            $enterpriseServers.Scope | Should -Be "DomainLocal"
            $enterpriseServers.MemberCount | Should -Be 0

            $recipientAdmins = $legacyGroups | Where-Object { $_.Name -eq "Exchange Recipient Administrators" }
            $recipientAdmins.Scope | Should -Be "Universal"
            $recipientAdmins.MemberCount | Should -Be 3
        }

        It "Extended Protection Enabled" {
            SetActiveDisplayGrouping "Exchange Information"
            TestObjectMatch "Extended Protection Enabled (Any VDir)" $true
            TestObjectMatch "EP - Default Web Site/OAB" "Require" -WriteType "Yellow"
        }

        It "Hardware Type" {
            SetActiveDisplayGrouping "Processor/Hardware Information"
            TestObjectMatch "Type" "Physical"
        }

        It "Number of Processors" {
            TestObjectMatch "Number of Processors" 4 -WriteType "Red"
        }

        It "Number of Physical Cores" {
            TestObjectMatch "Number of Physical Cores" 48 -WriteType "Green"
        }

        It "Number of Logical Cores" {
            TestObjectMatch "Number of Logical Cores" "96 - Error" -WriteType "Red"
        }

        It "Max Processor Speed" {
            TestObjectMatch "Max Processor Speed" 2201
        }

        It "Physical Memory" {
            TestObjectMatch "Physical Memory" 96 -WriteType "Yellow"
        }

        It "Manufacturer" {
            TestObjectMatch "Manufacturer" "My Custom PC"
        }

        It "Model" {
            TestObjectMatch "Model" "My HP ProLiant"
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

        It "UnifiedContent Auto Update" {
            SetActiveDisplayGrouping "Frequent Configuration Issues"
            TestObjectMatch "UnifiedContent Auto Cleanup Configured" $false -WriteType "Red"
        }

        It "Extended Protection" {
            SetActiveDisplayGrouping "Security Vulnerability"
            TestObjectMatch "Extended Protection Vulnerable" "True" -WriteType "Red"
            TestObjectMatch "Extended Protection Vulnerable Details" "Extended Protection isn't configured as expected" -WriteType "Red"
        }

        It "NIC Settings" {
            SetActiveDisplayGrouping "NIC Settings Per Active Adapter"
            TestObjectMatch "Sleepy NIC Disabled" "True"
        }

        It "HSTS Conflict on Default Web Site" {
            SetActiveDisplayGrouping "Exchange IIS Information"
            TestObjectMatch "hsts-Enabled-Default Web Site" $true -WriteType "Green"
            TestObjectMatch "hsts-max-age-Default Web Site" 300 -WriteType "Yellow"
            TestObjectMatch "hsts-conflict" $true -WriteType "Yellow"
            TestObjectMatch "hsts-MoreInfo" $true -WriteType "Yellow"
        }

        It "Dedicated Hybrid App Configured As Expected" {
            SetActiveDisplayGrouping "Hybrid Information"
            $dedicatedHybridApp = GetObject "AuthServer - 1"
            $dedicatedHybridApp.Id | Should -Match "^EvoSts - $Script:guidRegEx"
            $dedicatedHybridApp.Realm | Should -Match $Script:guidRegEx
            $dedicatedHybridApp.AppId | Should -Match $Script:guidRegEx
            $dedicatedHybridApp.DomainName | Should -Contain "contoso.mail.onmicrosoft.com"
        }
    }
}
