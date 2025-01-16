# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\Invoke-AnalyzerKnownBuildIssues.ps1
function Invoke-AnalyzerExchangeInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [int]$Order
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $keyExchangeInformation = Get-DisplayResultsGroupingKey -Name "Exchange Information"  -DisplayOrder $Order
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $hardwareInformation = $HealthServerObject.HardwareInformation
    $getWebServicesVirtualDirectory = $exchangeInformation.VirtualDirectories.GetWebServicesVirtualDirectory |
        Where-Object { $_.Name -eq "EWS (Default Web Site)" }
    $getWebServicesVirtualDirectoryBE = $exchangeInformation.VirtualDirectories.GetWebServicesVirtualDirectory |
        Where-Object { $_.Name -eq "EWS (Exchange Back End)" }

    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $keyExchangeInformation
    }

    $params = $baseParams + @{
        Name                  = "Name"
        Details               = $HealthServerObject.ServerName
        AddHtmlOverviewValues = $true
        HtmlName              = "Server Name"
    }
    Add-AnalyzedResultInformation @params

    $params = $baseParams + @{
        Name                  = "Generation Time"
        Details               = $HealthServerObject.GenerationTime
        AddHtmlOverviewValues = $true
    }
    Add-AnalyzedResultInformation @params

    $params = $baseParams + @{
        Name                  = "Version"
        Details               = $exchangeInformation.BuildInformation.VersionInformation.FriendlyName
        AddHtmlOverviewValues = $true
        HtmlName              = "Exchange Version"
    }
    Add-AnalyzedResultInformation @params

    $params = $baseParams + @{
        Name    = "Build Number"
        Details = $exchangeInformation.BuildInformation.ExchangeSetup.FileVersion
    }
    Add-AnalyzedResultInformation @params

    if ($null -ne $exchangeInformation.BuildInformation.ExchangeSetup.InstallTime) {
        $params = $baseParams + @{
            Name    = "Latest Install Time (SU/CU)"
            Details = $exchangeInformation.BuildInformation.ExchangeSetup.InstallTime
        }
        Add-AnalyzedResultInformation @params
    }

    if ($exchangeInformation.BuildInformation.VersionInformation.Supported -eq $false) {
        $daysOld = ($date - $exchangeInformation.BuildInformation.VersionInformation.ReleaseDate).Days

        $params = $baseParams + @{
            Name                   = "Error"
            Details                = "Out of date Cumulative Update. Please upgrade to one of the two most recently released Cumulative Updates. Currently running on a build that is $daysOld days old."
            DisplayWriteType       = "Red"
            DisplayCustomTabNumber = 2
            TestingName            = "Out of Date"
            DisplayTestingValue    = $true
            HtmlName               = "Out of date"
        }
        Add-AnalyzedResultInformation @params
    }

    $extendedSupportDate = $exchangeInformation.BuildInformation.VersionInformation.ExtendedSupportDate
    $exchangeFriendlyName = $exchangeInformation.BuildInformation.VersionInformation.FriendlyName
    if ($extendedSupportDate -le ([DateTime]::Now.AddYears(1))) {
        $displayWriteType = "Yellow"

        if ($extendedSupportDate -le ([DateTime]::Now.AddDays(178))) {
            $displayWriteType = "Red"
        }

        if (($exchangeFriendlyName -match '2010|2013|2016|2019')) {
            $displayValue = "$($exchangeInformation.BuildInformation.VersionInformation.ExtendedSupportDate.ToString("MMM dd, yyyy",
            [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US"))) - Please note the End Of Life date. Reference our blog for more information: https://aka.ms/HC-UpgradeToSE"
        } else {
            $displayValue = "Please note the End Of Life date and plan your migration accordingly."
        }

        if ($extendedSupportDate -le ([DateTime]::Now)) {
            $displayValue = "Error: Your Exchange server reached end of life on " +
            "$($exchangeInformation.BuildInformation.VersionInformation.ExtendedSupportDate.ToString("MMM dd, yyyy",
                [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US"))), and is no longer supported."
        }

        $params = $baseParams + @{
            Name                   = "End Of Life"
            Details                = $displayValue
            DisplayWriteType       = $displayWriteType
            DisplayCustomTabNumber = 2
            DisplayTestingValue    = $true
            AddHtmlDetailRow       = $false
        }
        Add-AnalyzedResultInformation @params
    }

    if ($null -ne $exchangeInformation.BuildInformation.LocalBuildNumber) {
        $local = $exchangeInformation.BuildInformation.LocalBuildNumber
        $remote = [system.version]$exchangeInformation.BuildInformation.ExchangeSetup.FileVersion

        if ($local -ne $remote) {
            $params = $baseParams + @{
                Name                   = "Warning"
                Details                = "Running commands from a different version box can cause issues. Local Tools Server Version: $local"
                DisplayWriteType       = "Yellow"
                DisplayCustomTabNumber = 2
                AddHtmlDetailRow       = $false
            }
            Add-AnalyzedResultInformation @params
        }
    }

    # If the ExSetup wasn't found, we need to report that.
    if ($exchangeInformation.BuildInformation.ExchangeSetup.FailedGetExSetup -eq $true) {
        $params = $baseParams + @{
            Name                   = "Warning"
            Details                = "Didn't detect ExSetup.exe on the server. This might mean that setup didn't complete correctly the last time it was run."
            DisplayCustomTabNumber = 2
            DisplayWriteType       = "Yellow"
        }
        Add-AnalyzedResultInformation @params
    }

    if ($null -ne $exchangeInformation.BuildInformation.KBsInstalledInfo.PackageName) {
        Add-AnalyzedResultInformation -Name "Exchange IU or Security Hotfix Detected" @baseParams
        $problemKbFound = $false
        $problemKbName = "KB5029388"

        foreach ($kbInfo in $exchangeInformation.BuildInformation.KBsInstalledInfo) {
            $kbName = $kbInfo.PackageName
            $params = $baseParams + @{
                Details                = "$kbName"
                DisplayCustomTabNumber = 2
                TestingName            = "Exchange IU"
            }
            Add-AnalyzedResultInformation @params

            if ($kbName.Contains($problemKbName)) {
                $problemKbFound = $true
            }
        }

        if ($problemKbFound) {
            Write-Verbose "Found problem $problemKbName"
            if ($null -ne $HealthServerObject.OSInformation.BuildInformation.OperatingSystem.OSLanguage) {
                [int]$OSLanguageID = [int]($HealthServerObject.OSInformation.BuildInformation.OperatingSystem.OSLanguage)
                # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
                $englishLanguageIDs = @(9, 1033, 2057, 3081, 4105, 5129, 6153, 7177, 8201, 10249, 11273)
                if ($englishLanguageIDs.Contains($OSLanguageID)) {
                    Write-Verbose "OS is english language. No action required"
                } else {
                    Write-Verbose "Non english language code: $OSLanguageID"
                    $params = $baseParams + @{
                        Details                = "Error: August 2023 SU 1 Problem Detected. More Information: https://aka.ms/HC-Aug23SUIssue"
                        DisplayWriteType       = "Red"
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params
                }
            } else {
                Write-Verbose "Language Code is null"
            }
        }
    }

    # Both must be true. We need to be out of extended support AND no longer consider the latest SU the latest SU for this version to be secure.
    if ($extendedSupportDate -le ([DateTime]::Now) -and
        $exchangeInformation.BuildInformation.VersionInformation.LatestSU -eq $false) {
        $params = $baseParams + @{
            Details                = "Error: Your Exchange server is out of support and no longer receives SUs." +
            "`n`t`tIt is now considered persistently vulnerable and it should be decommissioned ASAP."
            DisplayWriteType       = "Red"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    } elseif ($exchangeInformation.BuildInformation.VersionInformation.LatestSU -eq $false) {
        $params = $baseParams + @{
            Details                = "Not on the latest SU. More Information: https://aka.ms/HC-ExBuilds"
            DisplayWriteType       = "Yellow"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }

    $params = @{
        AnalyzeResults     = $AnalyzeResults
        DisplayGroupingKey = $keyExchangeInformation
        CurrentBuild       = $exchangeInformation.BuildInformation.ExchangeSetup.FileVersion
    }
    Invoke-AnalyzerKnownBuildIssues @params

    $params = $baseParams + @{
        Name                  = "Server Role"
        Details               = $exchangeInformation.BuildInformation.ServerRole
        AddHtmlOverviewValues = $true
    }
    Add-AnalyzedResultInformation @params

    $displayWriteType = "Grey"
    $details = $exchangeInformation.GetExchangeServer.Edition.ToString()

    if ($exchangeInformation.GetExchangeServer.IsExchangeTrialEdition) {
        $displayWriteType = "Yellow"
        $details = "Warning - $details"
    }

    $params = $baseParams + @{
        Name             = "Edition"
        Details          = $details
        DisplayWriteType = $displayWriteType
    }
    Add-AnalyzedResultInformation @params

    if ($exchangeInformation.GetExchangeServer.IsExchangeTrialEdition) {
        $displayWriteType = "Grey"
        $details = $exchangeInformation.GetExchangeServer.RemainingTrialPeriod.ToString()

        if ($exchangeInformation.GetExchangeServer.IsExpiredExchangeTrialEdition) {
            $displayWriteType = "Red"
            $details = "Error - $($exchangeInformation.GetExchangeServer.RemainingTrialPeriod)"
        } elseif ([TimeSpan]$exchangeInformation.GetExchangeServer.RemainingTrialPeriod.ToString() -lt [TimeSpan]"7.00:00:00") {
            $displayWriteType = "Yellow"
            $details = "Warning - $($exchangeInformation.GetExchangeServer.RemainingTrialPeriod)"
        }

        $params = $baseParams + @{
            Name                   = "Remaining Trial Period"
            Details                = $details
            DisplayWriteType       = $displayWriteType
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }

    if ($exchangeInformation.GetExchangeServer.IsMailboxServer -eq $true) {
        $dagName = [System.Convert]::ToString($exchangeInformation.GetMailboxServer.DatabaseAvailabilityGroup)
        if ([System.String]::IsNullOrWhiteSpace($dagName)) {
            $dagName = "Standalone Server"
        }
        $params = $baseParams + @{
            Name    = "DAG Name"
            Details = $dagName
        }
        Add-AnalyzedResultInformation @params
    }

    $params = $baseParams + @{
        Name    = "AD Site"
        Details = ([System.Convert]::ToString(($exchangeInformation.GetExchangeServer.Site)).Split("/")[-1])
    }
    Add-AnalyzedResultInformation @params

    if ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false) {

        Write-Verbose "Working on MRS Proxy Settings"
        $mrsProxyDetails = $getWebServicesVirtualDirectory.MRSProxyEnabled
        if ($getWebServicesVirtualDirectory.MRSProxyEnabled) {
            $mrsProxyDetails = "$mrsProxyDetails`n`r`t`tKeep MRS Proxy disabled if you do not plan to move mailboxes cross-forest or remote"
            $mrsProxyWriteType = "Yellow"
        } else {
            $mrsProxyWriteType = "Grey"
        }

        $params = $baseParams + @{
            Name             = "MRS Proxy Enabled"
            Details          = $mrsProxyDetails
            DisplayWriteType = $mrsProxyWriteType
        }
        Add-AnalyzedResultInformation @params
    }

    if ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false) {
        Write-Verbose "Determining Server Group Membership"

        $params = $baseParams + @{
            Name             = "Exchange Server Membership"
            Details          = "Passed"
            DisplayWriteType = "Grey"
        }

        if ($null -ne $exchangeInformation.ComputerMembership -and
            $null -ne $HealthServerObject.OrganizationInformation.WellKnownSecurityGroups) {
            $localGroupList = $HealthServerObject.OrganizationInformation.WellKnownSecurityGroups |
                Where-Object { $_.WellKnownName -eq "Exchange Trusted Subsystem" }
            # By Default, I also have Managed Availability Servers and Exchange Install Domain Servers.
            # But not sure what issue they would cause if we don't have the server as a member, leaving out for now
            $adGroupList = $HealthServerObject.OrganizationInformation.WellKnownSecurityGroups |
                Where-Object { $_.WellKnownName -in @("Exchange Trusted Subsystem", "Exchange Servers") }
            $displayMissingGroups = New-Object System.Collections.Generic.List[string]

            if ($null -ne $exchangeInformation.ComputerMembership.LocalGroupMember) {
                foreach ($localGroup in $localGroupList) {
                    if (($null -eq ($exchangeInformation.ComputerMembership.LocalGroupMember.SID | Where-Object { $_.ToString() -eq $localGroup.SID } ))) {
                        $displayMissingGroups.Add("$($localGroup.WellKnownName) - Local System Membership")
                    }
                }
            } else {
                $displayMissingGroups.Add("Unable to determine Local System Membership as the results were blank.")
            }

            if ($exchangeInformation.ComputerMembership.ADGroupMembership -eq "NoAdModule") {
                $displayMissingGroups.Add("Missing Active Directory Module. Run 'Install-WindowsFeature RSat-AD-PowerShell'")
            } elseif ($null -ne $exchangeInformation.ComputerMembership.ADGroupMembership -and
                $exchangeInformation.ComputerMembership.ADGroupMembership.Count -gt 0) {
                foreach ($adGroup in $adGroupList) {
                    if (($null -eq ($exchangeInformation.ComputerMembership.ADGroupMembership.SID | Where-Object { $_.ToString() -eq $adGroup.SID }))) {
                        $displayMissingGroups.Add("$($adGroup.WellKnownName) - AD Group Membership")
                    }
                }
            } else {
                $displayMissingGroups.Add("Unable to determine AD Group Membership as the results were blank.")
            }

            if ($displayMissingGroups.Count -ge 1) {
                $params.DisplayWriteType = "Red"
                $params.Details = "Failed"
                Add-AnalyzedResultInformation @params

                foreach ($group in $displayMissingGroups) {
                    $params = $baseParams + @{
                        Details                = $group
                        TestingName            = $group
                        DisplayWriteType       = "Red"
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params
                }

                $params = $baseParams + @{
                    Details                = "More Information: https://aka.ms/HC-ServerMembership"
                    DisplayWriteType       = "Yellow"
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            } else {
                Add-AnalyzedResultInformation @params
            }
        } else {
            $params.DisplayWriteType = "Yellow"
            $params.Details = "Unknown - Wasn't able to get the Computer Membership information"
            Add-AnalyzedResultInformation @params
        }
    }

    if ($exchangeInformation.BuildInformation.MajorVersion -eq "Exchange2013" -and
        $exchangeInformation.GetExchangeServer.IsClientAccessServer -eq $true) {

        if ($null -ne $exchangeInformation.ApplicationPools -and
            $exchangeInformation.ApplicationPools.Count -gt 0) {
            $mapiFEAppPool = $exchangeInformation.ApplicationPools["MSExchangeMapiFrontEndAppPool"]
            [bool]$enabled = $mapiFEAppPool.GCServerEnabled
            [bool]$unknown = $mapiFEAppPool.GCUnknown
            $warning = [string]::Empty
            $displayWriteType = "Green"
            $displayValue = "Server"

            if ($hardwareInformation.TotalMemory -ge 21474836480 -and
                $enabled -eq $false) {
                $displayWriteType = "Red"
                $displayValue = "Workstation --- Error"
                $warning = "To Fix this issue go into the file MSExchangeMapiFrontEndAppPool_CLRConfig.config in the Exchange Bin directory and change the GCServer to true and recycle the MAPI Front End App Pool"
            } elseif ($unknown) {
                $displayValue = "Unknown --- Warning"
                $displayWriteType = "Yellow"
            } elseif (!($enabled)) {
                $displayWriteType = "Yellow"
                $displayValue = "Workstation --- Warning"
                $warning = "You could be seeing some GC issues within the Mapi Front End App Pool. However, you don't have enough memory installed on the system to recommend switching the GC mode by default without consulting a support professional."
            }

            $params = $baseParams + @{
                Name                   = "MAPI Front End App Pool GC Mode"
                Details                = $displayValue
                DisplayCustomTabNumber = 2
                DisplayWriteType       = $displayWriteType
            }
            Add-AnalyzedResultInformation @params
        } else {
            $warning = "Unable to determine MAPI Front End App Pool GC Mode status. This may be a temporary issue. You should try to re-run the script"
        }

        if ($warning -ne [string]::Empty) {
            $params = $baseParams + @{
                Details                = $warning
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
                AddHtmlDetailRow       = $false
            }
            Add-AnalyzedResultInformation @params
        }
    }

    $internetProxy = $exchangeInformation.GetExchangeServer.InternetWebProxy

    $params = $baseParams + @{
        Name    = "Internet Web Proxy"
        Details = $internetProxy
    }

    if ([string]::IsNullOrEmpty($internetProxy)) {
        $params.Details = "Not Set"
    } elseif ($internetProxy.Scheme -ne "http") {
        <#
        We use the WebProxy class WebProxy(Uri, Boolean, String[]) constructor when running Set-ExchangeServer -InternetWebProxy,
        which throws an UriFormatException if the URI provided cannot be parsed.
        This is the case if it doesn't follow the scheme as per RFC 2396 (https://datatracker.ietf.org/doc/html/rfc2396#section-3.1).
        However, we sometimes see cases where customers have set an invalid proxy url that cannot be used by Exchange Server
        (e.g., https://proxy.contoso.local, ftp://proxy.contoso.local or even proxy.contoso.local).
        #>
        $params.Details = "$internetProxy is invalid as it must start with http://"
        $params.Add("DisplayWriteType", "Red")
    }
    Add-AnalyzedResultInformation @params

    if (-not ([string]::IsNullOrWhiteSpace($getWebServicesVirtualDirectory.InternalNLBBypassUrl))) {
        $params = $baseParams + @{
            Name             = "EWS Internal Bypass URL Set"
            Details          = "$($getWebServicesVirtualDirectory.InternalNLBBypassUrl) - Can cause issues after KB 5001779" +
            "`r`n`t`tThe Web Services Virtual Directory has a value set for InternalNLBBypassUrl which can cause problems with Exchange." +
            "`r`n`t`tSet the InternalNLBBypassUrl to NULL to correct this."
            DisplayWriteType = "Red"
        }
        Add-AnalyzedResultInformation @params
    }

    if ($null -ne $getWebServicesVirtualDirectoryBE -and
        $null -ne $getWebServicesVirtualDirectoryBE.InternalNLBBypassUrl) {
        Write-Verbose "Checking EWS Internal NLB Bypass URL for the BE"
        $expectedValue = "https://$($exchangeInformation.GetExchangeServer.Fqdn.ToString()):444/ews/exchange.asmx"

        if ($getWebServicesVirtualDirectoryBE.InternalNLBBypassUrl.ToString() -ne $expectedValue) {
            $params = $baseParams + @{
                Name             = "EWS Internal Bypass URL Incorrectly Set on BE"
                Details          = "Error: '$expectedValue' is the expected value for this." +
                "`r`n`t`tAnything other than the expected value, will result in connectivity issues."
                DisplayWriteType = "Red"
            }

            Add-AnalyzedResultInformation @params
        }
    }

    Write-Verbose "Working on results from Test-ServiceHealth"
    $servicesNotRunning = $exchangeInformation.ExchangeServicesNotRunning

    if ($null -ne $servicesNotRunning -and
        $servicesNotRunning.Count -gt 0 ) {
        Add-AnalyzedResultInformation -Name "Services Not Running" @baseParams

        foreach ($stoppedService in $servicesNotRunning) {
            $params = $baseParams + @{
                Details                = $stoppedService
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
            }
            Add-AnalyzedResultInformation @params
        }
    }

    Write-Verbose "Working on Exchange Dependent Services"
    if ($null -ne $exchangeInformation.DependentServices) {

        if ($exchangeInformation.DependentServices.Critical.Count -gt 0) {
            Write-Verbose "Critical Services found to be not running."
            Add-AnalyzedResultInformation -Name "Critical Services Not Running" @baseParams

            foreach ($service in $exchangeInformation.DependentServices.Critical) {
                $params = $baseParams + @{
                    Details                = "$($service.Name) - Status: $($service.Status) - StartType: $($service.StartType)"
                    DisplayCustomTabNumber = 2
                    DisplayWriteType       = "Red"
                    TestingName            = "Critical $($service.Name)"
                }
                Add-AnalyzedResultInformation @params
            }
        }
        if ($exchangeInformation.DependentServices.Common.Count -gt 0) {
            Write-Verbose "Common Services found to be not running."
            Add-AnalyzedResultInformation -Name "Common Services Not Running" @baseParams

            foreach ($service in $exchangeInformation.DependentServices.Common) {
                $params = $baseParams + @{
                    Details                = "$($service.Name) - Status: $($service.Status) - StartType: $($service.StartType)"
                    DisplayCustomTabNumber = 2
                    DisplayWriteType       = "Yellow"
                    TestingName            = "Common $($service.Name)"
                }
                Add-AnalyzedResultInformation @params
            }
        }

        if ($exchangeInformation.DependentServices.Misconfigured.Count -gt 0) {
            Write-Verbose "Misconfigured Services found."
            Add-AnalyzedResultInformation -Name "Misconfigured Services" @baseParams

            foreach ($service in $exchangeInformation.DependentServices.Misconfigured) {
                $params = $baseParams + @{
                    Details                = "$($service.Name) - Status: $($service.Status) - StartType: $($service.StartType) - CorrectStartType: $($service.CorrectStartType)"
                    DisplayCustomTabNumber = 2
                    DisplayWriteType       = "Yellow"
                }
                Add-AnalyzedResultInformation @params
            }
        }

        if ($exchangeInformation.DependentServices.Critical.Count -gt 0 -or
            $exchangeInformation.DependentServices.Common.Count -gt 0 -or
            $exchangeInformation.DependentServices.Misconfigured.Count -gt 0) {
            $params = $baseParams + @{
                Details                = "To determine the display name of the service that is not properly configured or running, run 'Get-Service <Name>' to get more information."
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
            }
            Add-AnalyzedResultInformation @params
        }
    }

    if ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false -and
        $null -ne $exchangeInformation.ExtendedProtectionConfig) {
        $params = $baseParams + @{
            Name    = "Extended Protection Enabled (Any VDir)"
            Details = $exchangeInformation.ExtendedProtectionConfig.ExtendedProtectionConfigured
        }
        Add-AnalyzedResultInformation @params

        # If any directory has a higher than expected configuration, we need to throw a warning
        # This will be detected by SupportedExtendedProtection being set to false, as we are set higher than expected/recommended value you will likely run into issues of some kind
        # Skip over Default Web Site/Powershell if RequireSsl is not set.
        $notSupportedExtendedProtectionDirectories = $exchangeInformation.ExtendedProtectionConfig.ExtendedProtectionConfiguration |
            Where-Object { ($_.SupportedExtendedProtection -eq $false -and
                    $_.VirtualDirectoryName -ne "Default Web Site/Powershell") -or
                ($_.SupportedExtendedProtection -eq $false -and
                $_.VirtualDirectoryName -eq "Default Web Site/Powershell" -and
                $_.Configuration.SslSettings.RequireSsl -eq $true)
            }

        if ($null -ne $notSupportedExtendedProtectionDirectories) {
            foreach ($entry in $notSupportedExtendedProtectionDirectories) {
                $expectedValue = if ($entry.MitigationSupported -and $entry.MitigationEnabled) { "None" } else { $entry.ExpectedExtendedConfiguration }
                $params = $baseParams + @{
                    Details                = "$($entry.VirtualDirectoryName) - Current Value: '$($entry.ExtendedProtection)'   Expected Value: '$expectedValue'"
                    DisplayWriteType       = "Yellow"
                    DisplayCustomTabNumber = 2
                    TestingName            = "EP - $($entry.VirtualDirectoryName)"
                    DisplayTestingValue    = ($entry.ExtendedProtection)
                }
                Add-AnalyzedResultInformation @params
            }

            $params = $baseParams + @{
                Details          = "`r`n`t`tThe current Extended Protection settings may cause issues with some clients types on $(if(@($notSupportedExtendedProtectionDirectories).Count -eq 1) { "this protocol."} else { "these protocols."})" +
                "`r`n`t`tIt is recommended to set the EP setting to the recommended value if you are having issues with that protocol." +
                "`r`n`t`tMore Information: https://aka.ms/ExchangeEPDoc"
                DisplayWriteType = "Yellow"
            }
            Add-AnalyzedResultInformation @params
        } else {
            Write-Verbose "All virtual directories are supported for the Extended Protection value."
        }
    }

    if ($null -ne $exchangeInformation.SettingOverrides) {

        $overridesDetected = $null -ne $exchangeInformation.SettingOverrides.SettingOverrides
        $params = $baseParams + @{
            Name    = "Setting Overrides Detected"
            Details = $overridesDetected
        }
        Add-AnalyzedResultInformation @params

        if ($overridesDetected) {
            $params = $baseParams + @{
                OutColumns = ([PSCustomObject]@{
                        DisplayObject = $exchangeInformation.SettingOverrides.SimpleSettingOverrides
                        IndentSpaces  = 12
                    })
                HtmlName   = "Setting Overrides"
            }
            Add-AnalyzedResultInformation @params
        }
    }

    $monitoringOverrides = New-Object System.Collections.Generic.List[object]
    foreach ($monitoringOverride in $HealthServerObject.OrganizationInformation.GetGlobalMonitoringOverride.SimpleView) {
        $monitoringOverrides.Add($monitoringOverride)
    }
    foreach ($monitoringOverride in $exchangeInformation.GetServerMonitoringOverride.SimpleView) {
        $monitoringOverrides.Add($monitoringOverride)
    }

    $monitoringOverridesDetected = $monitoringOverrides.Count -gt 0
    $params = $baseParams + @{
        Name    = "Monitoring Overrides Detected"
        Details = $monitoringOverridesDetected
    }

    Add-AnalyzedResultInformation @params

    if ($monitoringOverridesDetected) {
        $params = $baseParams + @{
            OutColumns = ([PSCustomObject]@{
                    DisplayObject = $monitoringOverrides
                    IndentSpaces  = 12
                })
            HtmlName   = "Monitoring Overrides"
        }
        Add-AnalyzedResultInformation @params
    }

    if ($null -ne $exchangeInformation.EdgeTransportResourceThrottling) {
        try {
            # SystemMemory does not block mail flow.
            $resourceThrottling = ([xml]$exchangeInformation.EdgeTransportResourceThrottling).Diagnostics.Components.ResourceThrottling.ResourceTracker.ResourceMeter |
                Where-Object { $_.Resource -ne "SystemMemory" -and $_.CurrentResourceUse -ne "Low" }
        } catch {
            Invoke-CatchActions
        }

        if ($null -ne $resourceThrottling) {
            $resourceThrottlingList = @($resourceThrottling.Resource |
                    ForEach-Object {
                        $index = $_.IndexOf("[")
                        if ($index -eq -1) {
                            $_
                        } else {
                            $_.Substring(0, $index)
                        }
                    })
            $params = $baseParams + @{
                Name             = "Transport Back Pressure"
                Details          = "--ERROR-- The following resources are causing back pressure: $([string]::Join(", ", $resourceThrottlingList))"
                DisplayWriteType = "Red"
            }
            Add-AnalyzedResultInformation @params
        }
    }

    Write-Verbose "Working on Exchange Server Maintenance"
    $serverMaintenance = $exchangeInformation.ServerMaintenance
    $getMailboxServer = $exchangeInformation.GetMailboxServer

    if (($serverMaintenance.InactiveComponents).Count -eq 0 -and
        ($null -eq $serverMaintenance.GetClusterNode -or
        $serverMaintenance.GetClusterNode.State -eq "Up") -and
        ($null -eq $getMailboxServer -or
            ($getMailboxServer.DatabaseCopyActivationDisabledAndMoveNow -eq $false -and
        $getMailboxServer.DatabaseCopyAutoActivationPolicy.ToString() -eq "Unrestricted"))) {
        $params = $baseParams + @{
            Name             = "Exchange Server Maintenance"
            Details          = "Server is not in Maintenance Mode"
            DisplayWriteType = "Green"
        }
        Add-AnalyzedResultInformation @params
    } else {
        Add-AnalyzedResultInformation -Details "Exchange Server Maintenance" @baseParams

        if (($serverMaintenance.InactiveComponents).Count -ne 0) {
            foreach ($inactiveComponent in $serverMaintenance.InactiveComponents) {
                $params = $baseParams + @{
                    Name                   = "Component"
                    Details                = $inactiveComponent
                    DisplayCustomTabNumber = 2
                    DisplayWriteType       = "Red"
                }
                Add-AnalyzedResultInformation @params
            }

            $params = $baseParams + @{
                Details                = "For more information: https://aka.ms/HC-ServerComponentState"
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
            }
            Add-AnalyzedResultInformation @params
        }

        if ($getMailboxServer.DatabaseCopyActivationDisabledAndMoveNow -or
            $getMailboxServer.DatabaseCopyAutoActivationPolicy -eq "Blocked") {
            $displayValue = "`r`n`t`tDatabaseCopyActivationDisabledAndMoveNow: $($getMailboxServer.DatabaseCopyActivationDisabledAndMoveNow) --- should be 'false'"
            $displayValue += "`r`n`t`tDatabaseCopyAutoActivationPolicy: $($getMailboxServer.DatabaseCopyAutoActivationPolicy) --- should be 'unrestricted'"

            $params = $baseParams + @{
                Name                   = "Database Copy Maintenance"
                Details                = $displayValue
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Red"
            }
            Add-AnalyzedResultInformation @params
        }

        if ($null -ne $serverMaintenance.GetClusterNode -and
            $serverMaintenance.GetClusterNode.State -ne "Up") {
            $params = $baseParams + @{
                Name                   = "Cluster Node"
                Details                = "'$($serverMaintenance.GetClusterNode.State)' --- should be 'Up'"
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Red"
            }
            Add-AnalyzedResultInformation @params
        }
    }
}
