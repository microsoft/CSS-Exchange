# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
Function Invoke-AnalyzerEngine {
    param(
        [HealthChecker.HealthCheckerExchangeServer]$HealthServerObject
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $analyzedResults = New-Object HealthChecker.AnalyzedInformation
    $analyzedResults.HealthCheckerExchangeServer = $HealthServerObject

    #Display Grouping Keys
    $order = 0
    $keyBeginningInfo = Get-DisplayResultsGroupingKey -Name "BeginningInfo" -DisplayGroupName $false -DisplayOrder ($order++) -DefaultTabNumber 0
    $keyExchangeInformation = Get-DisplayResultsGroupingKey -Name "Exchange Information"  -DisplayOrder ($order++)
    $keyHybridInformation = Get-DisplayResultsGroupingKey -Name "Hybrid Information" -DisplayOrder ($order++)
    $keyOSInformation = Get-DisplayResultsGroupingKey -Name "Operating System Information" -DisplayOrder ($order++)
    $keyHardwareInformation = Get-DisplayResultsGroupingKey -Name "Processor/Hardware Information" -DisplayOrder ($order++)
    $keyNICSettings = Get-DisplayResultsGroupingKey -Name "NIC Settings Per Active Adapter" -DisplayOrder ($order++) -DefaultTabNumber 2
    $keyFrequentConfigIssues = Get-DisplayResultsGroupingKey -Name "Frequent Configuration Issues" -DisplayOrder ($order++)
    $keySecuritySettings = Get-DisplayResultsGroupingKey -Name "Security Settings" -DisplayOrder ($order++)
    $keyWebApps = Get-DisplayResultsGroupingKey -Name "Exchange Web App Pools" -DisplayOrder ($order++)

    #Set short cut variables
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $osInformation = $HealthServerObject.OSInformation
    $hardwareInformation = $HealthServerObject.HardwareInformation

    if (!$Script:DisplayedScriptVersionAlready) {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Exchange Health Checker Version" -Details $BuildVersion `
            -DisplayGroupingKey $keyBeginningInfo `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    if ($HealthServerObject.HardwareInformation.ServerType -eq [HealthChecker.ServerType]::VMWare -or
        $HealthServerObject.HardwareInformation.ServerType -eq [HealthChecker.ServerType]::HyperV) {
        $analyzedResults = Add-AnalyzedResultInformation -Details $VirtualizationWarning -DisplayWriteType "Yellow" `
            -DisplayGroupingKey $keyBeginningInfo `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    #########################
    # Exchange Information
    #########################
    Write-Verbose "Working on Exchange Information"

    $analyzedResults = Add-AnalyzedResultInformation -Name "Name" -Details ($HealthServerObject.ServerName) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true `
        -HtmlName "Server Name" `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Generation Time" -Details $HealthServerObject.GenerationTime `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Version" -Details ($exchangeInformation.BuildInformation.FriendlyName) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true `
        -HtmlName "Exchange Version" `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Build Number" -Details ($exchangeInformation.BuildInformation.BuildNumber) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AnalyzedInformation $analyzedResults

    if ($exchangeInformation.BuildInformation.SupportedBuild -eq $false) {
        $daysOld = ($date - ([System.Convert]::ToDateTime([DateTime]$exchangeInformation.BuildInformation.ReleaseDate, [System.Globalization.DateTimeFormatInfo]::InvariantInfo))).Days

        $analyzedResults = Add-AnalyzedResultInformation -Name "Error" -Details ("Out of date Cumulative Update. Please upgrade to one of the two most recently released Cumulative Updates. Currently running on a build that is {0} days old." -f $daysOld) `
            -DisplayGroupingKey $keyExchangeInformation `
            -DisplayWriteType "Red" `
            -DisplayCustomTabNumber 2 `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    if (-not ([string]::IsNullOrEmpty($exchangeInformation.BuildInformation.LocalBuildNumber))) {
        $local = $exchangeInformation.BuildInformation.LocalBuildNumber
        $remote = $exchangeInformation.BuildInformation.BuildNumber

        if ($local.Substring(0, $local.LastIndexOf(".")) -ne $remote.Substring(0, $remote.LastIndexOf("."))) {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Warning" -Details ("Running commands from a different version box can cause issues. Local Tools Server Version: {0}" -f $local) `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayWriteType "Yellow" `
                -DisplayCustomTabNumber 2 `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
    }

    if ($null -ne $exchangeInformation.BuildInformation.KBsInstalled) {
        $analyzedResults = Add-AnalyzedResultInformation -Details ("Exchange IU or Security Hotfix Detected.") `
            -DisplayGroupingKey $keyExchangeInformation `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults

        foreach ($kb in $exchangeInformation.BuildInformation.KBsInstalled) {
            $analyzedResults = Add-AnalyzedResultInformation -Details $kb `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Server Role" -Details ($exchangeInformation.BuildInformation.ServerRole) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true `
        -AnalyzedInformation $analyzedResults

    if ($exchangeInformation.BuildInformation.ServerRole -le [HealthChecker.ExchangeServerRole]::Mailbox) {
        $dagName = [System.Convert]::ToString($exchangeInformation.GetMailboxServer.DatabaseAvailabilityGroup)
        if ([System.String]::IsNullOrWhiteSpace($dagName)) {
            $dagName = "Standalone Server"
        }
        $analyzedResults = Add-AnalyzedResultInformation -Name "DAG Name" -Details $dagName `
            -DisplayGroupingKey $keyExchangeInformation `
            -AnalyzedInformation $analyzedResults
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "AD Site" -Details ([System.Convert]::ToString(($exchangeInformation.GetExchangeServer.Site)).Split("/")[-1]) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "MAPI/HTTP Enabled" -Details ($exchangeInformation.MapiHttpEnabled) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AnalyzedInformation $analyzedResults

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013 -and
        $exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge -and
        $exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Mailbox) {

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

            $analyzedResults = Add-AnalyzedResultInformation -Name "MAPI Front End App Pool GC Mode" -Details $displayValue `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType $displayWriteType `
                -AnalyzedInformation $analyzedResults
        } else {
            $warning = "Unable to determine MAPI Front End App Pool GC Mode status. This may be a temporary issue. You should try to re-run the script"
        }

        if ($warning -ne [string]::Empty) {
            $analyzedResults = Add-AnalyzedResultInformation -Details $warning `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
    }

    if (-not ([string]::IsNullOrWhiteSpace($exchangeInformation.GetWebServicesVirtualDirectory.InternalNLBBypassUrl))) {
        $analyzedResults = Add-AnalyzedResultInformation -Name "EWS Internal Bypass URL Set" -Details ("$($exchangeInformation.GetWebServicesVirtualDirectory.InternalNLBBypassUrl) - Can cause issues after KB 5001779") `
            -DisplayGroupingKey $keyExchangeInformation `
            -DisplayWriteType "Red" `
            -AnalyzedInformation $analyzedResults
    }

    #########################
    # Hybrid Information
    #########################
    Write-Verbose "Working on Hybrid Configuration Information"
    if ($exchangeInformation.BuildInformation.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2013 -and
        $null -ne $exchangeInformation.GetHybridConfiguration) {

        $analyzedResults = Add-AnalyzedResultInformation -Name "Organization Hybrid enabled" -Details "True" `
            -DisplayGroupingKey $keyHybridInformation `
            -AnalyzedInformation $analyzedResults

        if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.OnPremisesSmartHost))) {
            $onPremSmartHostDomain = ($exchangeInformation.GetHybridConfiguration.OnPremisesSmartHost).ToString()
            $onPremSmartHostWriteType = "Grey"
        } else {
            $onPremSmartHostDomain = "No on-premises smart host domain configured for hybrid use"
            $onPremSmartHostWriteType = "Yellow"
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "On-Premises Smart Host Domain" -Details $onPremSmartHostDomain `
            -DisplayGroupingKey $keyHybridInformation `
            -DisplayWriteType $onPremSmartHostWriteType `
            -AnalyzedInformation $analyzedResults

        if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.Domains))) {
            $domainsConfiguredForHybrid = $exchangeInformation.GetHybridConfiguration.Domains
            $domainsConfiguredForHybridWriteType = "Grey"
        } else {
            $domainsConfiguredForHybridWriteType = "Yellow"
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "Domain(s) configured for Hybrid use" `
            -DisplayGroupingKey $keyHybridInformation `
            -DisplayWriteType $domainsConfiguredForHybridWriteType `
            -AnalyzedInformation $analyzedResults

        if ($domainsConfiguredForHybrid.Count -ge 1) {
            foreach ($domain in $domainsConfiguredForHybrid) {
                $analyzedResults = Add-AnalyzedResultInformation -Details $domain `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayWriteType $domainsConfiguredForHybridWriteType `
                    -DisplayCustomTabNumber 2 `
                    -AnalyzedInformation $analyzedResults
            }
        } else {
            $analyzedResults = Add-AnalyzedResultInformation -Details "No domain configured for Hybrid use" `
                -DisplayGroupingKey $keyHybridInformation `
                -DisplayWriteType $domainsConfiguredForHybridWriteType `
                -DisplayCustomTabNumber 2 `
                -AnalyzedInformation $analyzedResults
        }

        if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.EdgeTransportServers))) {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Edge Transport Server(s)" `
                -DisplayGroupingKey $keyHybridInformation `
                -AnalyzedInformation $analyzedResults

            foreach ($edgeServer in $exchangeInformation.GetHybridConfiguration.EdgeTransportServers) {
                $analyzedResults = Add-AnalyzedResultInformation -Details $edgeServer `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayCustomTabNumber 2  `
                    -AnalyzedInformation $analyzedResults
            }

            if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.ReceivingTransportServers)) -or
                (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.SendingTransportServers)))) {
                $analyzedResults = Add-AnalyzedResultInformation -Details "When configuring the EdgeTransportServers parameter, you must configure the ReceivingTransportServers and SendingTransportServers parameter values to null" `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayWriteType "Yellow" `
                    -DisplayCustomTabNumber 2 `
                    -AnalyzedInformation $analyzedResults
            }
        } else {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Receiving Transport Server(s)" `
                -DisplayGroupingKey $keyHybridInformation `
                -AnalyzedInformation $analyzedResults

            if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.ReceivingTransportServers))) {
                foreach ($receivingTransportSrv in $exchangeInformation.GetHybridConfiguration.ReceivingTransportServers) {
                    $analyzedResults = Add-AnalyzedResultInformation -Details $receivingTransportSrv `
                        -DisplayGroupingKey $keyHybridInformation `
                        -DisplayCustomTabNumber 2 `
                        -AnalyzedInformation $analyzedResults
                }
            } else {
                $analyzedResults = Add-AnalyzedResultInformation -Details "No Receiving Transport Server configured for Hybrid use" `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayCustomTabNumber 2 `
                    -DisplayWriteType "Yellow" `
                    -AnalyzedInformation $analyzedResults
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "Sending Transport Server(s)" `
                -DisplayGroupingKey $keyHybridInformation `
                -AnalyzedInformation $analyzedResults

            if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.SendingTransportServers))) {
                foreach ($sendingTransportSrv in $exchangeInformation.GetHybridConfiguration.SendingTransportServers) {
                    $analyzedResults = Add-AnalyzedResultInformation -Details $sendingTransportSrv `
                        -DisplayGroupingKey $keyHybridInformation `
                        -DisplayCustomTabNumber 2 `
                        -AnalyzedInformation $analyzedResults
                }
            } else {
                $analyzedResults = Add-AnalyzedResultInformation -Details "No Sending Transport Server configured for Hybrid use" `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayCustomTabNumber 2 `
                    -DisplayWriteType "Yellow" `
                    -AnalyzedInformation $analyzedResults
            }
        }

        if ($exchangeInformation.GetHybridConfiguration.ServiceInstance -eq 1) {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Service Instance" -Details "Office 365 operated by 21Vianet" `
                -DisplayGroupingKey $keyHybridInformation `
                -AnalyzedInformation $analyzedResults
        } elseif ($exchangeInformation.GetHybridConfiguration.ServiceInstance -ne 0) {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Service Instance" -Details ($exchangeInformation.GetHybridConfiguration.ServiceInstance) `
                -DisplayGroupingKey $keyHybridInformation `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults

            $analyzedResults = Add-AnalyzedResultInformation -Details "You are using an invalid value. Please set this value to 0 (null) or re-run HCW" `
                -DisplayGroupingKey $keyHybridInformation `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        }

        if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.TlsCertificateName))) {
            $analyzedResults = Add-AnalyzedResultInformation -Name "TLS Certificate Name" -Details ($exchangeInformation.GetHybridConfiguration.TlsCertificateName).ToString() `
                -DisplayGroupingKey $keyHybridInformation `
                -AnalyzedInformation $analyzedResults
        } else {
            $analyzedResults = Add-AnalyzedResultInformation -Name "TLS Certificate Name" -Details "No valid certificate found" `
                -DisplayGroupingKey $keyHybridInformation `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "Feature(s) enabled for Hybrid use" `
            -DisplayGroupingKey $keyHybridInformation `
            -AnalyzedInformation $analyzedResults

        if (-not([System.String]::IsNullOrEmpty($exchangeInformation.GetHybridConfiguration.Features))) {
            foreach ($feature in $exchangeInformation.GetHybridConfiguration.Features) {
                $analyzedResults = Add-AnalyzedResultInformation -Details $feature `
                    -DisplayGroupingKey $keyHybridInformation `
                    -DisplayCustomTabNumber 2  `
                    -AnalyzedInformation $analyzedResults
            }
        } else {
            $analyzedResults = Add-AnalyzedResultInformation -Details "No feature(s) enabled for Hybrid use" `
                -DisplayGroupingKey $keyHybridInformation `
                -DisplayCustomTabNumber 2  `
                -AnalyzedInformation $analyzedResults
        }
    }

    ##############################
    # Exchange Test Services
    ##############################
    Write-Verbose "Working on results from Test-ServiceHealth"
    $servicesNotRunning = $exchangeInformation.ExchangeServicesNotRunning
    if ($null -ne $servicesNotRunning) {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Services Not Running" `
            -DisplayGroupingKey $keyExchangeInformation `
            -AnalyzedInformation $analyzedResults

        foreach ($stoppedService in $servicesNotRunning) {
            $analyzedResults = Add-AnalyzedResultInformation -Details $stoppedService `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2  `
                -DisplayWriteType "Yellow" `
                -AnalyzedInformation $analyzedResults
        }
    }

    ##############################
    # Exchange Server Maintenance
    ##############################
    Write-Verbose "Working on Exchange Server Maintenance"
    $serverMaintenance = $exchangeInformation.ServerMaintenance

    if (($serverMaintenance.InactiveComponents).Count -eq 0 -and
        ($null -eq $serverMaintenance.GetClusterNode -or
        $serverMaintenance.GetClusterNode.State -eq "Up") -and
        ($null -eq $serverMaintenance.GetMailboxServer -or
            ($serverMaintenance.GetMailboxServer.DatabaseCopyActivationDisabledAndMoveNow -eq $false -and
        $serverMaintenance.GetMailboxServer.DatabaseCopyAutoActivationPolicy -eq "Unrestricted"))) {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Exchange Server Maintenance" -Details "Server is not in Maintenance Mode" `
            -DisplayGroupingKey $keyExchangeInformation `
            -DisplayWriteType "Green" `
            -AnalyzedInformation $analyzedResults
    } else {
        $analyzedResults = Add-AnalyzedResultInformation -Details "Exchange Server Maintenance" `
            -DisplayGroupingKey $keyExchangeInformation `
            -AnalyzedInformation $analyzedResults

        if (($serverMaintenance.InactiveComponents).Count -ne 0) {
            foreach ($inactiveComponent in $serverMaintenance.InactiveComponents) {
                $analyzedResults = Add-AnalyzedResultInformation -Name "Component" -Details $inactiveComponent `
                    -DisplayGroupingKey $keyExchangeInformation `
                    -DisplayCustomTabNumber 2  `
                    -DisplayWriteType "Red" `
                    -AnalyzedInformation $analyzedResults
            }

            $analyzedResults = Add-AnalyzedResultInformation -Details "For more information: https://aka.ms/HC-ServerComponentState" `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AnalyzedInformation $analyzedResults
        }

        if ($serverMaintenance.GetMailboxServer.DatabaseCopyActivationDisabledAndMoveNow -or
            $serverMaintenance.GetMailboxServer.DatabaseCopyAutoActivationPolicy -eq "Blocked") {
            $displayValue = "`r`n`t`tDatabaseCopyActivationDisabledAndMoveNow: {0} --- should be 'false'`r`n`t`tDatabaseCopyAutoActivationPolicy: {1} --- should be 'unrestricted'" -f `
                $serverMaintenance.GetMailboxServer.DatabaseCopyActivationDisabledAndMoveNow,
            $serverMaintenance.GetMailboxServer.DatabaseCopyAutoActivationPolicy

            $analyzedResults = Add-AnalyzedResultInformation -Name "Database Copy Maintenance" -Details $displayValue `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        }

        if ($null -ne $serverMaintenance.GetClusterNode -and
            $serverMaintenance.GetClusterNode.State -ne "Up") {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Cluster Node" -Details ("'{0}' --- should be 'Up'" -f $serverMaintenance.GetClusterNode.State) `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        }
    }

    #########################
    # Operating System
    #########################
    Write-Verbose "Working on Operating System"

    $analyzedResults = Add-AnalyzedResultInformation -Name "Version" -Details ($osInformation.BuildInformation.FriendlyName) `
        -DisplayGroupingKey $keyOSInformation `
        -AddHtmlOverviewValues $true `
        -HtmlName "OS Version" `
        -AnalyzedInformation $analyzedResults

    $upTime = "{0} day(s) {1} hour(s) {2} minute(s) {3} second(s)" -f $osInformation.ServerBootUp.Days,
    $osInformation.ServerBootUp.Hours,
    $osInformation.ServerBootUp.Minutes,
    $osInformation.ServerBootUp.Seconds

    $analyzedResults = Add-AnalyzedResultInformation -Name "System Up Time" -Details $upTime `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayTestingValue ($osInformation.ServerBootUp) `
        -AddHtmlDetailRow $false `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Time Zone" -Details ($osInformation.TimeZone.CurrentTimeZone) `
        -DisplayGroupingKey $keyOSInformation `
        -AddHtmlOverviewValues $true `
        -AnalyzedInformation $analyzedResults

    $writeValue = $false
    $warning = @("Windows can not properly detect any DST rule changes in your time zone. Set 'Adjust for daylight saving time automatically to on'")

    if ($osInformation.TimeZone.DstIssueDetected) {
        $writeType = "Red"
    } elseif ($osInformation.TimeZone.DynamicDaylightTimeDisabled -ne 0) {
        $writeType = "Yellow"
    } else {
        $warning = [string]::Empty
        $writeValue = $true
        $writeType = "Grey"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Dynamic Daylight Time Enabled" -Details $writeValue `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $writeType `
        -AnalyzedInformation $analyzedResults

    if ($warning -ne [string]::Empty) {
        $analyzedResults = Add-AnalyzedResultInformation -Details $warning `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow" `
            -DisplayCustomTabNumber 2 `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    if ([string]::IsNullOrEmpty($osInformation.TimeZone.TimeZoneKeyName)) {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Time Zone Key Name" -Details "Empty --- Warning Need to switch your current time zone to a different value, then switch it back to have this value populated again." `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow" `
            -AnalyzedInformation $analyzedResults
    }

    if ($exchangeInformation.NETFramework.OnRecommendedVersion) {
        $analyzedResults = Add-AnalyzedResultInformation -Name ".NET Framework" -Details ($osInformation.NETFramework.FriendlyName) `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Green" `
            -AddHtmlOverviewValues $true `
            -AnalyzedInformation $analyzedResults
    } else {
        $testObject = New-Object PSCustomObject
        $testObject | Add-Member -MemberType NoteProperty -Name "CurrentValue" -Value ($osInformation.NETFramework.FriendlyName)
        $testObject | Add-Member -MemberType NoteProperty -Name "MaxSupportedVersion" -Value ($exchangeInformation.NETFramework.MaxSupportedVersion)
        $displayFriendly = Get-NETFrameworkVersion -NetVersionKey $exchangeInformation.NETFramework.MaxSupportedVersion
        $displayValue = "{0} - Warning Recommended .NET Version is {1}" -f $osInformation.NETFramework.FriendlyName, $displayFriendly.FriendlyName
        $analyzedResults = Add-AnalyzedResultInformation -Name ".NET Framework" -Details $displayValue `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow" `
            -DisplayTestingValue $testObject `
            -HtmlDetailsCustomValue ($osInformation.NETFramework.FriendlyName) `
            -AddHtmlOverviewValues $true `
            -AnalyzedInformation $analyzedResults
    }

    $displayValue = [string]::Empty
    $displayWriteType = "Yellow"
    $totalPhysicalMemory = $hardwareInformation.TotalMemory
    $maxPageSize = $osInformation.PageFile.MaxPageSize
    Write-Verbose "Total Memory: $totalPhysicalMemory"
    Write-Verbose "Page File: $maxPageSize"
    $testingValue = New-Object PSCustomObject
    $testingValue | Add-Member -MemberType NoteProperty -Name "TotalPhysicalMemory" -Value $totalPhysicalMemory
    $testingValue | Add-Member -MemberType NoteProperty -Name "MaxPageSize" -Value $maxPageSize
    $testingValue | Add-Member -MemberType NoteProperty -Name "MultiPageFile" -Value ($osInformation.PageFile.PageFile.Count -gt 1)
    $testingValue | Add-Member -MemberType NoteProperty -Name "RecommendedPageFile" -Value 0
    if ($maxPageSize -eq 0) {
        $displayValue = "Error: System is set to automatically manage the pagefile size."
        $displayWriteType = "Red"
    } elseif ($osInformation.PageFile.PageFile.Count -gt 1) {
        $displayValue = "Multiple page files detected. `r`n`t`tError: This has been know to cause performance issues please address this."
        $displayWriteType = "Red"
    } elseif ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {
        $testingValue.RecommendedPageFile = ($recommendedPageFileSize = [Math]::Round(($totalPhysicalMemory / 1MB) / 4))
        Write-Verbose "Recommended Page File Size: $recommendedPageFileSize"
        if ($recommendedPageFileSize -ne $maxPageSize) {
            $displayValue = "{0}MB `r`n`t`tWarning: Page File is not set to 25% of the Total System Memory which is {1}MB. Recommended is {2}MB" -f $maxPageSize, ([Math]::Round($totalPhysicalMemory / 1MB)), $recommendedPageFileSize
        } else {
            $displayValue = "{0}MB" -f $recommendedPageFileSize
            $displayWriteType = "Grey"
        }
    } elseif ($totalPhysicalMemory -ge 34359738368) {
        #32GB = 1024 * 1024 * 1024 * 32 = 34,359,738,368
        if ($maxPageSize -eq 32778) {
            $displayValue = "{0}MB" -f $maxPageSize
            $displayWriteType = "Grey"
        } else {
            $displayValue = "{0}MB `r`n`t`tWarning: Pagefile should be capped at 32778MB for 32GB plus 10MB - Article: https://aka.ms/HC-SystemRequirements2016#hardware-requirements-for-exchange-2016" -f $maxPageSize
        }
    } else {
        $testingValue.RecommendedPageFile = ($recommendedPageFileSize = [Math]::Round(($totalPhysicalMemory / 1MB) + 10))

        if ($recommendedPageFileSize -ne $maxPageSize) {
            $displayValue = "{0}MB `r`n`t`tWarning: Page File is not set to Total System Memory plus 10MB which should be {1}MB" -f $maxPageSize, $recommendedPageFileSize
        } else {
            $displayValue = "{0}MB" -f $maxPageSize
            $displayWriteType = "Grey"
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Page File Size" -Details $displayValue `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $testingValue `
        -AnalyzedInformation $analyzedResults

    if ($osInformation.PowerPlan.HighPerformanceSet) {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Power Plan" -Details ($osInformation.PowerPlan.PowerPlanSetting) `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Green" `
            -AnalyzedInformation $analyzedResults
    } else {
        $displayValue = "{0} --- Error" -f $osInformation.PowerPlan.PowerPlanSetting
        $analyzedResults = Add-AnalyzedResultInformation -Name "Power Plan" -Details $displayValue `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Red" `
            -AnalyzedInformation $analyzedResults
    }

    if ($osInformation.NetworkInformation.HttpProxy -eq "<None>") {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Http Proxy Setting" -Details ($osInformation.NetworkInformation.HttpProxy) `
            -DisplayGroupingKey $keyOSInformation `
            -HtmlDetailsCustomValue "None" `
            -AnalyzedInformation $analyzedResults
    } else {
        $displayValue = "{0} --- Warning this can cause client connectivity issues." -f $osInformation.NetworkInformation.HttpProxy
        $analyzedResults = Add-AnalyzedResultInformation -Name "Http Proxy Setting" -Details $displayValue `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow" `
            -DisplayTestingValue ($osInformation.NetworkInformation.HttpProxy) `
            -AnalyzedInformation $analyzedResults
    }

    $displayWriteType2012 = "Yellow"
    $displayWriteType2013 = "Yellow"
    $displayValue2012 = "Unknown"
    $displayValue2013 = "Unknown"

    if ($null -ne $osInformation.VcRedistributable) {

        if (Test-VisualCRedistributableUpToDate -Year 2012 -Installed $osInformation.VcRedistributable) {
            $displayWriteType2012 = "Green"
            $displayValue2012 = "$((Get-VisualCRedistributableInfo 2012).VersionNumber) Version is current"
        } elseif (Test-VisualCRedistributableInstalled -Year 2012 -Installed $osInformation.VcRedistributable) {
            $displayValue2012 = "Redistributable is outdated"
        }

        if (Test-VisualCRedistributableUpToDate -Year 2013 -Installed $osInformation.VcRedistributable) {
            $displayWriteType2013 = "Green"
            $displayValue2013 = "$((Get-VisualCRedistributableInfo 2013).VersionNumber) Version is current"
        } elseif (Test-VisualCRedistributableInstalled -Year 2013 -Installed $osInformation.VcRedistributable) {
            $displayValue2013 = "Redistributable is outdated"
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Visual C++ 2012" -Details $displayValue2012 `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $displayWriteType2012 `
        -AnalyzedInformation $analyzedResults

    if ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Visual C++ 2013" -Details $displayValue2013 `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType $displayWriteType2013 `
            -AnalyzedInformation $analyzedResults
    }

    if (($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge -and
            ($displayWriteType2012 -eq "Yellow" -or
            $displayWriteType2013 -eq "Yellow")) -or
        $displayWriteType2012 -eq "Yellow") {

        $analyzedResults = Add-AnalyzedResultInformation -Details "Note: For more information about the latest C++ Redistributeable please visit: https://aka.ms/HC-LatestVC`r`n`t`tThis is not a requirement to upgrade, only a notification to bring to your attention." `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType "Yellow" `
            -AnalyzedInformation $analyzedResults
    }

    $displayValue = "False"
    $writeType = "Grey"

    if ($osInformation.ServerPendingReboot.PendingReboot) {
        $displayValue = "True --- Warning a reboot is pending and can cause issues on the server."
        $writeType = "Yellow"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Server Pending Reboot" -Details $displayValue `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $writeType `
        -DisplayTestingValue ($osInformation.ServerPendingReboot.PendingReboot) `
        -AnalyzedInformation $analyzedResults

    ################################
    # Processor/Hardware Information
    ################################
    Write-Verbose "Working on Processor/Hardware Information"

    $analyzedResults = Add-AnalyzedResultInformation -Name "Type" -Details ($hardwareInformation.ServerType) `
        -DisplayGroupingKey $keyHardwareInformation `
        -AddHtmlOverviewValues $true `
        -Htmlname "Hardware Type" `
        -AnalyzedInformation $analyzedResults

    if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::Physical -or
        $hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2) {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Manufacturer" -Details ($hardwareInformation.Manufacturer) `
            -DisplayGroupingKey $keyHardwareInformation `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name "Model" -Details ($hardwareInformation.Model) `
            -DisplayGroupingKey $keyHardwareInformation `
            -AnalyzedInformation $analyzedResults
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Processor" -Details ($hardwareInformation.Processor.Name) `
        -DisplayGroupingKey $keyHardwareInformation `
        -AnalyzedInformation $analyzedResults

    $value = $hardwareInformation.Processor.NumberOfProcessors
    $processorName = "Number of Processors"

    if ($hardwareInformation.ServerType -ne [HealthChecker.ServerType]::Physical) {
        $analyzedResults = Add-AnalyzedResultInformation -Name $processorName -Details $value `
            -DisplayGroupingKey $keyHardwareInformation `
            -AnalyzedInformation $analyzedResults

        <# Comment out for now. Not sure if we have a lot of value here as i believe this changed in newer vmware hosts versions.
        if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::VMWare) {
            $analyzedResults = Add-AnalyzedResultInformation -Details "Note: Please make sure you are following VMware's performance recommendation to get the most out of your guest machine. VMware blog 'Does corespersocket Affect Performance?' https://blogs.vmware.com/vsphere/2013/10/does-corespersocket-affect-performance.html" `
                -DisplayGroupingKey $keyHardwareInformation `
                -DisplayCustomTabNumber 2 `
                -AnalyzedInformation $analyzedResults
        }
    #>
    } elseif ($value -gt 2) {
        $analyzedResults = Add-AnalyzedResultInformation -Name $processorName -Details ("{0} - Error: Recommended to only have 2 Processors" -f $value) `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Red" `
            -DisplayTestingValue $value `
            -HtmlDetailsCustomValue $value `
            -AnalyzedInformation $analyzedResults
    } else {
        $analyzedResults = Add-AnalyzedResultInformation -Name $processorName -Details $value `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Green" `
            -AnalyzedInformation $analyzedResults
    }

    $physicalValue = $hardwareInformation.Processor.NumberOfPhysicalCores
    $logicalValue = $hardwareInformation.Processor.NumberOfLogicalCores

    $displayWriteType = "Green"

    if (($logicalValue -gt 24 -and
            $exchangeInformation.BuildInformation.MajorVersion -lt [HealthChecker.ExchangeMajorVersion]::Exchange2019) -or
        $logicalValue -gt 48) {
        $displayWriteType = "Yellow"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Number of Physical Cores" -Details $physicalValue `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayWriteType $displayWriteType `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Number of Logical Cores" -Details $logicalValue `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayWriteType $displayWriteType `
        -AddHtmlOverviewValues $true `
        -AnalyzedInformation $analyzedResults

    $displayValue = "Disabled"
    $displayWriteType = "Green"
    $displayTestingValue = $false
    $additionalDisplayValue = [string]::Empty
    $additionalWriteType = "Red"

    if ($logicalValue -gt $physicalValue) {

        if ($hardwareInformation.ServerType -ne [HealthChecker.ServerType]::HyperV) {
            $displayValue = "Enabled --- Error: Having Hyper-Threading enabled goes against best practices and can cause performance issues. Please disable as soon as possible."
            $displayTestingValue = $true
            $displayWriteType = "Red"
        } else {
            $displayValue = "Enabled --- Not Applicable"
            $displayTestingValue = $true
            $displayWriteType = "Grey"
        }

        if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2) {
            $additionalDisplayValue = "Error: For high-performance computing (HPC) application, like Exchange, Amazon recommends that you have Hyper-Threading Technology disabled in their service. More information: https://aka.ms/HC-EC2HyperThreading"
        }

        if ($hardwareInformation.Processor.Name.StartsWith("AMD")) {
            $additionalDisplayValue = "This script may incorrectly report that Hyper-Threading is enabled on certain AMD processors. Check with the manufacturer to see if your model supports SMT."
            $additionalWriteType = "Yellow"
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Hyper-Threading" -Details $displayValue `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $displayTestingValue `
        -AnalyzedInformation $analyzedResults

    if (!([string]::IsNullOrEmpty($additionalDisplayValue))) {
        $analyzedResults = Add-AnalyzedResultInformation -Details $additionalDisplayValue `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType $additionalWriteType `
            -DisplayCustomTabNumber 2 `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    #NUMA BIOS CHECK - AKA check to see if we can properly see all of our cores on the box
    $displayWriteType = "Yellow"
    $testingValue = "Unknown"
    $displayValue = [string]::Empty

    if ($hardwareInformation.Model.Contains("ProLiant")) {
        $name = "NUMA Group Size Optimization"

        if ($hardwareInformation.Processor.EnvironmentProcessorCount -eq -1) {
            $displayValue = "Unknown `r`n`t`tWarning: If this is set to Clustered, this can cause multiple types of issues on the server"
        } elseif ($hardwareInformation.Processor.EnvironmentProcessorCount -ne $logicalValue) {
            $displayValue = "Clustered `r`n`t`tError: This setting should be set to Flat. By having this set to Clustered, we will see multiple different types of issues."
            $testingValue = "Clustered"
            $displayWriteType = "Red"
        } else {
            $displayValue = "Flat"
            $testingValue = "Flat"
            $displayWriteType = "Green"
        }
    } else {
        $name = "All Processor Cores Visible"

        if ($hardwareInformation.Processor.EnvironmentProcessorCount -eq -1) {
            $displayValue = "Unknown `r`n`t`tWarning: If we aren't able to see all processor cores from Exchange, we could see performance related issues."
        } elseif ($hardwareInformation.Processor.EnvironmentProcessorCount -ne $logicalValue) {
            $displayValue = "Failed `r`n`t`tError: Not all Processor Cores are visible to Exchange and this will cause a performance impact"
            $displayWriteType = "Red"
            $testingValue = "Failed"
        } else {
            $displayWriteType = "Green"
            $displayValue = "Passed"
            $testingValue = "Passed"
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name $name -Details $displayValue `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $testingValue `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Max Processor Speed" -Details ($hardwareInformation.Processor.MaxMegacyclesPerCore) `
        -DisplayGroupingKey $keyHardwareInformation `
        -AnalyzedInformation $analyzedResults

    if ($hardwareInformation.Processor.ProcessorIsThrottled) {
        $currentSpeed = $hardwareInformation.Processor.CurrentMegacyclesPerCore
        $analyzedResults = Add-AnalyzedResultInformation -Name "Current Processor Speed" -Details ("{0} --- Error: Processor appears to be throttled." -f $currentSpeed) `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Red" `
            -DisplayTestingValue $currentSpeed `
            -AnalyzedInformation $analyzedResults

        $displayValue = "Error: Power Plan is NOT set to `"High Performance`". This change doesn't require a reboot and takes affect right away. Re-run script after doing so"

        if ($osInformation.PowerPlan.HighPerformanceSet) {
            $displayValue = "Error: Power Plan is set to `"High Performance`", so it is likely that we are throttling in the BIOS of the computer settings."
        }

        $analyzedResults = Add-AnalyzedResultInformation -Details $displayValue `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Red" `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    $totalPhysicalMemory = [System.Math]::Round($hardwareInformation.TotalMemory / 1024 / 1024 / 1024)
    $displayWriteType = "Yellow"
    $displayDetails = [string]::Empty

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {

        if ($totalPhysicalMemory -gt 256) {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 256 GB of Memory" -f $totalPhysicalMemory
        } elseif ($totalPhysicalMemory -lt 64 -and
            $exchangeInformation.BuildInformation.ServerRole -eq [HealthChecker.ExchangeServerRole]::Edge) {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to have a minimum of 64GB of RAM installed on the machine." -f $totalPhysicalMemory
        } elseif ($totalPhysicalMemory -lt 128) {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to have a minimum of 128GB of RAM installed on the machine." -f $totalPhysicalMemory
        } else {
            $displayDetails = "{0} GB" -f $totalPhysicalMemory
            $displayWriteType = "Grey"
        }
    } elseif ($totalPhysicalMemory -gt 192 -and
        $exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) {
        $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 192 GB of Memory." -f $totalPhysicalMemory
    } elseif ($totalPhysicalMemory -gt 96 -and
        $exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013) {
        $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 96GB of Memory." -f $totalPhysicalMemory
    } else {
        $displayDetails = "{0} GB" -f $totalPhysicalMemory
        $displayWriteType = "Grey"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Physical Memory" -Details $displayDetails `
        -DisplayGroupingKey $keyHardwareInformation `
        -DipslayTestingValue $totalPhysicalMemory `
        -DisplayWriteType $displayWriteType `
        -AddHtmlOverviewValues $true `
        -AnalyzedInformation $analyzedResults

    ################################
    #NIC Settings Per Active Adapter
    ################################
    Write-Verbose "Working on NIC Settings Per Active Adapter Information"

    foreach ($adapter in $osInformation.NetworkInformation.NetworkAdapters) {

        if ($adapter.Description -eq "Remote NDIS Compatible Device") {
            Write-Verbose "Remote NDSI Compatible Device found. Ignoring NIC."
            continue
        }

        $value = "{0} [{1}]" -f $adapter.Description, $adapter.Name
        $analyzedResults = Add-AnalyzedResultInformation -Name "Interface Description" -Details $value `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayCustomTabNumber 1 `
            -AnalyzedInformation $analyzedResults

        if ($osInformation.BuildInformation.MajorVersion -ge [HealthChecker.OSServerVersion]::Windows2012R2) {
            Write-Verbose "On Windows 2012 R2 or new. Can provide more details on the NICs"

            $driverDate = $adapter.DriverDate
            $detailsValue = $driverDate

            if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::Physical -or
                $hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2) {

                if ($null -eq $driverDate -or
                    $driverDate -eq [DateTime]::MaxValue) {
                    $detailsValue = "Unknown"
                } elseif ((New-TimeSpan -Start $date -End $driverDate).Days -lt [int]-365) {
                    $analyzedResults = Add-AnalyzedResultInformation -Details "Warning: NIC driver is over 1 year old. Verify you are at the latest version." `
                        -DisplayGroupingKey $keyNICSettings `
                        -DisplayWriteType "Yellow" `
                        -AddHtmlDetailRow $false `
                        -AnalyzedInformation $analyzedResults
                }
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "Driver Date" -Details $detailsValue `
                -DisplayGroupingKey $keyNICSettings `
                -AnalyzedInformation $analyzedResults

            $analyzedResults = Add-AnalyzedResultInformation -Name "Driver Version" -Details ($adapter.DriverVersion) `
                -DisplayGroupingKey $keyNICSettings `
                -AnalyzedInformation $analyzedResults

            $analyzedResults = Add-AnalyzedResultInformation -Name "MTU Size" -Details ($adapter.MTUSize) `
                -DisplayGroupingKey $keyNICSettings `
                -AnalyzedInformation $analyzedResults

            $analyzedResults = Add-AnalyzedResultInformation -Name "Max Processors" -Details ($adapter.NetAdapterRss.MaxProcessors) `
                -DisplayGroupingKey $keyNICSettings `
                -AnalyzedInformation $analyzedResults

            $analyzedResults = Add-AnalyzedResultInformation -Name "Max Processor Number" -Details ($adapter.NetAdapterRss.MaxProcessorNumber) `
                -DisplayGroupingKey $keyNICSettings `
                -AnalyzedInformation $analyzedResults

            $analyzedResults = Add-AnalyzedResultInformation -Name "Number of Receive Queues" -Details ($adapter.NetAdapterRss.NumberOfReceiveQueues) `
                -DisplayGroupingKey $keyNICSettings `
                -AnalyzedInformation $analyzedResults

            $writeType = "Yellow"
            $testingValue = $null

            if ($adapter.RssEnabledValue -eq 0) {
                $detailsValue = "False --- Warning: Enabling RSS is recommended."
                $testingValue = $false
            } elseif ($adapter.RssEnabledValue -eq 1) {
                $detailsValue = "True"
                $testingValue = $true
                $writeType = "Green"
            } else {
                $detailsValue = "No RSS Feature Detected."
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "RSS Enabled" -Details $detailsValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayWriteType $writeType `
                -DisplayTestingValue $testingValue `
                -AnalyzedInformation $analyzedResults
        } else {
            Write-Verbose "On Windows 2012 or older and can't get advanced NIC settings"
        }

        $linkSpeed = $adapter.LinkSpeed
        $displayValue = "{0} --- This may not be accurate due to virtualized hardware" -f $linkSpeed

        if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::Physical -or
            $hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2) {
            $displayValue = $linkSpeed
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "Link Speed" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayTestingValue $linkSpeed `
            -AnalyzedInformation $analyzedResults

        $displayValue = "{0}" -f $adapter.IPv6Enabled
        $displayWriteType = "Grey"
        $testingValue = $adapter.IPv6Enabled

        if ($osInformation.NetworkInformation.IPv6DisabledComponents -ne 255 -and
            $adapter.IPv6Enabled -eq $false) {
            $displayValue = "{0} --- Warning" -f $adapter.IPv6Enabled
            $displayWriteType = "Yellow"
            $testingValue = $false
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "IPv6 Enabled" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayWriteType $displayWriteType `
            -DisplayTestingValue $TestingValue `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name "IPv4 Address" `
            -DisplayGroupingKey $keyNICSettings `
            -AnalyzedInformation $analyzedResults

        foreach ($address in $adapter.IPv4Addresses) {
            $displayValue = "{0}\{1}" -f $address.Address, $address.Subnet

            if ($address.DefaultGateway -ne [string]::Empty) {
                $displayValue += " Gateway: {0}" -f $address.DefaultGateway
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "Address" -Details $displayValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayCustomTabNumber 3 `
                -AnalyzedInformation $analyzedResults
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "IPv6 Address" `
            -DisplayGroupingKey $keyNICSettings `
            -AnalyzedInformation $analyzedResults

        foreach ($address in $adapter.IPv6Addresses) {
            $displayValue = "{0}\{1}" -f $address.Address, $address.Subnet

            if ($address.DefaultGateway -ne [string]::Empty) {
                $displayValue += " Gateway: {0}" -f $address.DefaultGateway
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "Address" -Details $displayValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayCustomTabNumber 3 `
                -AnalyzedInformation $analyzedResults
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "DNS Server" -Details $adapter.DnsServer `
            -DisplayGroupingKey $keyNICSettings `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name "Registered In DNS" -Details $adapter.RegisteredInDns `
            -DisplayGroupingKey $keyNICSettings `
            -AnalyzedInformation $analyzedResults

        #Assuming that all versions of Hyper-V doesn't allow sleepy NICs
        if (($hardwareInformation.ServerType -ne [HealthChecker.ServerType]::HyperV) -and ($adapter.PnPCapabilities -ne "MultiplexorNoPnP")) {
            $displayWriteType = "Grey"
            $displayValue = $adapter.SleepyNicDisabled

            if (!$adapter.SleepyNicDisabled) {
                $displayWriteType = "Yellow"
                $displayValue = "False --- Warning: It's recommended to disable NIC power saving options`r`n`t`t`tMore Information: https://aka.ms/HC-NICPowerManagement"
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "Sleepy NIC Disabled" -Details $displayValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayWriteType $displayWriteType `
                -DisplayTestingValue $adapter.SleepyNicDisabled `
                -AnalyzedInformation $analyzedResults
        }

        $adapterDescription = $adapter.Description
        $cookedValue = 0
        $foundCounter = $false

        if ($null -eq $osInformation.NetworkInformation.PacketsReceivedDiscarded) {
            Write-Verbose "PacketsReceivedDiscarded is null"
            continue
        }

        foreach ($prdInstance in $osInformation.NetworkInformation.PacketsReceivedDiscarded) {
            $instancePath = $prdInstance.Path
            $startIndex = $instancePath.IndexOf("(") + 1
            $charLength = $instancePath.Substring($startIndex, ($instancePath.IndexOf(")") - $startIndex)).Length
            $instanceName = $instancePath.Substring($startIndex, $charLength)
            $possibleInstanceName = $adapterDescription.Replace("#", "_")

            if ($instanceName -eq $adapterDescription -or
                $instanceName -eq $possibleInstanceName) {
                $cookedValue = $prdInstance.CookedValue
                $foundCounter = $true
                break
            }
        }

        $displayWriteType = "Yellow"
        $displayValue = $cookedValue
        $baseDisplayValue = "{0} --- {1}: This value should be at 0."
        $knownIssue = $false

        if ($foundCounter) {

            if ($cookedValue -eq 0) {
                $displayWriteType = "Green"
            } elseif ($cookedValue -lt 1000) {
                $displayValue = $baseDisplayValue -f $cookedValue, "Warning"
            } else {
                $displayWriteType = "Red"
                $displayValue = [string]::Concat(($baseDisplayValue -f $cookedValue, "Error"), "We are also seeing this value being rather high so this can cause a performance impacted on a system.")
            }

            if ($adapterDescription -like "*vmxnet3*" -and
                $cookedValue -gt 0) {
                $knownIssue = $true
            }
        } else {
            $displayValue = "Couldn't find value for the counter."
            $cookedValue = $null
            $displayWriteType = "Grey"
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "Packets Received Discarded" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayTestingValue $cookedValue `
            -DisplayWriteType $displayWriteType `
            -AnalyzedInformation $analyzedResults

        if ($knownIssue) {
            $analyzedResults = Add-AnalyzedResultInformation -Details "Known Issue with vmxnet3: 'Large packet loss at the guest operating system level on the VMXNET3 vNIC in ESXi (2039495)' - https://aka.ms/HC-VMwareLostPackets" `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayWriteType "Yellow" `
                -DisplayCustomTabNumber 3 `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
    }

    if ($osInformation.NetworkInformation.NetworkAdapters.Count -gt 1) {
        $analyzedResults = Add-AnalyzedResultInformation -Details "Multiple active network adapters detected. Exchange 2013 or greater may not need separate adapters for MAPI and replication traffic.  For details please refer to https://aka.ms/HC-PlanHA#network-requirements" `
            -DisplayGroupingKey $keyNICSettings `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    if ($osInformation.NetworkInformation.IPv6DisabledOnNICs) {
        $displayWriteType = "Grey"
        $displayValue = "True"
        $testingValue = $true

        if ($osInformation.NetworkInformation.IPv6DisabledComponents -eq -1) {
            $displayWriteType = "Red"
            $testingValue = $false
            $displayValue = "False `r`n`t`tError: IPv6 is disabled on some NIC level settings but not correctly disabled via DisabledComponents registry value. It is currently set to '-1'. `r`n`t`tThis setting cause a system startup delay of 5 seconds. For details please refer to: `r`n`t`thttps://aka.ms/HC-ConfigureIPv6"
        } elseif ($osInformation.NetworkInformation.IPv6DisabledComponents -ne 255) {
            $displayWriteType = "Red"
            $testingValue = $false
            $displayValue = "False `r`n`t`tError: IPv6 is disabled on some NIC level settings but not fully disabled. DisabledComponents registry value currently set to '{0}'. For details please refer to the following articles: `r`n`t`thttps://aka.ms/HC-DisableIPv6`r`n`t`thttps://aka.ms/HC-ConfigureIPv6" -f $osInformation.NetworkInformation.IPv6DisabledComponents
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "Disable IPv6 Correctly" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayWriteType $displayWriteType `
            -DisplayCustomTabNumber 1 `
            -AnalyzedInformation $analyzedResults
    }

    ################
    #TCP/IP Settings
    ################
    Write-Verbose "Working on TCP/IP Settings"

    $tcpKeepAlive = $osInformation.NetworkInformation.TCPKeepAlive

    if ($tcpKeepAlive -eq 0) {
        $displayValue = "Not Set `r`n`t`tError: Without this value the KeepAliveTime defaults to two hours, which can cause connectivity and performance issues between network devices such as firewalls and load balancers depending on their configuration. `r`n`t`tMore details: https://aka.ms/HC-TSPerformanceChecklist"
        $displayWriteType = "Red"
    } elseif ($tcpKeepAlive -lt 900000 -or
        $tcpKeepAlive -gt 1800000) {
        $displayValue = "{0} `r`n`t`tWarning: Not configured optimally, recommended value between 15 to 30 minutes (900000 and 1800000 decimal). `r`n`t`tMore details: https://aka.ms/HC-TSPerformanceChecklist" -f $tcpKeepAlive
        $displayWriteType = "Yellow"
    } else {
        $displayValue = $tcpKeepAlive
        $displayWriteType = "Green"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "TCP/IP Settings" -Details $displayValue `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $tcpKeepAlive `
        -HtmlName "TCPKeepAlive" `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "RPC Min Connection Timeout" -Details ("{0} `r`n`t`tMore Information: https://aka.ms/HC-RPCSetting" -f $osInformation.NetworkInformation.RpcMinConnectionTimeout) `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -HtmlName "RPC Minimum Connection Timeout" `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "FIPS Algorithm Policy Enabled" -Details ($exchangeInformation.RegistryValues.FipsAlgorithmPolicyEnabled) `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -HtmlName "FipsAlgorithmPolicy-Enabled" `
        -AnalyzedInformation $analyzedResults

    $displayValue = $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage
    $displayWriteType = "Green"

    if ($exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage -ne 0) {
        $displayWriteType = "Red"
        $displayValue = "{0} `r`n`t`tError: This can cause an impact to the server's search performance. This should only be used a temporary fix if no other options are available vs a long term solution." -f $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "CTS Processor Affinity Percentage" -Details $displayValue `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue ($exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage) `
        -HtmlName "CtsProcessorAffinityPercentage" `
        -AnalyzedInformation $analyzedResults

    $displayValue = $osInformation.CredentialGuardEnabled
    $displayWriteType = "Grey"

    if ($osInformation.CredentialGuardEnabled) {
        $displayValue = "{0} `r`n`t`tError: Credential Guard is not supported on an Exchange Server. This can cause a performance hit on the server." -f $osInformation.CredentialGuardEnabled
        $displayWriteType = "Red"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Credential Guard Enabled" -Details $displayValue `
        -DisplayGroupingKey $keyFrequentConfigIssues `
        -DisplayWriteType $displayWriteType `
        -AnalyzedInformation $analyzedResults

    if ($null -ne $exchangeInformation.ApplicationConfigFileStatus -and
        $exchangeInformation.ApplicationConfigFileStatus.Count -ge 1) {

        foreach ($configKey in $exchangeInformation.ApplicationConfigFileStatus.Keys) {
            $configStatus = $exchangeInformation.ApplicationConfigFileStatus[$configKey]

            $writeType = "Green"
            $writeName = "{0} Present" -f $configKey
            $writeValue = $configStatus.Present

            if (!$configStatus.Present) {
                $writeType = "Red"
                $writeValue = "{0} --- Error" -f $writeValue
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name $writeName -Details $writeValue `
                -DisplayGroupingKey $keyFrequentConfigIssues `
                -DisplayWriteType $writeType `
                -AnalyzedInformation $analyzedResults
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "LmCompatibilityLevel Settings" -Details ($osInformation.LmCompatibility.RegistryValue) `
        -DisplayGroupingKey $keySecuritySettings `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Description" -Details ($osInformation.LmCompatibility.Description) `
        -DisplayGroupingKey $keySecuritySettings `
        -DisplayCustomTabNumber 2 `
        -AddHtmlDetailRow $false `
        -AnalyzedInformation $analyzedResults

    ##############
    # TLS Settings
    ##############
    Write-Verbose "Working on TLS Settings"

    $tlsVersions = @("1.0", "1.1", "1.2")
    $currentNetVersion = $osInformation.TLSSettings["NETv4"]

    foreach ($tlsKey in $tlsVersions) {
        $currentTlsVersion = $osInformation.TLSSettings[$tlsKey]

        $analyzedResults = Add-AnalyzedResultInformation -Details ("TLS {0}" -f $tlsKey) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 1 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name ("Server Enabled") -Details ($currentTlsVersion.ServerEnabled) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name ("Server Disabled By Default") -Details ($currentTlsVersion.ServerDisabledByDefault) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name ("Client Enabled") -Details ($currentTlsVersion.ClientEnabled) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name ("Client Disabled By Default") -Details ($currentTlsVersion.ClientDisabledByDefault) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        if ($currentTlsVersion.ServerEnabled -ne $currentTlsVersion.ClientEnabled) {
            $detectedTlsMismatch = $true
            $analyzedResults = Add-AnalyzedResultInformation -Details ("Error: Mismatch in TLS version for client and server. Exchange can be both client and a server. This can cause issues within Exchange for communication.") `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 3 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        }

        if (($tlsKey -eq "1.0" -or
                $tlsKey -eq "1.1") -and (
                $currentTlsVersion.ServerEnabled -eq $false -or
                $currentTlsVersion.ClientEnabled -eq $false -or
                $currentTlsVersion.ServerDisabledByDefault -or
                $currentTlsVersion.ClientDisabledByDefault) -and
            ($currentNetVersion.SystemDefaultTlsVersions -eq $false -or
            $currentNetVersion.WowSystemDefaultTlsVersions -eq $false)) {
            $analyzedResults = Add-AnalyzedResultInformation -Details ("Error: SystemDefaultTlsVersions is not set to the recommended value. Please visit on how to properly enable TLS 1.2 https://aka.ms/HC-TLSPart2") `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 3 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "SystemDefaultTlsVersions" -Details ($currentNetVersion.SystemDefaultTlsVersions) `
        -DisplayGroupingKey $keySecuritySettings `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "SystemDefaultTlsVersions - Wow6432Node" -Details ($currentNetVersion.WowSystemDefaultTlsVersions) `
        -DisplayGroupingKey $keySecuritySettings `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "SchUseStrongCrypto" -Details ($currentNetVersion.SchUseStrongCrypto) `
        -DisplayGroupingKey $keySecuritySettings `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "SchUseStrongCrypto - Wow6432Node" -Details ($currentNetVersion.WowSchUseStrongCrypto) `
        -DisplayGroupingKey $keySecuritySettings `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "SecurityProtocol" -Details ($currentNetVersion.SecurityProtocol) `
        -DisplayGroupingKey $keySecuritySettings `
        -AnalyzedInformation $analyzedResults

    <#
    [array]$securityProtocols = $currentNetVersion.SecurityProtocol.Split(",").Trim().ToUpper()
    $lowerTLSVersions = @("1.0", "1.1")

    foreach ($tlsKey in $lowerTLSVersions) {
        $currentTlsVersion = $osInformation.TLSSettings[$tlsKey]
        $securityProtocolCheck = "TLS"
        if ($tlsKey -eq "1.1") {
            $securityProtocolCheck = "TLS11"
        }

        if (($currentTlsVersion.ServerEnabled -eq $false -or
                $currentTlsVersion.ClientEnabled -eq $false) -and
            $securityProtocols.Contains($securityProtocolCheck)) {

            $analyzedResults = Add-AnalyzedResultInformation -Details ("Security Protocol is able to use TLS when we have TLS {0} disabled in the registry. This can cause issues with connectivity. It is recommended to follow the proper TLS settings. In some cases, it may require to also set SchUseStrongCrypto in the registry." -f $tlsKey) `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AnalyzedInformation $analyzedResults
        }
    }
#>

    if ($detectedTlsMismatch) {
        $displayValues = @("Exchange Server TLS guidance Part 1: Getting Ready for TLS 1.2: https://aka.ms/HC-TLSPart1",
            "Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It: https://aka.ms/HC-TLSPart2",
            "Exchange Server TLS guidance Part 3: Turning Off TLS 1.0/1.1: https://aka.ms/HC-TLSPart3")

        $analyzedResults = Add-AnalyzedResultInformation -Details "For More Information on how to properly set TLS follow these blog posts:" `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType "Yellow" `
            -AnalyzedInformation $analyzedResults

        foreach ($displayValue in $displayValues) {
            $analyzedResults = Add-AnalyzedResultInformation -Details $displayValue `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayWriteType "Yellow" `
                -DisplayCustomTabNumber 3 `
                -AnalyzedInformation $analyzedResults
        }
    }

    foreach ($certificate in $exchangeInformation.ExchangeCertificates) {

        if ($certificate.LifetimeInDays -ge 60) {
            $displayColor = "Green"
        } elseif ($certificate.LifetimeInDays -ge 30) {
            $displayColor = "Yellow"
        } else {
            $displayColor = "Red"
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "Certificate" `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 1 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name "FriendlyName" -Details $certificate.FriendlyName `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name "Thumbprint" -Details $certificate.Thumbprint `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name "Lifetime in days" -Details $certificate.LifetimeInDays `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType $displayColor `
            -AnalyzedInformation $analyzedResults

        if ($certificate.LifetimeInDays -lt 0) {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Certificate has expired" -Details $true `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        } else {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Certificate has expired" -Details $false `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -AnalyzedInformation $analyzedResults
        }

        $certStatusWriteType = [string]::Empty

        if ($null -ne $certificate.Status) {
            Switch ($certificate.Status) {
                ("Unknown") { $certStatusWriteType = "Yellow" }
                ("Valid") { $certStatusWriteType = "Grey" }
                ("Revoked") { $certStatusWriteType = "Red" }
                ("DateInvalid") { $certStatusWriteType = "Red" }
                ("Untrusted") { $certStatusWriteType = "Yellow" }
                ("Invalid") { $certStatusWriteType = "Red" }
                ("RevocationCheckFailure") { $certStatusWriteType = "Yellow" }
                ("PendingRequest") { $certStatusWriteType = "Yellow" }
                default { $certStatusWriteType = "Yellow" }
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "Certificate status" -Details $certificate.Status `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType $certStatusWriteType `
                -AnalyzedInformation $analyzedResults
        } else {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Certificate status" -Details "Unknown" `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AnalyzedInformation $analyzedResults
        }

        if ($certificate.PublicKeySize -lt 2048) {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Key size" -Details $certificate.PublicKeySize `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults

            $analyzedResults = Add-AnalyzedResultInformation -Details "It's recommended to use a key size of at least 2048 bit" `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        } else {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Key size" -Details $certificate.PublicKeySize `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -AnalyzedInformation $analyzedResults
        }

        if ($certificate.SignatureHashAlgorithmSecure -eq 1) {
            $shaDisplayWriteType = "Yellow"
        } else {
            $shaDisplayWriteType = "Grey"
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "Signature Algorithm" -Details $certificate.SignatureAlgorithm `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType $shaDisplayWriteType `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name "Signature Hash Algorithm" -Details $certificate.SignatureHashAlgorithm `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType $shaDisplayWriteType `
            -AnalyzedInformation $analyzedResults

        if ($shaDisplayWriteType -eq "Yellow") {
            $analyzedResults = Add-AnalyzedResultInformation -Details "It's recommended to use a hash algorithm from the SHA-2 family `r`n`t`tMore information: https://aka.ms/HC-SSLBP" `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType $shaDisplayWriteType `
                -AnalyzedInformation $analyzedResults
        }

        if ($null -ne $certificate.Services) {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Bound to services" -Details $certificate.Services `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -AnalyzedInformation $analyzedResults
        }

        if ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Current Auth Certificate" -Details $certificate.IsCurrentAuthConfigCertificate `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -AnalyzedInformation $analyzedResults
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "SAN Certificate" -Details $certificate.IsSanCertificate `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name "Namespaces" `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        foreach ($namespace in $certificate.Namespaces) {
            $analyzedResults = Add-AnalyzedResultInformation -Details $namespace `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 3 `
                -AnalyzedInformation $analyzedResults
        }

        if ($certificate.IsCurrentAuthConfigCertificate -eq $true) {
            $currentAuthCertificate = $certificate
        }
    }

    if ($null -ne $currentAuthCertificate) {
        if ($currentAuthCertificate.LifetimeInDays -gt 0) {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Valid Auth Certificate Found On Server" -Details $true `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 1 `
                -DisplayWriteType "Green" `
                -AnalyzedInformation $analyzedResults
        } else {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Valid Auth Certificate Found On Server" -Details $false `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 1 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults

            $renewExpiredAuthCert = "Auth Certificate has expired `r`n`t`tMore Information: https://aka.ms/HC-OAuthExpired"
            $analyzedResults = Add-AnalyzedResultInformation -Details $renewExpiredAuthCert `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        }
    } elseif ($exchangeInformation.BuildInformation.ServerRole -eq [HealthChecker.ExchangeServerRole]::Edge) {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Valid Auth Certificate Found On Server" -Details $false `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 1 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Details "We can't check for Auth Certificates on Edge Transport Servers" `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults
    } else {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Valid Auth Certificate Found On Server" -Details $false `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 1 `
            -DisplayWriteType "Red" `
            -AnalyzedInformation $analyzedResults

        $createNewAuthCert = "No valid Auth Certificate found. This may cause several problems. `r`n`t`tMore Information: https://aka.ms/HC-FindOAuthHybrid"
        $analyzedResults = Add-AnalyzedResultInformation -Details $createNewAuthCert `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType "Red" `
            -AnalyzedInformation $analyzedResults
    }

    $additionalDisplayValue = [string]::Empty
    $smb1Settings = $osInformation.Smb1ServerSettings

    if ($osInformation.BuildInformation.MajorVersion -gt [HealthChecker.OSServerVersion]::Windows2012) {
        $displayValue = "False"
        $writeType = "Green"

        if (-not ($smb1Settings.SuccessfulGetInstall)) {
            $displayValue = "Failed to get install status"
            $writeType = "Yellow"
        } elseif ($smb1Settings.Installed) {
            $displayValue = "True"
            $writeType = "Red"
            $additionalDisplayValue = "SMB1 should be uninstalled"
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "SMB1 Installed" -Details $displayValue `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType $writeType `
            -AnalyzedInformation $analyzedResults
    }

    $writeType = "Green"
    $displayValue = "True"

    if (-not ($smb1Settings.SuccessfulGetBlocked)) {
        $displayValue = "Failed to get block status"
        $writeType = "Yellow"
    } elseif (-not($smb1Settings.IsBlocked)) {
        $displayValue = "False"
        $writeType = "Red"
        $additionalDisplayValue += " SMB1 should be blocked"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "SMB1 Blocked" -Details $displayValue `
        -DisplayGroupingKey $keySecuritySettings `
        -DisplayWriteType $writeType `
        -AnalyzedInformation $analyzedResults

    if ($additionalDisplayValue -ne [string]::Empty) {
        $additionalDisplayValue += "`r`n`t`tMore Information: https://aka.ms/HC-SMB1"

        $analyzedResults = Add-AnalyzedResultInformation -Details $additionalDisplayValue.Trim() `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType "Yellow" `
            -DisplayCustomTabNumber 2 `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    ##########################
    #Exchange Web App GC Mode#
    ##########################
    if ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) {
        Write-Verbose "Working on Exchange Web App GC Mode"

        $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]
        foreach ($webAppKey in $exchangeInformation.ApplicationPools.Keys) {

            $appPool = $exchangeInformation.ApplicationPools[$webAppKey]
            $appRestarts = $appPool.AppSettings.add.recycling.periodicRestart
            $appRestartSet = ($appRestarts.PrivateMemory -ne "0" -or
                $appRestarts.Memory -ne "0" -or
                $appRestarts.Requests -ne "0" -or
                $null -ne $appRestarts.Schedule -or
                ($appRestarts.Time -ne "00:00:00" -and
                    ($webAppKey -ne "MSExchangeOWAAppPool" -and
                $webAppKey -ne "MSExchangeECPAppPool")))

            $outputObjectDisplayValue.Add(([PSCustomObject]@{
                        AppPoolName         = $webAppKey
                        State               = $appPool.AppSettings.state
                        GCServerEnabled     = $appPool.GCServerEnabled
                        RestartConditionSet = $appRestartSet
                    })
            )
        }

        $sbStarted = { param($o, $p) if ($p -eq "State") { if ($o."$p" -eq "Started") { "Green" } else { "Red" } } }
        $sbRestart = { param($o, $p) if ($p -eq "RestartConditionSet") { if ($o."$p") { "Red" } else { "Green" } } }
        $analyzedResults = Add-AnalyzedResultInformation -OutColumns ([PSCustomObject]@{
                DisplayObject      = $outputObjectDisplayValue
                ColorizerFunctions = @($sbStarted, $sbRestart)
                IndentSpaces       = 8
            }) `
            -DisplayGroupingKey $keyWebApps `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults

        $periodicStartAppPools = $outputObjectDisplayValue | Where-Object { $_.RestartConditionSet -eq $true }

        if ($null -ne $periodicStartAppPools) {

            $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]

            foreach ($appPool in $periodicStartAppPools) {
                $periodicRestart = $exchangeInformation.ApplicationPools[$appPool.AppPoolName].AppSettings.add.recycling.periodicRestart
                $schedule = $periodicRestart.Schedule

                if ([string]::IsNullOrEmpty($schedule)) {
                    $schedule = "null"
                }

                $outputObjectDisplayValue.Add(([PSCustomObject]@{
                            AppPoolName   = $appPool.AppPoolName
                            PrivateMemory = $periodicRestart.PrivateMemory
                            Memory        = $periodicRestart.Memory
                            Requests      = $periodicRestart.Requests
                            Schedule      = $schedule
                            Time          = $periodicRestart.Time
                        }))
            }

            $sbColorizer = {
                param($o, $p)
                switch ($p) {
                    { $_ -in "PrivateMemory", "Memory", "Requests" } {
                        if ($o."$p" -eq "0") { "Green" } else { "Red" }
                    }
                    "Time" {
                        if ($o."$p" -eq "00:00:00") { "Green" } else { "Red" }
                    }
                    "Schedule" {
                        if ($o."$p" -eq "null") { "Green" } else { "Red" }
                    }
                }
            }

            $analyzedResults = Add-AnalyzedResultInformation -OutColumns ([PSCustomObject]@{
                    DisplayObject      = $outputObjectDisplayValue
                    ColorizerFunctions = @($sbColorizer)
                    IndentSpaces       = 8
                }) `
                -DisplayGroupingKey $keyWebApps `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults

            $analyzedResults = Add-AnalyzedResultInformation -Details "Error: The above app pools currently have the periodic restarts set. This restart will cause disruption to end users." `
                -DisplayGroupingKey $keyWebApps `
                -DisplayWriteType "Red" `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
    }

    ######################
    # Vulnerability Checks
    ######################

    Function Test-VulnerabilitiesByBuildNumbersForDisplay {
        param(
            [Parameter(Mandatory = $true)][string]$ExchangeBuildRevision,
            [Parameter(Mandatory = $true)][array]$SecurityFixedBuilds,
            [Parameter(Mandatory = $true)][array]$CVENames
        )
        [int]$fileBuildPart = ($split = $ExchangeBuildRevision.Split("."))[0]
        [int]$filePrivatePart = $split[1]
        $Script:breakpointHit = $false

        foreach ($securityFixedBuild in $SecurityFixedBuilds) {
            [int]$securityFixedBuildPart = ($split = $securityFixedBuild.Split("."))[0]
            [int]$securityFixedPrivatePart = $split[1]

            if ($fileBuildPart -eq $securityFixedBuildPart) {
                $Script:breakpointHit = $true
            }

            if (($fileBuildPart -lt $securityFixedBuildPart) -or
                ($fileBuildPart -eq $securityFixedBuildPart -and
                $filePrivatePart -lt $securityFixedPrivatePart)) {
                foreach ($cveName in $CVENames) {
                    $details = "{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{0} for more information." -f $cveName
                    $Script:Vulnerabilities += $details
                    $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Name "Security Vulnerability" -Details $details `
                        -DisplayGroupingKey $keySecuritySettings `
                        -DisplayTestingValue $cveName `
                        -DisplayWriteType "Red" `
                        -AddHtmlDetailRow $false `
                        -AnalyzedInformation $Script:AnalyzedInformation
                }

                $Script:AllVulnerabilitiesPassed = $false
                break
            }

            if ($Script:breakpointHit) {
                break
            }
        }
    }

    Function Show-March2021SUOutdatedCUWarning {
        param(
            [Parameter(Mandatory = $true)][hashtable]$KBCVEHT
        )
        Write-Verbose "Calling: Show-March2021SUOutdatedCUWarning"

        foreach ($kbName in $KBCVEHT.Keys) {
            foreach ($cveName in $KBCVEHT[$kbName]) {
                $details = "`r`n`t`tPlease make sure {0} is installed to be fully protected against: {1}" -f $kbName, $cveName
                $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Name "March 2021 Exchange Security Update for unsupported CU detected" -Details $details `
                    -DisplayGroupingKey $keySecuritySettings `
                    -DisplayTestingValue $cveName `
                    -DisplayWriteType "Yellow" `
                    -AddHtmlDetailRow $false `
                    -AnalyzedInformation $Script:AnalyzedInformation
            }
        }
    }

    Function Test-DownloadDomainsConfiguration {
        param(
            [Parameter(Mandatory = $true)][object]$OwaVDirObject,
            [Parameter(Mandatory = $true)][bool]$DownloadDomainsEnabled
        )
        Write-Verbose "Calling: Test-DownloadDomainConfiguration"

        <#
        Unknown 0
        Download Domains disabled 1
        Download Domains enabled and configured as expected 2
        Download Domains enabled and external download host name = internal/external owa url 4
        Download Domains enabled but external download host name not set 8
        Download Domains enabled and internal download host name = internal/external owa url 16
        Download Domains enabled but internal download host name not set 32
        #>

        $downloadDomainsStatus = 0

        if ($DownloadDomainsEnabled) {
            $downloadDomainsStatus += 2

            if (![String]::IsNullOrEmpty($OwaVDirObject.ExternalDownloadHostName)) {

                if (($OwaVDirObject.ExternalDownloadHostName -eq $OwaVDirObject.ExternalUrl.Host) -or
                    ($OwaVDirObject.ExternalDownloadHostName -eq $OwaVDirObject.InternalUrl.Host)) {
                    $downloadDomainsStatus += 4
                }
            } else {
                Write-Verbose "'ExternalDownloadHostName' is not configured"
                $downloadDomainsStatus += 8
            }

            if (![String]::IsNullOrEmpty($OwaVDirObject.InternalDownloadHostName)) {

                if (($OwaVDirObject.InternalDownloadHostName -eq $OwaVDirObject.ExternalUrl.Host) -or
                    ($OwaVDirObject.InternalDownloadHostName -eq $OwaVDirObject.InternalUrl.Host)) {
                    $downloadDomainsStatus += 16
                }
            } else {
                Write-Verbose "'InternalDownloadHostName' is not configured"
                $downloadDomainsStatus += 32
            }

            return $downloadDomainsStatus
        } else {
            $downloadDomainsStatus += 1
            return $downloadDomainsStatus
        }
    }

    $Script:AllVulnerabilitiesPassed = $true
    $Script:Vulnerabilities = @()
    $Script:AnalyzedInformation = $analyzedResults
    [string]$buildRevision = ("{0}.{1}" -f $exchangeInformation.BuildInformation.ExchangeSetup.FileBuildPart, $exchangeInformation.BuildInformation.ExchangeSetup.FilePrivatePart)
    $exchangeCU = $exchangeInformation.BuildInformation.CU
    Write-Verbose "Exchange Build Revision: $buildRevision"
    Write-Verbose "Exchange CU: $exchangeCU"

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013) {

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU19) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1347.5", "1365.3" -CVENames "CVE-2018-0924", "CVE-2018-0940"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU20) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1365.7", "1367.6" -CVENames "CVE-2018-8151", "CVE-2018-8154", "CVE-2018-8159"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU21) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1367.9", "1395.7" -CVENames "CVE-2018-8302"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1395.8" -CVENames "CVE-2018-8265", "CVE-2018-8448"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1395.10" -CVENames "CVE-2019-0586", "CVE-2019-0588"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU22) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1473.3" -CVENames "CVE-2019-0686", "CVE-2019-0724"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1473.4" -CVENames "CVE-2019-0817", "CVE-2019-0858"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1473.5" -CVENames "ADV190018"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU23) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.3" -CVENames "CVE-2019-1084", "CVE-2019-1136", "CVE-2019-1137"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.4" -CVENames "CVE-2019-1373"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.6" -CVENames "CVE-2020-0688", "CVE-2020-0692"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.7" -CVENames "CVE-2020-16969"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.8" -CVENames "CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.10" -CVENames "CVE-2020-17117", "CVE-2020-17132", "CVE-2020-17142", "CVE-2020-17143"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1395.12", "1473.6", "1497.12" -CVENames "CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.12" -CVENames "CVE-2021-26412", "CVE-2021-27078", "CVE-2021-26854"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.15" -CVENames "CVE-2021-28480", "CVE-2021-28481", "CVE-2021-28482", "CVE-2021-28483"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.18" -CVENames "CVE-2021-31195", "CVE-2021-31198", "CVE-2021-31207", "CVE-2021-31209"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.23" -CVENames "CVE-2021-31206", "CVE-2021-31196", "CVE-2021-33768"
        }
    } elseif ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) {

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU8) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1261.39", "1415.4" -CVENames "CVE-2018-0924", "CVE-2018-0940", "CVE-2018-0941"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU9) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1415.7", "1466.8" -CVENames "CVE-2018-8151", "CVE-2018-8152", "CVE-2018-8153", "CVE-2018-8154", "CVE-2018-8159"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU10) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1466.9", "1531.6" -CVENames "CVE-2018-8374", "CVE-2018-8302"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1531.8" -CVENames "CVE-2018-8265", "CVE-2018-8448"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU11) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1531.8", "1591.11" -CVENames "CVE-2018-8604"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1531.10", "1591.13" -CVENames "CVE-2019-0586", "CVE-2019-0588"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU12) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1591.16", "1713.6" -CVENames "CVE-2019-0817", "CVE-2018-0858"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1591.17", "1713.7" -CVENames "ADV190018"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1713.5" -CVENames "CVE-2019-0686", "CVE-2019-0724"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU13) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1713.8", "1779.4" -CVENames "CVE-2019-1084", "CVE-2019-1136", "CVE-2019-1137"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1713.9", "1779.5" -CVENames "CVE-2019-1233", "CVE-2019-1266"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU14) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1779.7", "1847.5" -CVENames "CVE-2019-1373"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU15) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1847.7", "1913.7" -CVENames "CVE-2020-0688", "CVE-2020-0692"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1847.10", "1913.10" -CVENames "CVE-2020-0903"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU17) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1979.6", "2044.6" -CVENames "CVE-2020-16875"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU18) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2106.2" -CVENames "CVE-2021-1730"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2044.7", "2106.3" -CVENames "CVE-2020-16969"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2044.8", "2106.4" -CVENames "CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2044.12", "2106.6" -CVENames "CVE-2020-17117", "CVE-2020-17132", "CVE-2020-17141", "CVE-2020-17142", "CVE-2020-17143"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU19) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2106.8", "2176.4" -CVENames "CVE-2021-24085"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1415.8", "1466.13", "1531.12", "1591.18", "1713.10", "1779.8", "1847.12", "1913.12", "1979.8", "2044.13", "2106.13", "2176.9" -CVENames "CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2106.13", "2176.9" -CVENames "CVE-2021-26412", "CVE-2021-27078", "CVE-2021-26854"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU20) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2176.12", "2242.8" -CVENames "CVE-2021-28480", "CVE-2021-28481", "CVE-2021-28482", "CVE-2021-28483"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2176.14", "2242.10" -CVENames "CVE-2021-31195", "CVE-2021-31198", "CVE-2021-31207", "CVE-2021-31209"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU21) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2242.12", "2308.14" -CVENames "CVE-2021-31206", "CVE-2021-31196", "CVE-2021-33768"
        }
    } elseif ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU1) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "221.14" -CVENames "CVE-2019-0586", "CVE-2019-0588"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "221.16", "330.7" -CVENames "CVE-2019-0817", "CVE-2019-0858"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "221.17", "330.8" -CVENames "ADV190018"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "330.6" -CVENames "CVE-2019-0686", "CVE-2019-0724"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU2) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "330.9", "397.5" -CVENames "CVE-2019-1084", "CVE-2019-1137"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "397.6", "330.10" -CVENames "CVE-2019-1233", "CVE-2019-1266"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU3) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "397.9", "464.7" -CVENames "CVE-2019-1373"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU4) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "464.11", "529.8" -CVENames "CVE-2020-0688", "CVE-2020-0692"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "464.14", "529.11" -CVENames "CVE-2020-0903"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU6) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "595.6", "659.6" -CVENames "CVE-2020-16875"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU7) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "721.2" -CVENames "CVE-2021-1730"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "659.7", "721.3" -CVENames "CVE-2020-16969"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "659.8", "721.4" -CVENames "CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "659.11", "721.6" -CVENames "CVE-2020-17117", "CVE-2020-17132", "CVE-2020-17141", "CVE-2020-17142", "CVE-2020-17143"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU8) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "721.8", "792.5" -CVENames "CVE-2021-24085"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "221.18", "330.11", "397.11", "464.15", "529.13", "595.8", "659.12", "721.13", "792.10" -CVENames "CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "721.13", "792.10" -CVENames "CVE-2021-26412", "CVE-2021-27078", "CVE-2021-26854"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU9) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "792.13", "858.10" -CVENames "CVE-2021-28480", "CVE-2021-28481", "CVE-2021-28482", "CVE-2021-28483"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "792.15", "858.12" -CVENames "CVE-2021-31195", "CVE-2021-31198", "CVE-2021-31207", "CVE-2021-31209"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU10) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "858.15", "922.13" -CVENames "CVE-2021-31206", "CVE-2021-31196", "CVE-2021-33768"
        }
    } else {
        Write-Verbose "Unknown Version of Exchange"
        $Script:AllVulnerabilitiesPassed = $false
    }

    #Description: March 2021 Exchange vulnerabilities Security Update (SU) check for outdated version (CUs)
    #Affected Exchange versions: Exchange 2013, Exchange 2016, Exchange 2016 (we only provide this special SU for these versions)
    #Fix: Update to a supported CU and apply KB5000871

    if (($exchangeInformation.BuildInformation.March2021SUInstalled) -and ($exchangeInformation.BuildInformation.SupportedBuild -eq $false)) {
        if (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013) -and
            ($exchangeCU -lt [HealthChecker.ExchangeCULevel]::CU23)) {
            Switch ($exchangeCU) {
                ([HealthChecker.ExchangeCULevel]::CU21) { $KBCveComb = @{KB4340731 = "CVE-2018-8302"; KB4459266 = "CVE-2018-8265", "CVE-2018-8448"; KB4471389 = "CVE-2019-0586", "CVE-2019-0588" } }
                ([HealthChecker.ExchangeCULevel]::CU22) { $KBCveComb = @{KB4487563 = "CVE-2019-0817", "CVE-2019-0858"; KB4503027 = "ADV190018" } }
            }
            $Script:AllVulnerabilitiesPassed = $false
        } elseif (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) -and
            ($exchangeCU -lt [HealthChecker.ExchangeCULevel]::CU18)) {
            Switch ($exchangeCU) {
                ([HealthChecker.ExchangeCULevel]::CU8) { $KBCveComb = @{KB4073392 = "CVE-2018-0924", "CVE-2018-0940", "CVE-2018-0941"; KB4092041 = "CVE-2018-8151", "CVE-2018-8152", "CVE-2018-8153", "CVE-2018-8154", "CVE-2018-8159" } }
                ([HealthChecker.ExchangeCULevel]::CU9) { $KBCveComb = @{KB4092041 = "CVE-2018-8151", "CVE-2018-8152", "CVE-2018-8153", "CVE-2018-8154", "CVE-2018-8159"; KB4340731 = "CVE-2018-8374", "CVE-2018-8302" } }
                ([HealthChecker.ExchangeCULevel]::CU10) { $KBCveComb = @{KB4340731 = "CVE-2018-8374", "CVE-2018-8302"; KB4459266 = "CVE-2018-8265", "CVE-2018-8448"; KB4468741 = "CVE-2018-8604"; KB4471389 = "CVE-2019-0586", "CVE-2019-0588" } }
                ([HealthChecker.ExchangeCULevel]::CU11) { $KBCveComb = @{KB4468741 = "CVE-2018-8604"; KB4471389 = "CVE-2019-0586", "CVE-2019-0588"; KB4487563 = "CVE-2019-0817", "CVE-2018-0858"; KB4503027 = "ADV190018" } }
                ([HealthChecker.ExchangeCULevel]::CU12) { $KBCveComb = @{KB4487563 = "CVE-2019-0817", "CVE-2018-0858"; KB4503027 = "ADV190018"; KB4515832 = "CVE-2019-1233", "CVE-2019-1266" } }
                ([HealthChecker.ExchangeCULevel]::CU13) { $KBCveComb = @{KB4509409 = "CVE-2019-1084", "CVE-2019-1136", "CVE-2019-1137"; KB4515832 = "CVE-2019-1233", "CVE-2019-1266"; KB4523171 = "CVE-2019-1373" } }
                ([HealthChecker.ExchangeCULevel]::CU14) { $KBCveComb = @{KB4523171 = "CVE-2019-1373"; KB4536987 = "CVE-2020-0688", "CVE-2020-0692"; KB4540123 = "CVE-2020-0903" } }
                ([HealthChecker.ExchangeCULevel]::CU15) { $KBCveComb = @{KB4536987 = "CVE-2020-0688", "CVE-2020-0692"; KB4540123 = "CVE-2020-0903" } }
                ([HealthChecker.ExchangeCULevel]::CU16) { $KBCveComb = @{KB4577352 = "CVE-2020-16875" } }
                ([HealthChecker.ExchangeCULevel]::CU17) { $KBCveComb = @{KB4577352 = "CVE-2020-16875"; KB4581424 = "CVE-2020-16969"; KB4588741 = "CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085"; KB4593465 = "CVE-2020-17117", "CVE-2020-17132", "CVE-2020-17141", "CVE-2020-17142", "CVE-2020-17143" } }
            }
            $Script:AllVulnerabilitiesPassed = $false
        } elseif (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) -and
            ($exchangeCU -lt [HealthChecker.ExchangeCULevel]::CU7)) {
            Switch ($exchangeCU) {
                ([HealthChecker.ExchangeCULevel]::RTM) { $KBCveComb = @{KB4471389 = "CVE-2019-0586", "CVE-2019-0588"; KB4487563 = "CVE-2019-0817", "CVE-2019-0858"; KB4503027 = "ADV190018" } }
                ([HealthChecker.ExchangeCULevel]::CU1) { $KBCveComb = @{KB4487563 = "CVE-2019-0817", "CVE-2019-0858"; KB4503027 = "ADV190018"; KB4509409 = "CVE-2019-1084", "CVE-2019-1137"; KB4515832 = "CVE-2019-1233", "CVE-2019-1266" } }
                ([HealthChecker.ExchangeCULevel]::CU2) { $KBCveComb = @{KB4509409 = "CVE-2019-1084", "CVE-2019-1137"; KB4515832 = "CVE-2019-1233", "CVE-2019-1266"; KB4523171 = "CVE-2019-1373" } }
                ([HealthChecker.ExchangeCULevel]::CU3) { $KBCveComb = @{KB4523171 = "CVE-2019-1373"; KB4536987 = "CVE-2020-0688", "CVE-2020-0692"; KB4540123 = "CVE-2020-0903" } }
                ([HealthChecker.ExchangeCULevel]::CU4) { $KBCveComb = @{KB4536987 = "CVE-2020-0688", "CVE-2020-0692"; KB4540123 = "CVE-2020-0903" } }
                ([HealthChecker.ExchangeCULevel]::CU5) { $KBCveComb = @{KB4577352 = "CVE-2020-16875" } }
                ([HealthChecker.ExchangeCULevel]::CU6) { $KBCveComb = @{KB4577352 = "CVE-2020-16875"; KB4581424 = "CVE-2020-16969"; KB4588741 = "CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085"; KB4593465 = "CVE-2020-17117", "CVE-2020-17132", "CVE-2020-17141", "CVE-2020-17142", "CVE-2020-17143" } }
            }
            $Script:AllVulnerabilitiesPassed = $false
        } else {
            Write-Verbose "No need to call 'Show-March2021SUOutdatedCUWarning'"
        }
        if ($null -ne $KBCveComb) {
            Show-March2021SUOutdatedCUWarning -KBCVEHT $KBCveComb
        }
    }

    #Description: Check for CVE-2021-34470 rights elevation vulnerability
    #Affected Exchange versions: 2013, 2016, 2019
    #Fix:
    ##Exchange 2013 CU23 + July 2021 SU + /PrepareSchema,
    ##Exchange 2016 CU20 + July 2021 SU + /PrepareSchema or CU21,
    ##Exchange 2019 CU9 + July 2021 SU + /PrepareSchema or CU10
    #Workaround: N/A

    if (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013) -or
        (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) -and
            ($exchangeCU -lt [HealthChecker.ExchangeCULevel]::CU21)) -or
        (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) -and
            ($exchangeCU -lt [HealthChecker.ExchangeCULevel]::CU10))) {
        Write-Verbose "Testing CVE: CVE-2021-34470"

        $displayWriteTypeColor = $null
        if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013) {
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "1497.23" -CVENames "CVE-2021-34470"
        }

        if ($null -eq $exchangeInformation.msExchStorageGroup) {
            Write-Verbose "Unable to query classSchema: 'ms-Exch-Storage-Group' information"
            $details = "CVE-2021-34470`r`n`t`tWarning: Unable to query classSchema: 'ms-Exch-Storage-Group' to perform testing."
            $displayWriteTypeColor = "Yellow"
        } elseif ($exchangeInformation.msExchStorageGroup.Properties.posssuperiors -eq "computer") {
            Write-Verbose "Attribute: 'possSuperiors' with value: 'computer' detected in classSchema: 'ms-Exch-Storage-Group'"
            $details = "CVE-2021-34470`r`n`t`tPrepareSchema required: https://aka.ms/HC-July21SU"
            $displayWriteTypeColor = "Red"
        } else {
            Write-Verbose "System NOT vulnerable to CVE-2021-34470"
        }

        if ($null -ne $displayWriteTypeColor) {
            $Script:Vulnerabilities += $details
            $analyzedResults = Add-AnalyzedResultInformation -Name "Security Vulnerability" -Details $details `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayWriteType $displayWriteTypeColor `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
            $Script:AllVulnerabilitiesPassed = $false
        }
    } else {
        Write-Verbose "System NOT vulnerable to CVE-2021-34470"
    }

    #Description: Check for CVE-2021-1730 vulnerability
    #Fix available for: Exchange 2016 CU18+, Exchange 2019 CU7+
    #Fix: Configure Download Domains feature
    #Workaround: N/A

    if (((($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) -and
                ($exchangeCU -ge [HealthChecker.ExchangeCULevel]::CU18)) -or
            (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) -and
                ($exchangeCU -ge [HealthChecker.ExchangeCULevel]::CU7))) -and
        $exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) {

        $downloadDomainsConfig = Test-DownloadDomainsConfiguration -OwaVDirObject $exchangeInformation.GetOwaVirtualDirectory -DownloadDomainsEnabled $exchangeInformation.EnableDownloadDomains

        $downloadDomainsOrgDisplayValue = "True"
        $downloadDomainsOrgWriteType = "Green"

        if ($downloadDomainsConfig -band 1) {
            $downloadDomainsOrgDisplayValue = "False"
            $downloadDomainsOrgAdditionalDisplayValue = "Download Domains are not configured. You should configure them to be protected against CVE-2021-1730."
            $downloadDomainsOrgWriteType = "Red"
        }

        $downloadDomainsExtDisplayValue = "True"
        $downloadDomainsExtWriteType = "Green"

        if ($downloadDomainsConfig -band 4) {
            $downloadDomainsExtDisplayValue = "False"
            $downloadDomainsExtAdditionalDisplayValue = "Value is set to the same internal or external url as OWA. Please use a different url to reach a protected state against CVE-2021-1730."
            $downloadDomainsExtWriteType = "Red"
        } elseif ($downloadDomainsConfig -band 8) {
            $downloadDomainsExtDisplayValue = "False"
            $downloadDomainsExtAdditionalDisplayValue = "Value not set. Please configure to reach a protected state against CVE-2021-1730."
            $downloadDomainsExtWriteType = "Red"
        }

        $downloadDomainsIntDisplayValue = "True"
        $downloadDomainsIntWriteType = "Green"

        if ($downloadDomainsConfig -band 16) {
            $downloadDomainsIntDisplayValue = "False"
            $downloadDomainsIntAdditionalDisplayValue = "Value is set to the same internal or external url as OWA. Please use a different url to reach a protected state against CVE-2021-1730."
            $downloadDomainsIntWriteType = "Red"
        } elseif ($downloadDomainsConfig -band 32) {
            $downloadDomainsIntDisplayValue = "False"
            $downloadDomainsIntAdditionalDisplayValue = "Value not set. Please configure to reach a protected state against CVE-2021-1730."
            $downloadDomainsIntWriteType = "Red"
        }

        $analyzedResults = Add-AnalyzedResultInformation -Name "Download Domains Enabled" -Details $downloadDomainsOrgDisplayValue `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType $downloadDomainsOrgWriteType `
            -AddHtmlDetailRow $true `
            -AnalyzedInformation $analyzedResults

        if (![string]::IsNullOrEmpty($downloadDomainsOrgAdditionalDisplayValue)) {
            $analyzedResults = Add-AnalyzedResultInformation -Details $downloadDomainsOrgAdditionalDisplayValue `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayWriteType "Red" `
                -DisplayCustomTabNumber 2 `
                -AddHtmlDetailRow $true `
                -AnalyzedInformation $analyzedResults
        } else {

            $analyzedResults = Add-AnalyzedResultInformation -Name "ExternalDownloadHostName configured correctly" -Details $downloadDomainsExtDisplayValue `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayWriteType $downloadDomainsExtWriteType `
                -DisplayCustomTabNumber 2 `
                -AddHtmlDetailRow $true `
                -AnalyzedInformation $analyzedResults

            if (![string]::IsNullOrEmpty($downloadDomainsExtAdditionalDisplayValue)) {
                $analyzedResults = Add-AnalyzedResultInformation -Details $downloadDomainsExtAdditionalDisplayValue `
                    -DisplayGroupingKey $keySecuritySettings `
                    -DisplayWriteType "Red" `
                    -DisplayCustomTabNumber 2 `
                    -AddHtmlDetailRow $true `
                    -AnalyzedInformation $analyzedResults
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "InternalDownloadHostName configured correctly" -Details $downloadDomainsIntDisplayValue `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayWriteType $downloadDomainsIntWriteType `
                -DisplayCustomTabNumber 2 `
                -AddHtmlDetailRow $true `
                -AnalyzedInformation $analyzedResults

            if (![string]::IsNullOrEmpty($downloadDomainsIntAdditionalDisplayValue)) {
                $analyzedResults = Add-AnalyzedResultInformation -Details $downloadDomainsIntAdditionalDisplayValue `
                    -DisplayGroupingKey $keySecuritySettings `
                    -DisplayWriteType "Red" `
                    -DisplayCustomTabNumber 2 `
                    -AddHtmlDetailRow $true `
                    -AnalyzedInformation $analyzedResults
            }
        }

        if ($downloadDomainsOrgWriteType -eq "Red" -or
            $downloadDomainsExtWriteType -eq "Red" -or
            $downloadDomainsIntWriteType -eq "Red") {

            $analyzedResults = Add-AnalyzedResultInformation -Details "Configuration instructions: https://aka.ms/HC-DownloadDomains" `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayWriteType "Red" `
                -DisplayCustomTabNumber 2 `
                -AddHtmlDetailRow $true `
                -AnalyzedInformation $analyzedResults

            $Script:AllVulnerabilitiesPassed = $false
        }
    } else {
        Write-Verbose "Download Domains feature not available because we are on: $($exchangeInformation.BuildInformation.MajorVersion) $exchangeCU or on Edge Transport Server"
    }

    #Description: Check for CVE-2020-0796 SMBv3 vulnerability
    #Affected OS versions: Windows 10 build 1903 and 1909
    #Fix: KB4551762
    #Workaround: Disable SMBv3 compression

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {
        Write-Verbose "Testing CVE: CVE-2020-0796"
        $buildNumber = $osInformation.BuildInformation.VersionBuild.Split(".")[2]

        if (($buildNumber -eq 18362 -or
                $buildNumber -eq 18363) -and
            ($osInformation.RegistryValues.CurrentVersionUbr -lt 720)) {
            Write-Verbose "Build vulnerable to CVE-2020-0796. Checking if workaround is in place."
            $writeType = "Red"
            $writeValue = "System Vulnerable"

            if ($osInformation.RegistryValues.LanManServerDisabledCompression -eq 1) {
                Write-Verbose "Workaround to disable affected SMBv3 compression is in place."
                $writeType = "Yellow"
                $writeValue = "Workaround is in place"
            } else {
                Write-Verbose "Workaround to disable affected SMBv3 compression is NOT in place."
                $Script:AllVulnerabilitiesPassed = $false
            }

            $details = "{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0796 for more information." -f $writeValue
            $Script:Vulnerabilities += $details
            $analyzedResults = Add-AnalyzedResultInformation -Name "CVE-2020-0796" -Details $details `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayWriteType $writeType `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        } else {
            Write-Verbose "System NOT vulnerable to CVE-2020-0796. Information URL: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0796"
        }
    } else {
        Write-Verbose "Operating System NOT vulnerable to CVE-2020-0796."
    }

    #Description: Check for CVE-2020-1147
    #Affected OS versions: Every OS supporting .NET Core 2.1 and 3.1 and .NET Framework 2.0 SP2 or above
    #Fix: https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1147
    #Workaround: N/A
    $dllFileBuildPartToCheckAgainst = 3630

    if ($osInformation.NETFramework.NetMajorVersion -eq [HealthChecker.NetMajorVersion]::Net4d8) {
        $dllFileBuildPartToCheckAgainst = 4190
    }

    $systemDataDll = $osInformation.NETFramework.FileInformation["System.Data.dll"]
    $systemConfigurationDll = $osInformation.NETFramework.FileInformation["System.Configuration.dll"]
    Write-Verbose "System.Data.dll FileBuildPart: $($systemDataDll.VersionInfo.FileBuildPart) | LastWriteTimeUtc: $($systemDataDll.LastWriteTimeUtc)"
    Write-Verbose "System.Configuration.dll FileBuildPart: $($systemConfigurationDll.VersionInfo.FileBuildPart) | LastWriteTimeUtc: $($systemConfigurationDll.LastWriteTimeUtc)"

    if ($systemDataDll.VersionInfo.FileBuildPart -ge $dllFileBuildPartToCheckAgainst -and
        $systemConfigurationDll.VersionInfo.FileBuildPart -ge $dllFileBuildPartToCheckAgainst -and
        $systemDataDll.LastWriteTimeUtc -ge ([System.Convert]::ToDateTime("06/05/2020", [System.Globalization.DateTimeFormatInfo]::InvariantInfo)) -and
        $systemConfigurationDll.LastWriteTimeUtc -ge ([System.Convert]::ToDateTime("06/05/2020", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))) {
        Write-Verbose ("System NOT vulnerable to {0}. Information URL: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{0}" -f "CVE-2020-1147")
    } else {
        $Script:AllVulnerabilitiesPassed = $false
        $details = "{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{0} for more information." -f "CVE-2020-1147"
        $Script:Vulnerabilities += $details
        $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Name "Security Vulnerability" -Details $details `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType "Red" `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $Script:AnalyzedInformation
    }

    if ($Script:AllVulnerabilitiesPassed) {
        $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Details "All known security issues in this version of the script passed." `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType "Green" `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $Script:AnalyzedInformation

        $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Name "Security Vulnerabilities" -Details "None" `
            -AddDisplayResultsLineInfo $false `
            -AddHtmlOverviewValues $true `
            -AnalyzedInformation $Script:AnalyzedInformation
    } else {

        $details = $Script:Vulnerabilities |
            ForEach-Object {
                return $_ + "<br>"
            }

        $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Name "Security Vulnerabilities" -Details $details `
            -AddDisplayResultsLineInfo $false `
            -DisplayWriteType "Red" `
            -AnalyzedInformation $Script:AnalyzedInformation

        $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Name "Vulnerability Detected" -Details $true `
            -AddDisplayResultsLineInfo $false `
            -DisplayWriteType "Red" `
            -AddHtmlOverviewValues $true `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $Script:AnalyzedInformation
    }

    Write-Debug("End of Analyzer Engine")
    return $Script:AnalyzedInformation
}


