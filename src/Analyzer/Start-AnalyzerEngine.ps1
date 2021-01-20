Function Start-AnalyzerEngine {
    param(
        [HealthChecker.HealthCheckerExchangeServer]$HealthServerObject
    )
    Write-VerboseOutput("Calling: Start-AnalyzerEngine")

    $analyzedResults = New-Object HealthChecker.AnalyzedInformation
    $analyzedResults.HealthCheckerExchangeServer = $HealthServerObject

    #Display Grouping Keys
    $order = 0
    $keyBeginningInfo = New-DisplayResultsGroupingKey -Name "BeginningInfo" -DisplayGroupName $false -DisplayOrder ($order++) -DefaultTabNumber 0
    $keyExchangeInformation = New-DisplayResultsGroupingKey -Name "Exchange Information"  -DisplayOrder ($order++)
    $keyOSInformation = New-DisplayResultsGroupingKey -Name "Operating System Information" -DisplayOrder ($order++)
    $keyHardwareInformation = New-DisplayResultsGroupingKey -Name "Processor/Hardware Information" -DisplayOrder ($order++)
    $keyNICSettings = New-DisplayResultsGroupingKey -Name "NIC Settings Per Active Adapter" -DisplayOrder ($order++) -DefaultTabNumber 2
    $keyFrequentConfigIssues = New-DisplayResultsGroupingKey -Name "Frequent Configuration Issues" -DisplayOrder ($order++)
    $keySecuritySettings = New-DisplayResultsGroupingKey -Name "Security Settings" -DisplayOrder ($order++)
    $keyWebApps = New-DisplayResultsGroupingKey -Name "Exchange Web App Pools" -DisplayOrder ($order++)

    #Set short cut variables
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $osInformation = $HealthServerObject.OSInformation
    $hardwareInformation = $HealthServerObject.HardwareInformation

    if (!$Script:DisplayedScriptVersionAlready) {
        $analyzedResults = Add-AnalyzedResultInformation -Name "Exchange Health Checker Version" -Details $Script:scriptVersion `
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
    Write-VerboseOutput("Working on Exchange Information")

    $analyzedResults = Add-AnalyzedResultInformation -Name "Name" -Details ($HealthServerObject.ServerName) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true `
        -HtmlName "Server Name" `
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
        $daysOld = ($date - ([System.Convert]::ToDateTime([DateTime]$exchangeInformation.BuildInformation.ReleaseDate))).Days

        $analyzedResults = Add-AnalyzedResultInformation -Name "Error" -Details ("Out of date Cumulative Update. Please upgrade to one of the two most recently released Cumulative Updates. Currently running on a build that is {0} days old." -f $daysOld) `
            -DisplayGroupingKey $keyExchangeInformation `
            -DisplayWriteType "Red" `
            -DisplayCustomTabNumber 2 `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    if ($null -ne $exchangeInformation.BuildInformation.LocalBuildNumber) {
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
        $analyzedResults = Add-AnalyzedResultInformation -Name "DAG Name" -Details ($exchangeInformation.GetMailboxServer.DatabaseAvailabilityGroup.Name) `
            -DisplayGroupingKey $keyExchangeInformation `
            -AnalyzedInformation $analyzedResults
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "AD Site" -Details ($exchangeInformation.GetExchangeServer.Site.Name) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "MAPI/HTTP Enabled" -Details ($exchangeInformation.MapiHttpEnabled) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AnalyzedInformation $analyzedResults

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013 -and
        $exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) {

        if ($null -ne $exchangeInformation.ApplicationPools -and
            $exchangeInformation.ApplicationPools.Count -gt 0) {
            $content = [xml]$exchangeInformation.ApplicationPools["MSExchangeMapiFrontEndAppPool"].Content
            [bool]$enabled = $content.Configuration.Runtime.gcServer.Enabled -eq "true"
            [bool]$unknown = $content.Configuration.Runtime.gcServer.Enabled -ne "true" -and $content.Configuration.Runtime.gcServer.Enabled -ne "false"
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

    ##############################
    # Exchange Server Maintenance
    ##############################
    Write-VerboseOutput("Working on Exchange Server Maintenance")
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
                    -DisplayWriteType "Yellow" `
                    -AnalyzedInformation $analyzedResults
            }
        }

        if ($serverMaintenance.GetMailboxServer.DatabaseCopyActivationDisabledAndMoveNow -or
            $serverMaintenance.GetMailboxServer.DatabaseCopyAutoActivationPolicy -eq "Blocked") {
            $displayValue = "`r`n`t`tDatabaseCopyActivationDisabledAndMoveNow: {0} --- should be 'false'`r`n`t`tDatabaseCopyAutoActivationPolicy: {1} --- should be 'unrestricted'" -f `
                $serverMaintenance.GetMailboxServer.DatabaseCopyActivationDisabledAndMoveNow,
            $serverMaintenance.GetMailboxServer.DatabaseCopyAutoActivationPolicy

            $analyzedResults = Add-AnalyzedResultInformation -Name "Database Copy Maintenance" -Details $displayValue `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AnalyzedInformation $analyzedResults
        }

        if ($null -ne $serverMaintenance.GetClusterNode -and
            $serverMaintenance.GetClusterNode.State -ne "Up") {
            $analyzedResults = Add-AnalyzedResultInformation -Name "Cluster Node" -Details ("'{0}' --- should be 'Up'" -f $serverMaintenance.GetClusterNode.State) `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AnalyzedInformation $analyzedResults
        }
    }

    #########################
    # Operating System
    #########################
    Write-VerboseOutput("Working on Operating System")

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
    Write-VerboseOutput("Total Memory: {0}" -f ($totalPhysicalMemory = $hardwareInformation.TotalMemory))
    Write-VerboseOutput("Page File: {0}" -f ($maxPageSize = $osInformation.PageFile.MaxPageSize))
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
        $testingValue.RecommendedPageFile = ($recommendedPageFileSize = [Math]::Truncate(($totalPhysicalMemory / 1MB) / 4))
        Write-VerboseOutput("Recommended Page File Size: {0}" -f $recommendedPageFileSize)
        if ($recommendedPageFileSize -ne $maxPageSize) {
            $displayValue = "{0}MB `r`n`t`tWarning: Page File is not set to 25% of the Total System Memory which is {1}MB. Recommended is {2}MB" -f $maxPageSize, ([Math]::Truncate($totalPhysicalMemory / 1MB)), $recommendedPageFileSize
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
            $displayValue = "{0}MB `r`n`t`tWarning: Pagefile should be capped at 32778MB for 32GB plus 10MB - Article: https://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help#pagefile" -f $maxPageSize
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
        Write-VerboseOutput("VCRedist2012 Testing value: {0}" -f [HealthChecker.VCRedistVersion]::VCRedist2012.value__)
        Write-VerboseOutput("VCRedist2013 Testing value: {0}" -f [HealthChecker.VCRedistVersion]::VCRedist2013.value__)
        $vc2013Required = $exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge
        $displayValue2012 = "Redistributable is outdated"
        $displayValue2013 = "Redistributable is outdated"

        foreach ($detectedVisualRedistVersion in $osInformation.VcRedistributable) {
            Write-VerboseOutput("Testing {0} version id '{1}'" -f $detectedVisualRedistVersion.DisplayName, $detectedVisualRedistVersion.VersionIdentifier)

            if ($detectedVisualRedistVersion.VersionIdentifier -eq [HealthChecker.VCRedistVersion]::VCRedist2012) {
                $displayValue2012 = "{0} Version is current" -f $detectedVisualRedistVersion.DisplayVersion
                $displayWriteType2012 = "Green"
            } elseif ($vc2013Required -and
                $detectedVisualRedistVersion.VersionIdentifier -eq [HealthChecker.VCRedistVersion]::VCRedist2013) {
                $displayWriteType2013 = "Green"
                $displayValue2013 = "{0} Version is current" -f $detectedVisualRedistVersion.DisplayVersion
            }
        }
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "Visual C++ 2012" -Details $displayValue2012 `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $displayWriteType2012 `
        -AnalyzedInformation $analyzedResults

    $analyzedResults = Add-AnalyzedResultInformation -Name "Visual C++ 2013" -Details $displayValue2013 `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $displayWriteType2013 `
        -AnalyzedInformation $analyzedResults

    if ($null -ne $osInformation.VcRedistributable -and
        ($displayWriteType2012 -eq "Yellow" -or
            $displayWriteType2013 -eq "Yellow")) {
        $analyzedResults = Add-AnalyzedResultInformation -Details "Note: For more information about the latest C++ Redistributeable please visit: https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads`r`n`t`tThis is not a requirement to upgrade, only a notification to bring to your attention." `
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
    Write-VerboseOutput("Working on Processor/Hardware Information")

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

        if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::VMWare) {
            $analyzedResults = Add-AnalyzedResultInformation -Details "Note: Please make sure you are following VMware's performance recommendation to get the most out of your guest machine. VMware blog 'Does corespersocket Affect Performance?' https://blogs.vmware.com/vsphere/2013/10/does-corespersocket-affect-performance.html" `
                -DisplayGroupingKey $keyHardwareInformation `
                -DisplayCustomTabNumber 2 `
                -AnalyzedInformation $analyzedResults
        }
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
            $additionalDisplayValue = "Error: For high-performance computing (HPC) application, like Exchange, Amazon recommends that you have Hyper-Threading Technology disabled in their service. More informaiton: https://aws.amazon.com/blogs/compute/disabling-intel-hyper-threading-technology-on-amazon-ec2-windows-instances/"
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
    Write-VerboseOutput("Working on NIC Settings Per Active Adapter Information")

    foreach ($adapter in $osInformation.NetworkInformation.NetworkAdapters) {

        if ($adapter.Description -eq "Remote NDIS Compatible Device") {
            Write-VerboseOutput("Remote NDSI Compatible Device found. Ignoring NIC.")
            continue
        }

        $value = "{0} [{1}]" -f $adapter.Description, $adapter.Name
        $analyzedResults = Add-AnalyzedResultInformation -Name "Interface Description" -Details $value `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayCustomTabNumber 1 `
            -AnalyzedInformation $analyzedResults

        if ($osInformation.BuildInformation.MajorVersion -ge [HealthChecker.OSServerVersion]::Windows2012R2) {
            Write-VerboseOutput("On Windows 2012 R2 or new. Can provide more details on the NICs")

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
            Write-VerboseOutput("On Windows 2012 or older and can't get advanced NIC settings")
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
                $displayValue = "False --- Warning: It's recommended to disable NIC power saving options`r`n`t`t`tMore Information: http://support.microsoft.com/kb/2740020"
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
            Write-VerboseOutput("PacketsReceivedDiscarded is null")
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
            $analyzedResults = Add-AnalyzedResultInformation -Details "Known Issue with vmxnet3: 'Large packet loss at the guest operating system level on the VMXNET3 vNIC in ESXi (2039495)' - https://kb.vmware.com/s/article/2039495" `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayWriteType "Yellow" `
                -DisplayCustomTabNumber 3 `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        }
    }

    if ($osInformation.NetworkInformation.NetworkAdapters.Count -gt 1) {
        $analyzedResults = Add-AnalyzedResultInformation -Details "Multiple active network adapters detected. Exchange 2013 or greater may not need separate adapters for MAPI and replication traffic.  For details please refer to https://docs.microsoft.com/en-us/exchange/planning-for-high-availability-and-site-resilience-exchange-2013-help#NR" `
            -DisplayGroupingKey $keyNICSettings `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults
    }

    if ($osInformation.NetworkInformation.IPv6DisabledOnNICs) {
        $displayWriteType = "Grey"
        $displayValue = "True"
        $testingValue = $true

        if ($osInformation.NetworkInformation.IPv6DisabledComponents -ne 255) {
            $displayWriteType = "Red"
            $testingValue = $false
            $displayValue = "False `r`n`t`tError: IPv6 is disabled on some NIC level settings but not fully disabled. DisabledComponents registry key currently set to '{0}'. For details please refer to the following articles: `r`n`t`thttps://docs.microsoft.com/en-us/archive/blogs/rmilne/disabling-ipv6-and-exchange-going-all-the-way `r`n`t`thttps://support.microsoft.com/en-us/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users" -f $osInformation.NetworkInformation.DisabledComponents
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
    Write-VerboseOutput("Working on TCP/IP Settings")

    $tcpKeepAlive = $osInformation.NetworkInformation.TCPKeepAlive

    if ($tcpKeepAlive -eq 0) {
        $displayValue = "Not Set `r`n`t`tError: Without this value the KeepAliveTime defaults to two hours, which can cause connectivity and performance issues between network devices such as firewalls and load balancers depending on their configuration. `r`n`t`tMore details: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Checklist-for-troubleshooting-Outlook-connectivity-in-Exchange/ba-p/604792"
        $displayWriteType = "Red"
    } elseif ($tcpKeepAlive -lt 900000 -or
        $tcpKeepAlive -gt 1800000) {
        $displayValue = "{0} `r`n`t`tWarning: Not configured optimally, recommended value between 15 to 30 minutes (900000 and 1800000 decimal). `r`n`t`tMore details: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Checklist-for-troubleshooting-Outlook-connectivity-in-Exchange/ba-p/604792" -f $tcpKeepAlive
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

    $analyzedResults = Add-AnalyzedResultInformation -Name "RPC Min Connection Timeout" -Details ("{0} `r`n`t`tMore Information: https://blogs.technet.microsoft.com/messaging_with_communications/2012/06/06/outlook-anywhere-network-timeout-issue/" -f $osInformation.NetworkInformation.RpcMinConnectionTimeout) `
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
    Write-VerboseOutput("Working on TLS Settings")

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
            $analyzedResults = Add-AnalyzedResultInformation -Details ("Error: SystemDefaultTlsVersions is not set to the recommended value. Please visit on how to properly enable TLS 1.2 https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-2-Enabling-TLS-1-2-and/ba-p/607761") `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 3 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults
        }
    }

    if ($detectedTlsMismatch) {
        $displayValues = @("Exchange Server TLS guidance Part 1: Getting Ready for TLS 1.2: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-part-1-Getting-Ready-for-TLS-1-2/ba-p/607649",
            "Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-2-Enabling-TLS-1-2-and/ba-p/607761",
            "Exchange Server TLS guidance Part 3: Turning Off TLS 1.0/1.1: https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-3-Turning-Off-TLS-1-0-1-1/ba-p/607898")

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

        if ($certificate.PublicKeySize -lt 2048) {
            $additionalDisplayValue = "It's recommended to use a key size of at least 2048 bit."

            $analyzedResults = Add-AnalyzedResultInformation -Name "Key size" -Details $certificate.PublicKeySize `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red" `
                -AnalyzedInformation $analyzedResults

            $analyzedResults = Add-AnalyzedResultInformation -Details $additionalDisplayValue `
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

        $analyzedResults = Add-AnalyzedResultInformation -Name "Bound to services" -Details $certificate.Services `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

        $analyzedResults = Add-AnalyzedResultInformation -Name "Current Auth Certificate" -Details $certificate.IsCurrentAuthConfigCertificate `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -AnalyzedInformation $analyzedResults

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
    }

    if (($null -ne $exchangeInformation.ExchangeCertificates) -and
        ($exchangeInformation.ExchangeCertificates.IsCurrentAuthConfigCertificate.Contains($true))) {
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

        $analyzedResults = Add-AnalyzedResultInformation -Details "No valid Auth Certificate found. This may cause several problems --- Error" `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType "Red" `
            -AnalyzedInformation $analyzedResults
    }

    $additionalDisplayValue = [string]::Empty
    $smb1Status = $osInformation.Smb1ServerSettings.Smb1Status

    if ($osInformation.BuildInformation.MajorVersion -gt [HealthChecker.OSServerVersion]::Windows2012) {
        $displayValue = "False"
        $writeType = "Green"

        if ($smb1Status -band 1) {
            $displayValue = "Failed to get install status"
            $writeType = "Yellow"
        } elseif ($smb1Status -band 2) {
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

    if ($smb1Status -band 8) {
        $displayValue = "Failed to get block status"
        $writeType = "Yellow"
    } elseif ($smb1Status -band 16) {
        $displayValue = "False"
        $writeType = "Red"
        $additionalDisplayValue += " SMB1 should be blocked"
    }

    $analyzedResults = Add-AnalyzedResultInformation -Name "SMB1 Blocked" -Details $displayValue `
        -DisplayGroupingKey $keySecuritySettings `
        -DisplayWriteType $writeType `
        -AnalyzedInformation $analyzedResults

    if ($additionalDisplayValue -ne [string]::Empty) {
        $additionalDisplayValue += "`r`n`t`tMore Information: https://techcommunity.microsoft.com/t5/exchange-team-blog/exchange-server-and-smbv1/ba-p/1165615"

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
        Write-VerboseOutput("Working on Exchange Web App GC Mode")

        $analyzedResults = Add-AnalyzedResultInformation -Name "Web App Pool" -Details "GC Server Mode Enabled | Status" `
            -DisplayGroupingKey $keyWebApps `
            -AddHtmlDetailRow $false `
            -AnalyzedInformation $analyzedResults

        foreach ($webAppKey in $exchangeInformation.ApplicationPools.Keys) {
            $xmlData = [xml]$exchangeInformation.ApplicationPools[$webAppKey].Content
            $testingValue = New-Object PSCustomObject
            $testingValue | Add-Member -MemberType NoteProperty -Name "GCMode" -Value ($enabled = $xmlData.Configuration.Runtime.gcServer.Enabled -eq 'true')
            $testingValue | Add-Member -MemberType NoteProperty -Name "Status" -Value ($status = $exchangeInformation.ApplicationPools[$webAppKey].Status)

            $analyzedResults = Add-AnalyzedResultInformation -Name $webAppKey -Details ("{0} | {1}" -f $enabled, $status) `
                -DisplayGroupingKey $keyWebApps `
                -DisplayTestingValue $testingValue `
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
                    $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Name "Security Vulnerability" -Details ("{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{0} for more information." -f $cveName) `
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

    $Script:AllVulnerabilitiesPassed = $true
    $Script:AnalyzedInformation = $analyzedResults
    [string]$buildRevision = ("{0}.{1}" -f $exchangeInformation.BuildInformation.ExchangeSetup.FileBuildPart, $exchangeInformation.BuildInformation.ExchangeSetup.FilePrivatePart)

    Write-VerboseOutput("Exchange Build Revision: {0}" -f $buildRevision)
    Write-VerboseOutput("Exchange CU: {0}" -f ($exchangeCU = $exchangeInformation.BuildInformation.CU))

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
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2044.7", "2106.3" -CVENames "CVE-2020-16969"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2044.8", "2106.4" -CVENames "CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "2044.12", "2106.6" -CVENames "CVE-2020-17117", "CVE-2020-17132", "CVE-2020-17141", "CVE-2020-17142", "CVE-2020-17143"
        }

        if ($exchangeCU -ge [HealthChecker.ExchangeCULevel]::CU19) {
            Write-VerboseOutput("There are no known vulnerabilities in this Exchange Server Build.")
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
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "659.7", "721.3" -CVENames "CVE-2020-16969"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "659.8", "721.4" -CVENames "CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085"
            Test-VulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision -SecurityFixedBuilds "659.11", "721.6" -CVENames "CVE-2020-17117", "CVE-2020-17132", "CVE-2020-17141", "CVE-2020-17142", "CVE-2020-17143"
        }

        if ($exchangeCU -ge [HealthChecker.ExchangeCULevel]::CU8) {
            Write-VerboseOutput("There are no known vulnerabilities in this Exchange Server Build.")
        }
    } else {
        Write-VerboseOutput("Unknown Version of Exchange")
        $Script:AllVulnerabilitiesPassed = $false
    }

    #Description: Check for CVE-2020-0796 SMBv3 vulnerability
    #Affected OS versions: Windows 10 build 1903 and 1909
    #Fix: KB4551762
    #Workaround: Disable SMBv3 compression

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {
        Write-VerboseOutput("Testing CVE: CVE-2020-0796")
        $buildNumber = $osInformation.BuildInformation.VersionBuild.Split(".")[2]

        if (($buildNumber -eq 18362 -or
                $buildNumber -eq 18363) -and
            ($osInformation.RegistryValues.CurrentVersionUbr -lt 720)) {
            Write-VerboseOutput("Build vulnerable to CVE-2020-0796. Checking if workaround is in place.")
            $writeType = "Red"
            $writeValue = "System Vulnerable"

            if ($osInformation.RegistryValues.LanManServerDisabledCompression -eq 1) {
                Write-VerboseOutput("Workaround to disable affected SMBv3 compression is in place.")
                $writeType = "Yellow"
                $writeValue = "Workaround is in place"
            } else {
                Write-VerboseOutput("Workaround to disable affected SMBv3 compression is NOT in place.")
                $Script:AllVulnerabilitiesPassed = $false
            }

            $analyzedResults = Add-AnalyzedResultInformation -Name "CVE-2020-0796" -Details ("{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0796 for more information." -f $writeValue) `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayWriteType $writeType `
                -AddHtmlDetailRow $false `
                -AnalyzedInformation $analyzedResults
        } else {
            Write-VerboseOutput("System NOT vulnerable to CVE-2020-0796. Information URL: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0796")
        }
    } else {
        Write-VerboseOutput("Operating System NOT vulnerable to CVE-2020-0796.")
    }

    #Description: Check for CVE-2020-1147
    #Affected OS versions: Every OS supporting .NET Core 2.1 and 3.1 and .NET Framework 2.0 SP2 or above
    #Fix: https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1147
    #Workaround: N/A
    $dllFileBuildPartToCheckAgainst = 3630

    if ($osInformation.NETFramework.NetMajorVersion -eq [HealthChecker.NetMajorVersion]::Net4d8) {
        $dllFileBuildPartToCheckAgainst = 4190
    }

    Write-VerboseOutput("System.Data.dll FileBuildPart: {0} | LastWriteTimeUtc: {1}" -f ($systemDataDll = $osInformation.NETFramework.FileInformation["System.Data.dll"]).VersionInfo.FileBuildPart, `
            $systemDataDll.LastWriteTimeUtc)
    Write-VerboseOutput("System.Configuration.dll FileBuildPart: {0} | LastWriteTimeUtc: {1}" -f ($systemConfigurationDll = $osInformation.NETFramework.FileInformation["System.Configuration.dll"]).VersionInfo.FileBuildPart, `
            $systemConfigurationDll.LastWriteTimeUtc)

    if ($systemDataDll.VersionInfo.FileBuildPart -ge $dllFileBuildPartToCheckAgainst -and
        $systemConfigurationDll.VersionInfo.FileBuildPart -ge $dllFileBuildPartToCheckAgainst -and
        $systemDataDll.LastWriteTimeUtc -ge ([System.Convert]::ToDateTime("06/05/2020", [System.Globalization.DateTimeFormatInfo]::InvariantInfo)) -and
        $systemConfigurationDll.LastWriteTimeUtc -ge ([System.Convert]::ToDateTime("06/05/2020", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))) {
        Write-VerboseOutput("System NOT vulnerable to {0}. Information URL: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{0}" -f "CVE-2020-1147")
    } else {
        $Script:AllVulnerabilitiesPassed = $false
        $Script:AnalyzedInformation = Add-AnalyzedResultInformation -Name "Security Vulnerability" -Details ("{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{0} for more information." -f "CVE-2020-1147") `
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
    }

    Write-Debug("End of Analyzer Engine")
    return $Script:AnalyzedInformation
}