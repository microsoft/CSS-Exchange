# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
Function Invoke-AnalyzerOsInformation {
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
    $keyOSInformation = Get-DisplayResultsGroupingKey -Name "Operating System Information"  -DisplayOrder $Order
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $osInformation = $HealthServerObject.OSInformation
    $hardwareInformation = $HealthServerObject.HardwareInformation

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Version" -Details ($osInformation.BuildInformation.FriendlyName) `
        -DisplayGroupingKey $keyOSInformation `
        -AddHtmlOverviewValues $true `
        -HtmlName "OS Version"

    $upTime = "{0} day(s) {1} hour(s) {2} minute(s) {3} second(s)" -f $osInformation.ServerBootUp.Days,
    $osInformation.ServerBootUp.Hours,
    $osInformation.ServerBootUp.Minutes,
    $osInformation.ServerBootUp.Seconds

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "System Up Time" -Details $upTime `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayTestingValue ($osInformation.ServerBootUp) `
        -AddHtmlDetailRow $false

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Time Zone" -Details ($osInformation.TimeZone.CurrentTimeZone) `
        -DisplayGroupingKey $keyOSInformation `
        -AddHtmlOverviewValues $true

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

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Dynamic Daylight Time Enabled" -Details $writeValue `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $writeType

    if ($warning -ne [string]::Empty) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Details $warning `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow" `
            -DisplayCustomTabNumber 2 `
            -AddHtmlDetailRow $false
    }

    if ([string]::IsNullOrEmpty($osInformation.TimeZone.TimeZoneKeyName)) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Time Zone Key Name" -Details "Empty --- Warning Need to switch your current time zone to a different value, then switch it back to have this value populated again." `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow"
    }

    if ($exchangeInformation.NETFramework.OnRecommendedVersion) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name ".NET Framework" -Details ($osInformation.NETFramework.FriendlyName) `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Green" `
            -AddHtmlOverviewValues $true
    } else {
        $testObject = New-Object PSCustomObject
        $testObject | Add-Member -MemberType NoteProperty -Name "CurrentValue" -Value ($osInformation.NETFramework.FriendlyName)
        $testObject | Add-Member -MemberType NoteProperty -Name "MaxSupportedVersion" -Value ($exchangeInformation.NETFramework.MaxSupportedVersion)
        $displayFriendly = Get-NETFrameworkVersion -NetVersionKey $exchangeInformation.NETFramework.MaxSupportedVersion
        $displayValue = "{0} - Warning Recommended .NET Version is {1}" -f $osInformation.NETFramework.FriendlyName, $displayFriendly.FriendlyName
        $AnalyzeResults | Add-AnalyzedResultInformation -Name ".NET Framework" -Details $displayValue `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow" `
            -DisplayTestingValue $testObject `
            -HtmlDetailsCustomValue ($osInformation.NETFramework.FriendlyName) `
            -AddHtmlOverviewValues $true
    }

    $displayValue = [string]::Empty
    $displayWriteType = "Yellow"
    $totalPhysicalMemory = [Math]::Round($hardwareInformation.TotalMemory / 1MB)
    $instanceCount = 0
    Write-Verbose "Evaluating PageFile Information"
    Write-Verbose "Total Memory: $totalPhysicalMemory"

    foreach ($pageFile in $osInformation.PageFile) {

        $pageFileDisplayTemplate = "{0} Size: {1}MB"
        $pageFileAdditionalDisplayValue = $null

        Write-Verbose "Working on PageFile: $($pageFile.Name)"
        Write-Verbose "Max PageFile Size: $($pageFile.MaximumSize)"
        $pageFileObj = [PSCustomObject]@{
            Name                = $pageFile.Name
            TotalPhysicalMemory = $totalPhysicalMemory
            MaxPageSize         = $pageFile.MaximumSize
            MultiPageFile       = (($osInformation.PageFile).Count -gt 1)
            RecommendedPageFile = 0
        }

        if ($pageFileObj.MaxPageSize -eq 0) {
            Write-Verbose "Unconfigured PageFile detected"
            if ([System.String]::IsNullOrEmpty($pageFileObj.Name)) {
                Write-Verbose "System-wide automatically managed PageFile detected"
                $displayValue = ($pageFileDisplayTemplate -f "System is set to automatically manage the PageFile", $pageFileObj.MaxPageSize)
            } else {
                Write-Verbose "Specific system-managed PageFile detected"
                $displayValue = ($pageFileDisplayTemplate -f $pageFileObj.Name, $pageFileObj.MaxPageSize)
            }
            $displayWriteType = "Red"
        } else {
            Write-Verbose "Configured PageFile detected"
            $displayValue = ($pageFileDisplayTemplate -f $pageFileObj.Name, $pageFileObj.MaxPageSize)
        }

        if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {
            $recommendedPageFile = [Math]::Round($totalPhysicalMemory / 4)
            $pageFileObj.RecommendedPageFile = $recommendedPageFile
            Write-Verbose "System is running Exchange 2019. Recommended PageFile Size: $recommendedPageFile"

            $recommendedPageFileWording2019 = "On Exchange 2019, the recommended PageFile size is 25% ({0}MB) of the total system memory ({1}MB)."
            if ($pageFileObj.MaxPageSize -eq 0) {
                $pageFileAdditionalDisplayValue = ("Error: $recommendedPageFileWording2019" -f $recommendedPageFile, $totalPhysicalMemory)
            } elseif ($recommendedPageFile -ne $pageFileObj.MaxPageSize) {
                $pageFileAdditionalDisplayValue = ("Warning: $recommendedPageFileWording2019" -f $recommendedPageFile, $totalPhysicalMemory)
            } else {
                $displayWriteType = "Grey"
            }
        } elseif ($totalPhysicalMemory -ge 32768) {
            Write-Verbose "System is not running Exchange 2019 and has more than 32GB memory. Recommended PageFile Size: 32778MB"

            $recommendedPageFileWording32GBPlus = "PageFile should be capped at 32778MB for 32GB plus 10MB."
            if ($pageFileObj.MaxPageSize -eq 0) {
                $pageFileAdditionalDisplayValue = "Error: $recommendedPageFileWording32GBPlus"
            } elseif ($pageFileObj.MaxPageSize -eq 32778) {
                $displayWriteType = "Grey"
            } else {
                $pageFileAdditionalDisplayValue = "Warning: $recommendedPageFileWording32GBPlus"
            }
        } else {
            $recommendedPageFile = $totalPhysicalMemory + 10
            Write-Verbose "System is not running Exchange 2019 and has less than 32GB of memory. Recommended PageFile Size: $recommendedPageFile"

            $recommendedPageFileWordingBelow32GB = "PageFile is not set to total system memory plus 10MB which should be {0}MB."
            if ($pageFileObj.MaxPageSize -eq 0) {
                $pageFileAdditionalDisplayValue = ("Error: $recommendedPageFileWordingBelow32GB" -f $recommendedPageFile)
            } elseif ($recommendedPageFile -ne $pageFileObj.MaxPageSize) {
                $pageFileAdditionalDisplayValue = ("Warning: $recommendedPageFileWordingBelow32GB" -f $recommendedPageFile)
            } else {
                $displayWriteType = "Grey"
            }
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "PageFile" -Details $displayValue `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType $displayWriteType `
            -TestingName "PageFile Size $instanceCount" `
            -DisplayTestingValue $pageFileObj

        if ($null -ne $pageFileAdditionalDisplayValue) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details $pageFileAdditionalDisplayValue `
                -DisplayGroupingKey $keyOSInformation `
                -DisplayWriteType $displayWriteType `
                -TestingName "PageFile Additional Information" `
                -DisplayCustomTabNumber 2

            $AnalyzeResults | Add-AnalyzedResultInformation -Details "More information: https://aka.ms/HC-PageFile" `
                -DisplayGroupingKey $keyOSInformation `
                -DisplayWriteType $displayWriteType `
                -DisplayCustomTabNumber 2
        }

        $instanceCount++
    }

    if ($null -ne $osInformation.PageFile -and
        $osInformation.PageFile.Count -gt 1) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Details "`r`n`t`tError: Multiple PageFiles detected. This has been known to cause performance issues, please address this." `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Red" `
            -TestingName "Multiple PageFile Detected" `
            -DisplayTestingValue $true `
            -DisplayCustomTabNumber 2
    }

    if ($osInformation.PowerPlan.HighPerformanceSet) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Power Plan" -Details ($osInformation.PowerPlan.PowerPlanSetting) `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Green"
    } else {
        $displayValue = "{0} --- Error" -f $osInformation.PowerPlan.PowerPlanSetting
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Power Plan" -Details $displayValue `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Red"
    }

    $displayWriteType = "Grey"
    $displayValue = $osInformation.NetworkInformation.HttpProxy.ProxyAddress

    if ($osInformation.NetworkInformation.HttpProxy.ProxyAddress -ne "None") {
        $displayValue = "$($osInformation.NetworkInformation.HttpProxy.ProxyAddress) --- Warning this can cause client connectivity issues."
        $displayWriteType = "Yellow"
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Http Proxy Setting" `
        -Details $displayValue `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $osInformation.NetworkInformation.HttpProxy

    if ($displayWriteType -eq "Yellow") {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Http Proxy By Pass List" `
            -Details "$($osInformation.NetworkInformation.HttpProxy.ByPassList)" `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow"
    }

    if ($osInformation.NetworkInformation.HttpProxy.ProxyAddress -ne "None" -and
        $osInformation.NetworkInformation.HttpProxy.ProxyAddress -ne $exchangeInformation.GetExchangeServer.InternetWebProxy) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Details "Error: Exchange Internet Web Proxy doesn't match OS Web Proxy." `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Red" `
            -TestingName "Proxy Doesn't Match" `
            -DisplayCustomTabNumber 2
    }

    $displayWriteType2012 = $displayWriteType2013 = "Red"
    $displayValue2012 = $displayValue2013 = $defaultValue = "Error --- Unknown"

    if ($null -ne $osInformation.VcRedistributable) {

        if (Test-VisualCRedistributableUpToDate -Year 2012 -Installed $osInformation.VcRedistributable) {
            $displayWriteType2012 = "Green"
            $displayValue2012 = "$((Get-VisualCRedistributableInfo 2012).VersionNumber) Version is current"
        } elseif (Test-VisualCRedistributableInstalled -Year 2012 -Installed $osInformation.VcRedistributable) {
            $displayValue2012 = "Redistributable is outdated"
            $displayWriteType2012 = "Yellow"
        }

        if (Test-VisualCRedistributableUpToDate -Year 2013 -Installed $osInformation.VcRedistributable) {
            $displayWriteType2013 = "Green"
            $displayValue2013 = "$((Get-VisualCRedistributableInfo 2013).VersionNumber) Version is current"
        } elseif (Test-VisualCRedistributableInstalled -Year 2013 -Installed $osInformation.VcRedistributable) {
            $displayValue2013 = "Redistributable is outdated"
            $displayWriteType2013 = "Yellow"
        }
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Visual C++ 2012" -Details $displayValue2012 `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $displayWriteType2012

    if ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Visual C++ 2013" -Details $displayValue2013 `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType $displayWriteType2013
    }

    if (($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge -and
            ($displayWriteType2012 -eq "Yellow" -or
            $displayWriteType2013 -eq "Yellow")) -or
        $displayWriteType2012 -eq "Yellow") {

        $AnalyzeResults | Add-AnalyzedResultInformation -Details "Note: For more information about the latest C++ Redistributable please visit: https://aka.ms/HC-LatestVC`r`n`t`tThis is not a requirement to upgrade, only a notification to bring to your attention." `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType "Yellow"
    }

    if ($defaultValue -eq $displayValue2012 -or
        ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge -and
        $displayValue2013 -eq $defaultValue)) {

        $AnalyzeResults | Add-AnalyzedResultInformation -Details "ERROR: Unable to find one of the Visual C++ Redistributable Packages. This can cause a wide range of issues on the server.`r`n`t`tPlease install the missing package as soon as possible. Latest C++ Redistributable please visit: https://aka.ms/HC-LatestVC" `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType "Red"
    }

    $displayValue = "False"
    $writeType = "Grey"

    if ($osInformation.ServerPendingReboot.PendingReboot) {
        $displayValue = "True --- Warning a reboot is pending and can cause issues on the server."
        $writeType = "Yellow"
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Server Pending Reboot" -Details $displayValue `
        -DisplayGroupingKey $keyOSInformation `
        -DisplayWriteType $writeType `
        -DisplayTestingValue ($osInformation.ServerPendingReboot.PendingReboot)

    if ($osInformation.ServerPendingReboot.PendingReboot -and
        $osInformation.ServerPendingReboot.PendingRebootLocations.Count -gt 0) {

        foreach ($line in $osInformation.ServerPendingReboot.PendingRebootLocations) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details $line `
                -DisplayGroupingKey $keyOSInformation `
                -DisplayCustomTabNumber 2 `
                -TestingName $line `
                -DisplayWriteType "Yellow"
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Details "More Information: https://aka.ms/HC-RebootPending" `
            -DisplayGroupingKey $keyOSInformation `
            -DisplayWriteType "Yellow" `
            -TestingName "Reboot More Information" `
            -DisplayTestingValue $true `
            -DisplayCustomTabNumber 2
    }
}
