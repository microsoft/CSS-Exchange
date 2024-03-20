# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\..\..\..\Shared\CompareExchangeBuildLevel.ps1
. $PSScriptRoot\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\Get-NETFrameworkVersion.ps1
function Invoke-AnalyzerOsInformation {
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
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $osInformation = $HealthServerObject.OSInformation
    $hardwareInformation = $HealthServerObject.HardwareInformation

    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = (Get-DisplayResultsGroupingKey -Name "Operating System Information"  -DisplayOrder $Order)
    }

    $params = $baseParams + @{
        Name                  = "Version"
        Details               = $osInformation.BuildInformation.FriendlyName
        AddHtmlOverviewValues = $true
        HtmlName              = "OS Version"
    }
    Add-AnalyzedResultInformation @params

    $upTime = "{0} day(s) {1} hour(s) {2} minute(s) {3} second(s)" -f $osInformation.ServerBootUp.Days,
    $osInformation.ServerBootUp.Hours,
    $osInformation.ServerBootUp.Minutes,
    $osInformation.ServerBootUp.Seconds

    $params = $baseParams + @{
        Name                = "System Up Time"
        Details             = $upTime
        DisplayTestingValue = $osInformation.ServerBootUp
    }
    Add-AnalyzedResultInformation @params

    $params = $baseParams + @{
        Name                  = "Time Zone"
        Details               = $osInformation.TimeZone.CurrentTimeZone
        AddHtmlOverviewValues = $true
    }
    Add-AnalyzedResultInformation @params

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

    $params = $baseParams + @{
        Name             = "Dynamic Daylight Time Enabled"
        Details          = $writeValue
        DisplayWriteType = $writeType
    }
    Add-AnalyzedResultInformation @params

    if ($warning -ne [string]::Empty) {
        $params = $baseParams + @{
            Details                = $warning
            DisplayWriteType       = "Yellow"
            DisplayCustomTabNumber = 2
            AddHtmlDetailRow       = $false
        }
        Add-AnalyzedResultInformation @params
    }

    if ([string]::IsNullOrEmpty($osInformation.TimeZone.TimeZoneKeyName)) {
        $params = $baseParams + @{
            Name             = "Time Zone Key Name"
            Details          = "Empty --- Warning Need to switch your current time zone to a different value, then switch it back to have this value populated again."
            DisplayWriteType = "Yellow"
        }
        Add-AnalyzedResultInformation @params
    }

    # .NET Supported Levels
    $currentExchangeBuild = $exchangeInformation.BuildInformation.VersionInformation
    $ex2019 = "Exchange2019"
    $ex2016 = "Exchange2016"
    $ex2013 = "Exchange2013"
    $osVersion = $osInformation.BuildInformation.MajorVersion
    $recommendedNetVersion = $null
    $netVersionDictionary = GetNetVersionDictionary

    Write-Verbose "Checking $($exchangeInformation.BuildInformation.MajorVersion) .NET Framework Support Versions"

    if ((Test-ExchangeBuildLessThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2013 -CU "CU4")) {
        $recommendedNetVersion = $netVersionDictionary["Net4d5"]
    } elseif ((Test-ExchangeBuildLessThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2013 -CU "CU13") -or
    (Test-ExchangeBuildLessThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2016 -CU "CU2")) {
        $recommendedNetVersion = $netVersionDictionary["Net4d5d2wFix"]
    } elseif ((Test-ExchangeBuildLessThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2013 -CU "CU15") -or
    (Test-ExchangeBuildEqualBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2016 -CU "CU2") -or
    ((Test-ExchangeBuildEqualBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2016 -CU "CU3") -and
        $osVersion -ne "Windows2016")) {
        $recommendedNetVersion = $netVersionDictionary["Net4d6d1wFix"]
    } elseif ((Test-ExchangeBuildLessThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2013 -CU "CU19") -or
    (Test-ExchangeBuildLessThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2016 -CU "CU8")) {
        $recommendedNetVersion = $netVersionDictionary["Net4d6d2"]
    } elseif ((Test-ExchangeBuildLessThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2013 -CU "CU21") -or
    (Test-ExchangeBuildLessThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2016 -CU "CU11")) {
        $recommendedNetVersion = $netVersionDictionary["Net4d7d1"]
    } elseif ((Test-ExchangeBuildLessThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2013 -CU "CU21") -or
    (Test-ExchangeBuildLessThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2016 -CU "CU13") -or
    (Test-ExchangeBuildLessThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2019 -CU "CU2")) {
        $recommendedNetVersion = $netVersionDictionary["Net4d7d2"]
    } elseif ((Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $currentExchangeBuild -Version $ex2019 -CU "CU14") -and
        ($osVersion -ne "Windows2019")) {
        $recommendedNetVersion = $netVersionDictionary["Net4d8d1"]
    } else {
        $recommendedNetVersion = $netVersionDictionary["Net4d8"]
    }

    Write-Verbose "Recommended NET Version: $recommendedNetVersion"

    if ($osInformation.NETFramework.MajorVersion -eq $recommendedNetVersion) {
        $params = $baseParams + @{
            Name                  = ".NET Framework"
            Details               = $osInformation.NETFramework.FriendlyName
            DisplayWriteType      = "Green"
            AddHtmlOverviewValues = $true
        }
        Add-AnalyzedResultInformation @params
    } else {
        $displayFriendly = Get-NETFrameworkVersion -NetVersionKey $recommendedNetVersion
        $displayValue = "{0} - Warning Recommended .NET Version is {1}" -f $osInformation.NETFramework.FriendlyName, $displayFriendly.FriendlyName
        $testValue = [PSCustomObject]@{
            CurrentValue        = $osInformation.NETFramework.FriendlyName
            MaxSupportedVersion = $recommendedNetVersion
        }
        $params = $baseParams + @{
            Name                   = ".NET Framework"
            Details                = $displayValue
            DisplayWriteType       = "Yellow"
            DisplayTestingValue    = $testValue
            HtmlDetailsCustomValue = $osInformation.NETFramework.FriendlyName
            AddHtmlOverviewValues  = $true
        }
        Add-AnalyzedResultInformation @params

        if ($osInformation.NETFramework.MajorVersion -gt $recommendedNetVersion) {
            # Generic information stating we are looking into supporting this version of .NET
            # But don't use it till we update the supportability matrix
            $displayValue = "Microsoft is working on .NET $($osInformation.NETFramework.FriendlyName) validation with Exchange" +
            " and the recommendation is to not use .NET $($osInformation.NETFramework.FriendlyName) until it is officially added to the supportability matrix."

            $params = $baseParams + @{
                Details                = $displayValue
                DisplayWriteType       = "Yellow"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }
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

        if ($exchangeInformation.BuildInformation.VersionInformation.BuildVersion -ge "15.2.0.0") {
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

        $params = $baseParams + @{
            Name                = "PageFile"
            Details             = $displayValue
            DisplayWriteType    = $displayWriteType
            TestingName         = "PageFile Size $instanceCount"
            DisplayTestingValue = $pageFileObj
        }
        Add-AnalyzedResultInformation @params

        if ($null -ne $pageFileAdditionalDisplayValue) {
            $params = $baseParams + @{
                Details                = $pageFileAdditionalDisplayValue
                DisplayWriteType       = $displayWriteType
                TestingName            = "PageFile Additional Information"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Details                = "More information: https://aka.ms/HC-PageFile"
                DisplayWriteType       = $displayWriteType
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        $instanceCount++
    }

    if ($null -ne $osInformation.PageFile -and
        $osInformation.PageFile.Count -gt 1) {
        $params = $baseParams + @{
            Details                = "`r`n`t`tError: Multiple PageFiles detected. This has been known to cause performance issues, please address this."
            DisplayWriteType       = "Red"
            TestingName            = "Multiple PageFile Detected"
            DisplayTestingValue    = $true
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }

    if ($osInformation.PowerPlan.HighPerformanceSet) {
        $params = $baseParams + @{
            Name             = "Power Plan"
            Details          = $osInformation.PowerPlan.PowerPlanSetting
            DisplayWriteType = "Green"
        }
        Add-AnalyzedResultInformation @params
    } else {
        $params = $baseParams + @{
            Name             = "Power Plan"
            Details          = "$($osInformation.PowerPlan.PowerPlanSetting) --- Error"
            DisplayWriteType = "Red"
        }
        Add-AnalyzedResultInformation @params
    }

    $displayWriteType = "Grey"
    $displayValue = $osInformation.NetworkInformation.HttpProxy.ProxyAddress

    if (($osInformation.NetworkInformation.HttpProxy.ProxyAddress -ne "None") -and
        ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false)) {
        $displayValue = "$($osInformation.NetworkInformation.HttpProxy.ProxyAddress) --- Warning this can cause client connectivity issues."
        $displayWriteType = "Yellow"
    }

    $params = $baseParams + @{
        Name                = "Http Proxy Setting"
        Details             = $displayValue
        DisplayWriteType    = $displayWriteType
        DisplayTestingValue = $osInformation.NetworkInformation.HttpProxy
    }
    Add-AnalyzedResultInformation @params

    if ($displayWriteType -eq "Yellow") {
        $params = $baseParams + @{
            Name             = "Http Proxy By Pass List"
            Details          = "$($osInformation.NetworkInformation.HttpProxy.ByPassList)"
            DisplayWriteType = "Yellow"
        }
        Add-AnalyzedResultInformation @params
    }

    if (($osInformation.NetworkInformation.HttpProxy.ProxyAddress -ne "None") -and
        ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false) -and
        ($null -ne $exchangeInformation.GetExchangeServer.InternetWebProxy) -and
        ($osInformation.NetworkInformation.HttpProxy.ProxyAddress -ne
        "$($exchangeInformation.GetExchangeServer.InternetWebProxy.Host):$($exchangeInformation.GetExchangeServer.InternetWebProxy.Port)")) {
        $params = $baseParams + @{
            Details                = "Error: Exchange Internet Web Proxy doesn't match OS Web Proxy."
            DisplayWriteType       = "Red"
            TestingName            = "Proxy Doesn't Match"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }

    $displayWriteType2012 = $displayWriteType2013 = "Red"
    $displayValue2012 = $displayValue2013 = $defaultValue = "Error --- Unknown"

    if ($null -ne $osInformation.VcRedistributable) {

        $installed2012 = Get-VisualCRedistributableLatest 2012 $osInformation.VcRedistributable
        $installed2013 = Get-VisualCRedistributableLatest 2013 $osInformation.VcRedistributable

        if (Test-VisualCRedistributableUpToDate -Year 2012 -Installed $osInformation.VcRedistributable) {
            $displayWriteType2012 = "Green"
            $displayValue2012 = "$($installed2012.DisplayVersion) Version is current"
        } elseif (Test-VisualCRedistributableInstalled -Year 2012 -Installed $osInformation.VcRedistributable) {
            $displayValue2012 = "Redistributable ($($installed2012.DisplayVersion)) is outdated"
            $displayWriteType2012 = "Yellow"
        }

        if (Test-VisualCRedistributableUpToDate -Year 2013 -Installed $osInformation.VcRedistributable) {
            $displayWriteType2013 = "Green"
            $displayValue2013 = "$($installed2013.DisplayVersion) Version is current"
        } elseif (Test-VisualCRedistributableInstalled -Year 2013 -Installed $osInformation.VcRedistributable) {
            $displayValue2013 = "Redistributable ($($installed2013.DisplayVersion)) is outdated"
            $displayWriteType2013 = "Yellow"
        }
    }

    $params = $baseParams + @{
        Name             = "Visual C++ 2012 x64"
        Details          = $displayValue2012
        DisplayWriteType = $displayWriteType2012
    }
    Add-AnalyzedResultInformation @params

    if ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false) {
        $params = $baseParams + @{
            Name             = "Visual C++ 2013 x64"
            Details          = $displayValue2013
            DisplayWriteType = $displayWriteType2013
        }
        Add-AnalyzedResultInformation @params
    }

    if (($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false -and
            ($displayWriteType2012 -eq "Yellow" -or
            $displayWriteType2013 -eq "Yellow")) -or
        $displayWriteType2012 -eq "Yellow") {

        $params = $baseParams + @{
            Details                = "Note: For more information about the latest C++ Redistributable please visit: https://aka.ms/HC-LatestVC`r`n`t`tThis is not a requirement to upgrade, only a notification to bring to your attention."
            DisplayWriteType       = "Yellow"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }

    if ($defaultValue -eq $displayValue2012 -or
        ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false -and
        $displayValue2013 -eq $defaultValue)) {

        $params = $baseParams + @{
            Details                = "ERROR: Unable to find one of the Visual C++ Redistributable Packages. This can cause a wide range of issues on the server.`r`n`t`tPlease install the missing package as soon as possible. Latest C++ Redistributable please visit: https://aka.ms/HC-LatestVC"
            DisplayWriteType       = "Red"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }

    $displayValue = "False"
    $writeType = "Grey"

    if ($osInformation.ServerPendingReboot.PendingReboot) {
        $displayValue = "True --- Warning a reboot is pending and can cause issues on the server."
        $writeType = "Yellow"
    }

    $params = $baseParams + @{
        Name                = "Server Pending Reboot"
        Details             = $displayValue
        DisplayWriteType    = $writeType
        DisplayTestingValue = $osInformation.ServerPendingReboot.PendingReboot
    }
    Add-AnalyzedResultInformation @params

    if ($osInformation.ServerPendingReboot.PendingReboot -and
        $osInformation.ServerPendingReboot.PendingRebootLocations.Count -gt 0) {

        foreach ($line in $osInformation.ServerPendingReboot.PendingRebootLocations) {
            $params = $baseParams + @{
                Details                = $line
                DisplayWriteType       = "Yellow"
                DisplayCustomTabNumber = 2
                TestingName            = $line
            }
            Add-AnalyzedResultInformation @params
        }

        $params = $baseParams + @{
            Details                = "More Information: https://aka.ms/HC-RebootPending"
            DisplayWriteType       = "Yellow"
            DisplayTestingValue    = $true
            DisplayCustomTabNumber = 2
            TestingName            = "Reboot More Information"
        }
        Add-AnalyzedResultInformation @params
    }
}
