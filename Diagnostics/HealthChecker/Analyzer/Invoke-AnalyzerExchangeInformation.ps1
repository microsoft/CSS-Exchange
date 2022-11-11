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
        Details               = $exchangeInformation.BuildInformation.FriendlyName
        AddHtmlOverviewValues = $true
        HtmlName              = "Exchange Version"
    }
    Add-AnalyzedResultInformation @params

    $params = $baseParams + @{
        Name    = "Build Number"
        Details = $exchangeInformation.BuildInformation.ExchangeSetup.FileVersion
    }
    Add-AnalyzedResultInformation @params

    if ($exchangeInformation.BuildInformation.SupportedBuild -eq $false) {
        $daysOld = ($date - ([System.Convert]::ToDateTime([DateTime]$exchangeInformation.BuildInformation.ReleaseDate,
                    [System.Globalization.DateTimeFormatInfo]::InvariantInfo))).Days

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

    $extendedSupportDate = [System.Convert]::ToDateTime([DateTime]$exchangeInformation.BuildInformation.ExtendedSupportDate,
        [System.Globalization.DateTimeFormatInfo]::InvariantInfo)
    if ($extendedSupportDate -le ([DateTime]::Now.AddYears(1))) {
        $displayWriteType = "Yellow"

        if ($extendedSupportDate -le ([DateTime]::Now.AddDays(178))) {
            $displayWriteType = "Red"
        }

        $displayValue = "$($exchangeInformation.BuildInformation.ExtendedSupportDate) - Please note of the End Of Life date and plan to migrate soon."

        if ($extendedSupportDate -le ([DateTime]::Now)) {
            $displayValue = "$($exchangeInformation.BuildInformation.ExtendedSupportDate) - Error: You are past the End Of Life of Exchange."
        }

        $params = $baseParams + @{
            Name                   = "End Of Life"
            Details                = $displayValue
            DisplayWriteType       = $displayWriteType
            DisplayCustomTabNumber = 2
            AddHtmlDetailRow       = $false
        }
        Add-AnalyzedResultInformation @params
    }

    if (-not ([string]::IsNullOrEmpty($exchangeInformation.BuildInformation.LocalBuildNumber))) {
        $local = $exchangeInformation.BuildInformation.LocalBuildNumber
        $remote = $exchangeInformation.BuildInformation.BuildNumber

        if ($local.Substring(0, $local.LastIndexOf(".")) -ne $remote.Substring(0, $remote.LastIndexOf("."))) {
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

    if ($null -ne $exchangeInformation.BuildInformation.KBsInstalled) {
        Add-AnalyzedResultInformation -Name "Exchange IU or Security Hotfix Detected" @baseParams

        foreach ($kb in $exchangeInformation.BuildInformation.KBsInstalled) {
            $params = $baseParams + @{
                Details                = $kb
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }
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

    if ($exchangeInformation.BuildInformation.ServerRole -le [HealthChecker.ExchangeServerRole]::Mailbox) {
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

    $params = $baseParams + @{
        Name    = "MAPI/HTTP Enabled"
        Details = $HealthServerObject.OrganizationInformation.MapiHttpEnabled
    }
    Add-AnalyzedResultInformation @params

    if (($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) -and
        ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Hub) -and
        ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::None)) {

        Write-Verbose "Working on MRS Proxy Settings"
        $mrsProxyDetails = $exchangeInformation.GetWebServicesVirtualDirectory.MRSProxyEnabled
        if ($exchangeInformation.GetWebServicesVirtualDirectory.MRSProxyEnabled) {
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
        Details = $( if ([string]::IsNullOrEmpty($internetProxy)) { "Not Set" } else { $internetProxy } )
    }
    Add-AnalyzedResultInformation @params

    if (-not ([string]::IsNullOrWhiteSpace($exchangeInformation.GetWebServicesVirtualDirectory.InternalNLBBypassUrl))) {
        $params = $baseParams + @{
            Name             = "EWS Internal Bypass URL Set"
            Details          = "$($exchangeInformation.GetWebServicesVirtualDirectory.InternalNLBBypassUrl) - Can cause issues after KB 5001779"
            DisplayWriteType = "Red"
        }
        Add-AnalyzedResultInformation @params
    }

    Write-Verbose "Working on results from Test-ServiceHealth"
    $servicesNotRunning = $exchangeInformation.ExchangeServicesNotRunning

    if ($null -ne $servicesNotRunning) {
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
    }

    if ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge -and
        $null -ne $exchangeInformation.ExtendedProtectionConfig) {
        $params = $baseParams + @{
            Name    = "Extended Protection Enabled (Any Vdir)"
            Details = $exchangeInformation.ExtendedProtectionConfig.ExtendedProtectionConfigured
        }
        Add-AnalyzedResultInformation @params
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
