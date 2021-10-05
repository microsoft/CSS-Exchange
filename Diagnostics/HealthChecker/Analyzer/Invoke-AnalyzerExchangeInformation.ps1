# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
Function Invoke-AnalyzerExchangeInformation {
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

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Name" -Details ($HealthServerObject.ServerName) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true `
        -HtmlName "Server Name"

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Generation Time" -Details $HealthServerObject.GenerationTime `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Version" -Details ($exchangeInformation.BuildInformation.FriendlyName) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true `
        -HtmlName "Exchange Version"

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Build Number" -Details ($exchangeInformation.BuildInformation.ExchangeSetup.FileVersion) `
        -DisplayGroupingKey $keyExchangeInformation

    if ($exchangeInformation.BuildInformation.SupportedBuild -eq $false) {
        $daysOld = ($date - ([System.Convert]::ToDateTime([DateTime]$exchangeInformation.BuildInformation.ReleaseDate,
                    [System.Globalization.DateTimeFormatInfo]::InvariantInfo))).Days

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Error" `
            -Details ("Out of date Cumulative Update. Please upgrade to one of the two most recently released Cumulative Updates. Currently running on a build that is {0} days old." -f $daysOld) `
            -DisplayGroupingKey $keyExchangeInformation `
            -DisplayWriteType "Red" `
            -DisplayCustomTabNumber 2 `
            -TestingName "Out of Date" `
            -DisplayTestingValue $true `
            -AddHtmlDetailRow $false
    }

    if (-not ([string]::IsNullOrEmpty($exchangeInformation.BuildInformation.LocalBuildNumber))) {
        $local = $exchangeInformation.BuildInformation.LocalBuildNumber
        $remote = $exchangeInformation.BuildInformation.BuildNumber

        if ($local.Substring(0, $local.LastIndexOf(".")) -ne $remote.Substring(0, $remote.LastIndexOf("."))) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Warning" `
                -Details ("Running commands from a different version box can cause issues. Local Tools Server Version: {0}" -f $local) `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayWriteType "Yellow" `
                -DisplayCustomTabNumber 2 `
                -AddHtmlDetailRow $false
        }
    }

    if ($null -ne $exchangeInformation.BuildInformation.KBsInstalled) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Details ("Exchange IU or Security Hotfix Detected.") `
            -DisplayGroupingKey $keyExchangeInformation `
            -AddHtmlDetailRow $false

        foreach ($kb in $exchangeInformation.BuildInformation.KBsInstalled) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details $kb `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -AddHtmlDetailRow $false
        }
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Server Role" -Details ($exchangeInformation.BuildInformation.ServerRole) `
        -DisplayGroupingKey $keyExchangeInformation `
        -AddHtmlOverviewValues $true

    if ($exchangeInformation.BuildInformation.ServerRole -le [HealthChecker.ExchangeServerRole]::Mailbox) {
        $dagName = [System.Convert]::ToString($exchangeInformation.GetMailboxServer.DatabaseAvailabilityGroup)
        if ([System.String]::IsNullOrWhiteSpace($dagName)) {
            $dagName = "Standalone Server"
        }
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "DAG Name" -Details $dagName `
            -DisplayGroupingKey $keyExchangeInformation
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "AD Site" -Details ([System.Convert]::ToString(($exchangeInformation.GetExchangeServer.Site)).Split("/")[-1]) `
        -DisplayGroupingKey $keyExchangeInformation

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "MAPI/HTTP Enabled" -Details ($exchangeInformation.MapiHttpEnabled) `
        -DisplayGroupingKey $keyExchangeInformation

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

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "MAPI Front End App Pool GC Mode" -Details $displayValue `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType $displayWriteType
        } else {
            $warning = "Unable to determine MAPI Front End App Pool GC Mode status. This may be a temporary issue. You should try to re-run the script"
        }

        if ($warning -ne [string]::Empty) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details $warning `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AddHtmlDetailRow $false
        }
    }

    $internetProxy = $exchangeInformation.GetExchangeServer.InternetWebProxy

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Internet Web Proxy" `
        -Details $( if ([string]::IsNullOrEmpty($internetProxy)) { "Not Set" } else { $internetProxy } )`
        -DisplayGroupingKey $keyExchangeInformation

    if (-not ([string]::IsNullOrWhiteSpace($exchangeInformation.GetWebServicesVirtualDirectory.InternalNLBBypassUrl))) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "EWS Internal Bypass URL Set" `
            -Details ("$($exchangeInformation.GetWebServicesVirtualDirectory.InternalNLBBypassUrl) - Can cause issues after KB 5001779") `
            -DisplayGroupingKey $keyExchangeInformation `
            -DisplayWriteType "Red"
    }

    Write-Verbose "Working on results from Test-ServiceHealth"
    $servicesNotRunning = $exchangeInformation.ExchangeServicesNotRunning

    if ($null -ne $servicesNotRunning) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Services Not Running" `
            -DisplayGroupingKey $keyExchangeInformation

        foreach ($stoppedService in $servicesNotRunning) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details $stoppedService `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2  `
                -DisplayWriteType "Yellow"
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
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Exchange Server Maintenance" -Details "Server is not in Maintenance Mode" `
            -DisplayGroupingKey $keyExchangeInformation `
            -DisplayWriteType "Green"
    } else {
        $AnalyzeResults | Add-AnalyzedResultInformation -Details "Exchange Server Maintenance" `
            -DisplayGroupingKey $keyExchangeInformation

        if (($serverMaintenance.InactiveComponents).Count -ne 0) {
            foreach ($inactiveComponent in $serverMaintenance.InactiveComponents) {
                $AnalyzeResults | Add-AnalyzedResultInformation -Name "Component" -Details $inactiveComponent `
                    -DisplayGroupingKey $keyExchangeInformation `
                    -DisplayCustomTabNumber 2  `
                    -DisplayWriteType "Red"
            }

            $AnalyzeResults | Add-AnalyzedResultInformation -Details "For more information: https://aka.ms/HC-ServerComponentState" `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow"
        }

        if ($getMailboxServer.DatabaseCopyActivationDisabledAndMoveNow -or
            $getMailboxServer.DatabaseCopyAutoActivationPolicy -eq "Blocked") {
            $displayValue = "`r`n`t`tDatabaseCopyActivationDisabledAndMoveNow: {0} --- should be 'false'`r`n`t`tDatabaseCopyAutoActivationPolicy: {1} --- should be 'unrestricted'" -f `
                $getMailboxServer.DatabaseCopyActivationDisabledAndMoveNow,
            $getMailboxServer.DatabaseCopyAutoActivationPolicy

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Database Copy Maintenance" -Details $displayValue `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red"
        }

        if ($null -ne $serverMaintenance.GetClusterNode -and
            $serverMaintenance.GetClusterNode.State -ne "Up") {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Cluster Node" -Details ("'{0}' --- should be 'Up'" -f $serverMaintenance.GetClusterNode.State) `
                -DisplayGroupingKey $keyExchangeInformation `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red"
        }
    }
}
