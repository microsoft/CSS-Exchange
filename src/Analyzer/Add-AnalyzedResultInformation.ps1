Function Add-AnalyzedResultInformation {
    param(
        [object]$Details,
        [string]$Name,
        [string]$HtmlName,
        [object]$DisplayGroupingKey,
        [int]$DisplayCustomTabNumber = -1,
        [object]$DisplayTestingValue,
        [string]$DisplayWriteType = "Grey",
        [bool]$AddDisplayResultsLineInfo = $true,
        [bool]$AddHtmlDetailRow = $true,
        [string]$HtmlDetailsCustomValue = "",
        [bool]$AddHtmlOverviewValues = $false,
        [bool]$AddHtmlActionRow = $false,
        #[string]$ActionSettingClass = "",
        #[string]$ActionSettingValue,
        #[string]$ActionRecommendedDetailsClass = "",
        #[string]$ActionRecommendedDetailsValue,
        #[string]$ActionMoreInformationClass = "",
        #[string]$ActionMoreInformationValue,
        [HealthChecker.AnalyzedInformation]$AnalyzedInformation
    )

    Write-VerboseOutput("Calling Add-AnalyzedResultInformation: {0}" -f $name)

    if ($AddDisplayResultsLineInfo) {
        if (!($AnalyzedInformation.DisplayResults.ContainsKey($DisplayGroupingKey))) {
            Write-VerboseOutput("Adding Display Grouping Key: {0}" -f $DisplayGroupingKey.Name)
            [System.Collections.Generic.List[HealthChecker.DisplayResultsLineInfo]]$list = New-Object System.Collections.Generic.List[HealthChecker.DisplayResultsLineInfo]
            $AnalyzedInformation.DisplayResults.Add($DisplayGroupingKey, $list)
        }

        $lineInfo = New-Object HealthChecker.DisplayResultsLineInfo
        $lineInfo.DisplayValue = $Details
        $lineInfo.Name = $Name

        if ($DisplayCustomTabNumber -ne -1) {
            $lineInfo.TabNumber = $DisplayCustomTabNumber
        } else {
            $lineInfo.TabNumber = $DisplayGroupingKey.DefaultTabNumber
        }

        if ($null -ne $DisplayTestingValue) {
            $lineInfo.TestingValue = $DisplayTestingValue
        } else {
            $lineInfo.TestingValue = $Details
        }

        $lineInfo.WriteType = $DisplayWriteType
        $AnalyzedInformation.DisplayResults[$DisplayGroupingKey].Add($lineInfo)
    }

    if ($AddHtmlDetailRow) {
        if (!($analyzedResults.HtmlServerValues.ContainsKey("ServerDetails"))) {
            [System.Collections.Generic.List[HealthChecker.HtmlServerInformationRow]]$list = New-Object System.Collections.Generic.List[HealthChecker.HtmlServerInformationRow]
            $AnalyzedInformation.HtmlServerValues.Add("ServerDetails", $list)
        }

        $detailRow = New-Object HealthChecker.HtmlServerInformationRow

        if ($displayWriteType -ne "Grey") {
            $detailRow.Class = $displayWriteType
        }

        if ([string]::IsNullOrEmpty($HtmlName)) {
            $detailRow.Name = $Name
        } else {
            $detailRow.Name = $HtmlName
        }

        if ([string]::IsNullOrEmpty($HtmlDetailsCustomValue)) {
            $detailRow.DetailValue = $Details
        } else {
            $detailRow.DetailValue = $HtmlDetailsCustomValue
        }

        $AnalyzedInformation.HtmlServerValues["ServerDetails"].Add($detailRow)
    }

    if ($AddHtmlOverviewValues) {
        if (!($analyzedResults.HtmlServerValues.ContainsKey("OverviewValues"))) {
            [System.Collections.Generic.List[HealthChecker.HtmlServerInformationRow]]$list = New-Object System.Collections.Generic.List[HealthChecker.HtmlServerInformationRow]
            $AnalyzedInformation.HtmlServerValues.Add("OverviewValues", $list)
        }

        $overviewValue = New-Object HealthChecker.HtmlServerInformationRow

        if ($displayWriteType -ne "Grey") {
            $overviewValue.Class = $displayWriteType
        }

        if ([string]::IsNullOrEmpty($HtmlName)) {
            $overviewValue.Name = $Name
        } else {
            $overviewValue.Name = $HtmlName
        }

        if ([string]::IsNullOrEmpty($HtmlDetailsCustomValue)) {
            $overviewValue.DetailValue = $Details
        } else {
            $overviewValue.DetailValue = $HtmlDetailsCustomValue
        }

        $AnalyzedInformation.HtmlServerValues["OverviewValues"].Add($overviewValue)
    }

    if ($AddHtmlActionRow) {
        #TODO
    }

    return $AnalyzedInformation
}