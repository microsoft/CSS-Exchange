# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Add-AnalyzedResultInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [HealthChecker.AnalyzedInformation]$AnalyzedInformation,
        [object]$Details,
        [string]$Name,
        [string]$TestingName,
        [object]$OutColumns,
        [scriptblock[]]$OutColumnsColorTests,
        [string]$HtmlName,
        [object]$DisplayGroupingKey,
        [int]$DisplayCustomTabNumber = -1,
        [object]$DisplayTestingValue,
        [string]$DisplayWriteType = "Grey",
        [bool]$AddDisplayResultsLineInfo = $true,
        [bool]$AddHtmlDetailRow = $true,
        [string]$HtmlDetailsCustomValue = "",
        [bool]$AddHtmlOverviewValues = $false,
        [bool]$AddHtmlActionRow = $false
        #[string]$ActionSettingClass = "",
        #[string]$ActionSettingValue,
        #[string]$ActionRecommendedDetailsClass = "",
        #[string]$ActionRecommendedDetailsValue,
        #[string]$ActionMoreInformationClass = "",
        #[string]$ActionMoreInformationValue,
    )
    process {
        Write-Verbose "Calling $($MyInvocation.MyCommand): $name"

        if ($AddDisplayResultsLineInfo) {
            if (!($AnalyzedInformation.DisplayResults.ContainsKey($DisplayGroupingKey))) {
                Write-Verbose "Adding Display Grouping Key: $($DisplayGroupingKey.Name)"
                [System.Collections.Generic.List[HealthChecker.DisplayResultsLineInfo]]$list = New-Object System.Collections.Generic.List[HealthChecker.DisplayResultsLineInfo]
                $AnalyzedInformation.DisplayResults.Add($DisplayGroupingKey, $list)
            }

            $lineInfo = New-Object HealthChecker.DisplayResultsLineInfo

            if ($null -ne $OutColumns) {
                $testingValue = New-Object System.Collections.Generic.List[object]
                foreach ($obj in $OutColumns.DisplayObject) {
                    $objectTestingValue = New-Object PSCustomObject
                    foreach ($property in $obj.PSObject.Properties.Name) {
                        $displayColor = "Grey"

                        foreach ($func in $OutColumnsColorTests) {
                            $result = $func.Invoke($obj, $property)
                            if (-not [string]::IsNullOrEmpty($result)) {
                                $displayColor = $result[0]
                                break
                            }
                        }
                        $objectTestingValue | Add-Member -MemberType NoteProperty -Name $property -Value ([PSCustomObject]@{
                                Value        = $obj.$property
                                DisplayColor = $displayColor
                            })
                    }
                    $testingValue.Add($objectTestingValue)
                }
                $lineInfo.OutColumns = $OutColumns
                $lineInfo.WriteType = "OutColumns"
                $lineInfo.TestingValue = $testingValue
                $lineInfo.TestingName = $TestingName
            } else {

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

                if (-not ([string]::IsNullOrEmpty($TestingName))) {
                    $lineInfo.TestingName = $TestingName
                } else {
                    $lineInfo.TestingName = $Name
                }

                $lineInfo.WriteType = $DisplayWriteType
            }

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

            if ($null -ne $OutColumns) {
                $detailRow.TableValue = $OutColumns
            } elseif ([string]::IsNullOrEmpty($HtmlDetailsCustomValue)) {
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
    }
}
