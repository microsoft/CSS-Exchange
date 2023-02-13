# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Add-AnalyzedResultInformation {
    [CmdletBinding()]
    param(
        # Main object that we are manipulating and adding entries to
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$AnalyzedInformation,

        # The value of the display entry
        [object]$Details,

        [object]$DisplayGroupingKey,

        [int]$DisplayCustomTabNumber = -1,

        [string]$DisplayWriteType = "Grey",

        # The name of the display entry
        [string]$Name,

        # Used for when the name might have a duplicate and we want it to be unique for logic outside of display
        [string]$CustomName,

        # Used for when the value might have a duplicate and we want it to be unique for logic outside of display
        [object]$CustomValue,

        # Used to display an Object in a table
        [object]$OutColumns,

        [ScriptBlock[]]$OutColumnsColorTests,

        [string]$TestingName,

        [object]$DisplayTestingValue,

        [string]$HtmlName,

        [string]$HtmlDetailsCustomValue = "",

        [bool]$AddDisplayResultsLineInfo = $true,

        [bool]$AddHtmlDetailRow = $true,

        [bool]$AddHtmlOverviewValues = $false,

        [bool]$AddHtmlActionRow = $false
        #[string]$ActionSettingClass = "",
        #[string]$ActionSettingValue,
        #[string]$ActionRecommendedDetailsClass = "",
        #[string]$ActionRecommendedDetailsValue,
        #[string]$ActionMoreInformationClass = "",
        #[string]$ActionMoreInformationValue,
    )
    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand): $name"
        function GetOutColumnsColorObject {
            param(
                [object[]]$OutColumns,
                [ScriptBlock[]]$OutColumnsColorTests,
                [string]$DefaultDisplayColor = ""
            )

            $returnValue = New-Object System.Collections.Generic.List[object]

            foreach ($obj in $OutColumns) {
                $objectValue = New-Object PSCustomObject
                foreach ($property in $obj.PSObject.Properties.Name) {
                    $displayColor = $DefaultDisplayColor
                    foreach ($func in $OutColumnsColorTests) {
                        $result = $func.Invoke($obj, $property)
                        if (-not [string]::IsNullOrEmpty($result)) {
                            $displayColor = $result[0]
                            break
                        }
                    }

                    $objectValue | Add-Member -MemberType NoteProperty -Name $property -Value ([PSCustomObject]@{
                            Value        = $obj.$property
                            DisplayColor = $displayColor
                        })
                }
                $returnValue.Add($objectValue)
            }
            return $returnValue
        }
    }
    process {
        Write-Verbose "Calling $($MyInvocation.MyCommand): $name"

        if ($AddDisplayResultsLineInfo) {
            if (!($AnalyzedInformation.DisplayResults.ContainsKey($DisplayGroupingKey))) {
                Write-Verbose "Adding Display Grouping Key: $($DisplayGroupingKey.Name)"
                [System.Collections.Generic.List[object]]$list = New-Object System.Collections.Generic.List[object]
                $AnalyzedInformation.DisplayResults.Add($DisplayGroupingKey, $list)
            }

            $lineInfo = [PSCustomObject]@{
                DisplayValue = [string]::Empty
                Name         = [string]::Empty
                TestingName  = [string]::Empty       # Used for pestering testing
                CustomName   = [string]::Empty       # Used for security vulnerability
                TabNumber    = 0
                TestingValue = $null                 # Used for pester testing down the road
                CustomValue  = $null                 # Used for security vulnerability
                OutColumns   = $null                 # Used for colorized format table option
                WriteType    = [string]::Empty
            }

            if ($null -ne $OutColumns) {
                $lineInfo.OutColumns = $OutColumns
                $lineInfo.WriteType = "OutColumns"
                $lineInfo.TestingValue = (GetOutColumnsColorObject -OutColumns $OutColumns.DisplayObject -OutColumnsColorTests $OutColumnsColorTests -DefaultDisplayColor "Grey")
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

                if ($null -ne $CustomValue) {
                    $lineInfo.CustomValue = $CustomValue
                } elseif ($null -ne $DisplayTestingValue) {
                    $lineInfo.CustomValue = $DisplayTestingValue
                } else {
                    $lineInfo.CustomValue = $Details
                }

                if (-not ([string]::IsNullOrEmpty($TestingName))) {
                    $lineInfo.TestingName = $TestingName
                } else {
                    $lineInfo.TestingName = $Name
                }

                if (-not ([string]::IsNullOrEmpty($CustomName))) {
                    $lineInfo.CustomName = $CustomName
                } elseif (-not ([string]::IsNullOrEmpty($TestingName))) {
                    $lineInfo.CustomName = $TestingName
                } else {
                    $lineInfo.CustomName = $Name
                }

                $lineInfo.WriteType = $DisplayWriteType
            }

            $AnalyzedInformation.DisplayResults[$DisplayGroupingKey].Add($lineInfo)
        }

        $htmlDetailRow = [PSCustomObject]@{
            Name        = [string]::Empty
            DetailValue = [string]::Empty
            TableValue  = $null
            Class       = [string]::Empty
        }

        if ($AddHtmlDetailRow) {
            if (!($analyzedResults.HtmlServerValues.ContainsKey("ServerDetails"))) {
                [System.Collections.Generic.List[object]]$list = New-Object System.Collections.Generic.List[object]
                $AnalyzedInformation.HtmlServerValues.Add("ServerDetails", $list)
            }

            $detailRow = $htmlDetailRow

            if ($displayWriteType -ne "Grey") {
                $detailRow.Class = $displayWriteType
            }

            if ([string]::IsNullOrEmpty($HtmlName)) {
                $detailRow.Name = $Name
            } else {
                $detailRow.Name = $HtmlName
            }

            if ($null -ne $OutColumns) {
                $detailRow.TableValue = (GetOutColumnsColorObject -OutColumns $OutColumns.DisplayObject -OutColumnsColorTests $OutColumnsColorTests)
            } elseif ([string]::IsNullOrEmpty($HtmlDetailsCustomValue)) {
                $detailRow.DetailValue = $Details
            } else {
                $detailRow.DetailValue = $HtmlDetailsCustomValue
            }

            $AnalyzedInformation.HtmlServerValues["ServerDetails"].Add($detailRow)
        }

        if ($AddHtmlOverviewValues) {
            if (!($analyzedResults.HtmlServerValues.ContainsKey("OverviewValues"))) {
                [System.Collections.Generic.List[object]]$list = New-Object System.Collections.Generic.List[object]
                $AnalyzedInformation.HtmlServerValues.Add("OverviewValues", $list)
            }

            $overviewValue = $htmlDetailRow

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
