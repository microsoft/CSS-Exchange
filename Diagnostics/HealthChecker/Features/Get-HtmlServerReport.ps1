# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-HtmlServerReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$AnalyzedHtmlServerValues,

        [string]$HtmlOutFilePath
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    function GetOutColumnHtmlTable {
        param(
            [object]$OutColumn
        )
        # this keeps the order of the columns
        $headerValues = $OutColumn[0].PSObject.Properties.Name
        $htmlTableValue = "<table>"

        foreach ($header in $headerValues) {
            $htmlTableValue += "<th>$header</th>"
        }

        foreach ($dataRow in $OutColumn) {
            $htmlTableValue += "$([System.Environment]::NewLine)<tr>"

            foreach ($header in $headerValues) {
                $htmlTableValue += "<td class=`"$($dataRow.$header.DisplayColor)`">$($dataRow.$header.Value)</td>"
            }
            $htmlTableValue += "$([System.Environment]::NewLine)</tr>"
        }
        $htmlTableValue += "</table>"
        return $htmlTableValue
    }

    $htmlHeader = "<html>
        <style>
        BODY{font-family: Arial; font-size: 8pt;}
        H1{font-size: 16px;}
        H2{font-size: 14px;}
        H3{font-size: 12px;}
        TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
        TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
        TD{border: 1px solid black; padding: 5px; }
        td.Green{background: #7FFF00;}
        td.Yellow{background: #FFE600;}
        td.Red{background: #FF0000; color: #ffffff;}
        td.Info{background: #85D4FF;}
        </style>
        <body>
        <h1 align=""center"">Exchange Health Checker v$($BuildVersion)</h1><br>
        <h2>Servers Overview</h2>"

    [array]$htmlOverviewTable += "<p>
        <table>
        <tr>$([System.Environment]::NewLine)"

    foreach ($tableHeaderName in $AnalyzedHtmlServerValues[0]["OverviewValues"].Name) {
        $htmlOverviewTable += "<th>{0}</th>$([System.Environment]::NewLine)" -f $tableHeaderName
    }

    $htmlOverviewTable += "</tr>$([System.Environment]::NewLine)"

    foreach ($serverHtmlServerValues in $AnalyzedHtmlServerValues) {
        $htmlTableRow = @()
        [array]$htmlTableRow += "<tr>$([System.Environment]::NewLine)"
        foreach ($htmlTableDataRow in $serverHtmlServerValues["OverviewValues"]) {
            $htmlTableRow += "<td class=`"{0}`">{1}</td>$([System.Environment]::NewLine)" -f $htmlTableDataRow.Class, `
                $htmlTableDataRow.DetailValue
        }

        $htmlTableRow += "</tr>$([System.Environment]::NewLine)"
        $htmlOverviewTable += $htmlTableRow
    }

    $htmlOverviewTable += "</table>$([System.Environment]::NewLine)</p>$([System.Environment]::NewLine)"

    [array]$htmlServerDetails += "<p>$([System.Environment]::NewLine)<h2>Server Details</h2>$([System.Environment]::NewLine)<table>"

    foreach ($serverHtmlServerValues in $AnalyzedHtmlServerValues) {
        foreach ($htmlTableDataRow in $serverHtmlServerValues["ServerDetails"]) {
            if ($htmlTableDataRow.Name -eq "Server Name") {
                $htmlServerDetails += "<tr>$([System.Environment]::NewLine)<th>{0}</th>$([System.Environment]::NewLine)<th>{1}</th>$([System.Environment]::NewLine)</tr>$([System.Environment]::NewLine)" -f $htmlTableDataRow.Name, `
                    $htmlTableDataRow.DetailValue
            } elseif ($null -ne $htmlTableDataRow.TableValue) {
                $htmlTable = GetOutColumnHtmlTable $htmlTableDataRow.TableValue
                $htmlServerDetails += "<tr>$([System.Environment]::NewLine)<td class=`"{0}`">{1}</td><td class=`"{0}`">{2}</td>$([System.Environment]::NewLine)</tr>$([System.Environment]::NewLine)" -f $htmlTableDataRow.Class, `
                    $htmlTableDataRow.Name, `
                    $htmlTable
            } else {
                $htmlServerDetails += "<tr>$([System.Environment]::NewLine)<td class=`"{0}`">{1}</td><td class=`"{0}`">{2}</td>$([System.Environment]::NewLine)</tr>$([System.Environment]::NewLine)" -f $htmlTableDataRow.Class, `
                    $htmlTableDataRow.Name, `
                    $htmlTableDataRow.DetailValue
            }
        }
    }
    $htmlServerDetails += "$([System.Environment]::NewLine)</table>$([System.Environment]::NewLine)</p>$([System.Environment]::NewLine)"

    $htmlReport = $htmlHeader + $htmlOverviewTable + $htmlServerDetails + "</body>$([System.Environment]::NewLine)</html>"

    $htmlReport | Out-File $HtmlOutFilePath -Encoding UTF8

    Write-Host "HTML Report Location: $HtmlOutFilePath"
}
