# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-HtmlServerReport {
    param(
        [Parameter(Mandatory = $true)][array]$AnalyzedHtmlServerValues
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

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
        <tr>"

    foreach ($tableHeaderName in $AnalyzedHtmlServerValues[0]["OverviewValues"].Name) {
        $htmlOverviewTable += "<th>{0}</th>" -f $tableHeaderName
    }

    $htmlOverviewTable += "</tr>"

    foreach ($serverHtmlServerValues in $AnalyzedHtmlServerValues) {
        $htmlTableRow = @()
        [array]$htmlTableRow += "<tr>"
        foreach ($htmlTableDataRow in $serverHtmlServerValues["OverviewValues"]) {
            $htmlTableRow += "<td class=`"{0}`">{1}</td>" -f $htmlTableDataRow.Class, `
                $htmlTableDataRow.DetailValue
        }

        $htmlTableRow += "</tr>"
        $htmlOverviewTable += $htmlTableRow
    }

    $htmlOverviewTable += "</table></p>"

    [array]$htmlServerDetails += "<p><h2>Server Details</h2><table>"

    foreach ($serverHtmlServerValues in $AnalyzedHtmlServerValues) {
        foreach ($htmlTableDataRow in $serverHtmlServerValues["ServerDetails"]) {
            if ($htmlTableDataRow.Name -eq "Server Name") {
                $htmlServerDetails += "<tr><th>{0}</th><th>{1}</th><tr>" -f $htmlTableDataRow.Name, `
                    $htmlTableDataRow.DetailValue
            } else {
                $htmlServerDetails += "<tr><td class=`"{0}`">{1}</td><td class=`"{0}`">{2}</td><tr>" -f $htmlTableDataRow.Class, `
                    $htmlTableDataRow.Name, `
                    $htmlTableDataRow.DetailValue
            }
        }
    }
    $htmlServerDetails += "</table></p>"

    $htmlReport = $htmlHeader + $htmlOverviewTable + $htmlServerDetails + "</body></html>"

    $htmlReport | Out-File $HtmlReportFile -Encoding UTF8
}
