# Measure-EmailDelayInMTL
Generates a report of the maximum message delay for all messages in an Message Tracking Log.

## DESCRIPTION
Gather message tracking log details of all message to / from a given recipient for a given time range. Useful for determining if a "slow" message was a one off or a pattern.

Recommend using [Start-HistoricalSearch](https://learn.microsoft.com/en-us/powershell/module/exchange/start-historicalsearch?view=exchange-ps) in EXO to gather an detailed MTL for processing.

``` PowerShell
Start-HistoricalSearch -ReportTitle "Fabrikam Search" -StartDate 8/10/2024 -EndDate 8/12/2024 -ReportType MessageTraceDetail -SenderAddress michelle@fabrikam.com -NotifyAddress chris@contoso.com
```

## PARAMETER

**-MTLFile**

MTL File to process.

**-ReportPath**

Folder path for the output file.


## Outputs

### CSV File

| Header | Description |
| ------ | ----------- |
| MessageID | ID of the Message |
| TimeSent |  First time we see the message in the MTL |
| TimeReceived | Last delivery time in the MTL |
| MessageDelay | How long before the message was delivered |

### Statistical Summary

| Statistic | Description |
| --------- | ----------- |
| EmailCount | Number of email found in the MTL |
| MaximumDelay | Longest delivery delay found in the MTL |
| MinimumDelay | Shortest delivery delay found in the MTL |
| AverageDelay | Average of all delivery delays across all email in the MTL |

### Default Output File:
``` PowerShell
$PSScriptRoot\MTL_report.csv
```

## EXAMPLE
``` PowerShell
.\Measure-EmailDelayInMTL -MTLPath C:\temp\MyMtl.csv
```
Generates a report to the default path from the file C:\Temp\MyMtl.csv.

``` PowerShell
.\Measure-EmailDelayInMTL -MTLPath C:\temp\LargeMTL.csv -ReportPath C:\output
```
Generates a report to the c:\output directory from the file C:\Temp\LargeMTL.csv.