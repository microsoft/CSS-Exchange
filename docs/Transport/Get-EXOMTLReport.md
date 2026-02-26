# Get-EXOMTLReport
Download the latest release: [Get-EXOMTLReport](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-EXOMTLReport.ps1)

Provides information about email messages sent thru EXO by parsing a detailed message tracking log.

## DESCRIPTION
Parses thru EXO Message Tracking log to extract detailed information about the message and present it in a more readable format.

### Exchange Online
Recommend using [Start-HistoricalSearch](https://learn.microsoft.com/en-us/powershell/module/exchange/start-historicalsearch?view=exchange-ps) in EXO to gather a detailed Message Tracking Log for processing.

``` PowerShell
Start-HistoricalSearch -ReportTitle "Fabrikam Search" -StartDate 8/10/2024 -EndDate 8/12/2024 -ReportType MessageTraceDetail -SenderAddress michelle@fabrikam.com -NotifyAddress chris@contoso.com
```

### Exchange On Premises
Does NOT work with Exchange On Premises message tracking logs.

## PARAMETER

**-MTLFile**

CSV output of Message Tracking Log to process.

**-ReportPath**

Folder path for the output file.

**-MessageID**

Specifies the messageID to gather information about if there is more than one in the provided Message Tracking Log.

## Outputs

### Text File

* Message Statistics
* Submission Information (from non-smtp client)
* Mime Data

### Default Output File:
``` PowerShell
$PSScriptRoot\MTL_Report_<date>.txt
```

## EXAMPLE
``` PowerShell
.\Get-EXOMTLReport -MTLPath C:\temp\MyMtl.csv
```
Generates a report to the default path from the file C:\Temp\MyMtl.csv.

``` PowerShell
.\Measure-EmailDelayInMTL -MTLPath C:\temp\LargeMTL.csv -ReportPath C:\output -MessageID "<1231421231@server.contoso.com>"
```
Generates a report to the c:\output directory from the file C:\Temp\LargeMTL.csv focusing on the MessageID <1231421231@server.contoso.com>
