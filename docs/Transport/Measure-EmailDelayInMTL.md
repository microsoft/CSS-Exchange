# Measure-EmailDelayInMTL
Parse Message Tracking log output to provide information about message delivery delays.

## Exchange Online
For Exchange online it is recommended to use the output from [Start-HistoricalSearch](https://learn.microsoft.com/en-us/powershell/module/exchange/start-historicalsearch?view=exchange-ps).

``` PowerShell
Start-HistoricalSearch -ReportTitle "Fabrikam Search" -StartDate 8/10/2024 -EndDate 8/12/2024 -ReportType MessageTraceDetail -SenderAddress michelle@fabrikam.com -NotifyAddress chris@contoso.com
```

## Exchange On Prem
For Exchange On Prem we recommend using the output from [Get-MessageTrackingLog](https://learn.microsoft.com/en-us/powershell/module/exchange/get-messagetrackinglog?view=exchange-ps).

``` PowerShell
Get-TransportService | Get-MessageTrackingLog -Start 08/10/2024 -End 08/12/2024 -Sender user1@contoso.com | Export-csv c:\temp\MyMTL.csv -NoTypeInformation
```

** **Note:** The script will work with a RAW message tracking log from a server, but in a multiple server environment most messagesIDs will fail since receive and deliver events are generally not recorded on the same server.

## Syntax

```powershell
Measure-EmailDelayinMTL.ps1
  [-MTLFile <string>]
  [-ReportPath <string>]
```
## Outputs
The script will generate a MTL_Latency_Report_date.csv file, in the specified output directory or in the folder where the script is run if no directory is specified.
The statistical summary will be provided only to the screen to allow a general overview of what was found.

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

## Usage

``` PowerShell
.\Measure-EmailDelayInMTL -MTLPath C:\temp\MyMtl.csv
```
Generates a report to the default path from the file C:\Temp\MyMtl.csv.

``` PowerShell
.\Measure-EmailDelayInMTL -MTLPath C:\temp\LargeMTL.csv -ReportPath C:\output
```
Generates a report to the c:\output directory from the file C:\Temp\LargeMTL.csv.
