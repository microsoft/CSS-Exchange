# Compute-TopExoRecipientsFromMessageTrace

Download the latest release: [Compute-TopExoRecipientsFromMessageTrace.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Compute-TopExoRecipientsFromMessageTrace.ps1)

This script aggregates message trace events hourly and generates a report with the top o365 recipients

## Parameters

-StartDate

The StartDate parameter specifies the end date of the date range

-EndDate

The EndDate parameter specifies the end date of the date range. It is recommended to limit the start-end date range to a range of hours. i.e. an ~ 5 to 7 hours.

-TimeoutAfter

The TimeoutAfter parameter specifies the number of minutes before the script stop working.
This is to make sure that the script does not run for infinity. The default value is 30 minutes.

-Threshold

The Threshold parameter specifies the min threshold for the received limit.
It is used to filter the hourly aggregation.
The default value is 3600 messages.

## Examples

```powershell
$results = Compute-TopExoRecipientsFromMessageTrace -StartDate (Get-Date).AddHours(-7) -EndDate (Get-Date)
```

## Output

$results.TopRecipients : hourly report for top recipients over the threshold
$results.HourlyReport  : hourly aggregated message events without applying the threshold
$results.MessageTraceEvents: all downloaded message trace events without aggregations
