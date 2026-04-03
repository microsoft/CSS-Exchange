# Get-AllMessageTraceResults

Download the latest release: [Get-AllMessageTraceResults.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-AllMessageTraceResults.ps1)

This script provides a wrapper around `Get-MessageTraceV2` that automatically handles pagination to retrieve all matching message trace results from Exchange Online. It collects results in pages of up to 5000 and continues fetching until all results are returned or a timeout is reached.

## Parameters

-StartDate

The start date of the date range to search. Data is available for the last 90 days, with a maximum of 10 days per query.

-EndDate

The end date of the date range to search.

-SenderAddress

Filters results by the sender's email address. Accepts multiple values separated by commas.

-RecipientAddress

Filters results by the recipient's email address. Accepts multiple values separated by commas.

-MessageId

Filters results by the Message-ID header field of the message.

-MessageTraceId

Filters results by the message trace ID (GUID).

-FromIP

Filters results by the source IP address.

-ToIP

Filters results by the destination IP address.

-Status

Filters results by delivery status. Valid values are: `Delivered`, `Expanded`, `Failed`, `FilteredAsSpam`, `GettingStatus`, `Pending`, `Quarantined`.

-Subject

Filters results by the message subject. Use with `-SubjectFilterType` to control matching behavior.

-SubjectFilterType

Specifies how the `-Subject` value is evaluated. Valid values are: `Contains`, `StartsWith`, `EndsWith`.

-PageSize

The number of results to retrieve per page. Valid range is 1 to 5000. The default value is 5000.

-TimeoutMinutes

The number of minutes before the script stops fetching additional pages. The default value is 30 minutes.

## Examples

Retrieve all messages from the last 7 hours:

```powershell
. .\Get-AllMessageTraceResults.ps1
$messages = Get-AllMessageTraceResults -StartDate (Get-Date).AddHours(-7) -EndDate (Get-Date)
```

Filter by sender and status:

```powershell
$messages = Get-AllMessageTraceResults -StartDate (Get-Date).AddHours(-7) -EndDate (Get-Date) -SenderAddress "john@contoso.com" -Status "Delivered"
```

Filter by recipient with a custom page size:

```powershell
$messages = Get-AllMessageTraceResults -StartDate (Get-Date).AddDays(-2) -EndDate (Get-Date) -RecipientAddress "jane@contoso.com" -PageSize 1000
```

## Output

Returns an array of message trace objects from `Get-MessageTraceV2`. The total number of retrieved messages is displayed upon completion.
