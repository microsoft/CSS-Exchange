# Get-TerrlExternalRecipientEstimate

<!-- cspell:ignore TERRL Terrl -->

Download the latest release: [Get-TerrlExternalRecipientEstimate.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-TerrlExternalRecipientEstimate.ps1)

This script estimates Tenant External Recipient Rate Limit (TERRL) consumption from `Get-MessageTraceV2` data and identifies the senders and recipient domains contributing most to that estimate.

TERRL counts outbound recipients whose domain is not an accepted domain in the tenant. The count is per message-recipient pair, not per unique recipient. The script can query message trace directly, analyze an exported CSV, or accept message trace rows from the pipeline.

## Limitations

The result is an **estimate**, not the live TERRL counter. Message trace does not expose every property used by TERRL enforcement. The script detects Exchange Online journal reports when it can discover the journal configuration, excludes expanded distribution-group placeholder rows, and approximates NDR/DSN exclusions from sender information. It cannot reliably identify every excluded message type, including automatic replies or on-premises-generated journal reports, so its estimate can be higher than the live count.

`Get-LimitsEnforcementStatus` is the live ground truth for the tenant's current `ObservedValue`, `Threshold`, `Verdict`, and `EnforcementEnabled` state. Use `-CompareToEnforcementStatus` to display those values beside the estimate.

Message trace data can also be delayed. A zero or low estimate does not prove that the live rolling 24-hour counter is zero or below its threshold.

## Prerequisites

- Windows PowerShell or PowerShell.
- For a live query:
    - The Exchange Online PowerShell module.
    - An active Exchange Online PowerShell session.
    - Permissions to run `Get-MessageTraceV2` and `Get-AcceptedDomain`.
- To compare with enforcement, permission to run `Get-LimitsEnforcementStatus`.
- For automatic journal-report discovery, permission to run `Get-JournalRule` and `Get-TransportConfig`.
- For offline or pipeline analysis without `Get-AcceptedDomain`, provide `-AcceptedDomain`.

The built-in live fetch uses no more than 50 `Get-MessageTraceV2` requests in a rolling five-minute period so that it consumes no more than half of the tenant's shared 100-request limit.

## Parameters

### `-StartDate`

Start of the analysis window. The default is 24 hours before `EndDate`.

### `-EndDate`

End of the analysis window. The default is the current time.

### `-AcceptedDomain`

One or more accepted SMTP domains for the tenant. Recipients on these domains are internal and are not included in the TERRL estimate. If omitted, the script queries `Get-AcceptedDomain`.

### `-ExcludeNullSender`

Controls whether null senders are excluded as an approximation for NDR, DSN, and system traffic. The default is `$true`.

### `-JournalRecipient`

Additional Exchange Online journal-rule destination addresses to exclude. The script also attempts to discover destinations from enabled journal rules.

### `-JournalReportSender`

Additional Exchange Online journal-report envelope sender addresses. The script normally discovers or constructs the tenant's Microsoft Exchange Recipient address.

### `-PageSize`

Number of message trace rows requested per call. The valid range is 1 through 5000, and the default is 5000.

### `-TopSenders`

Maximum number of senders and external recipient domains returned in each ranking. The default is 25.

### `-CompareToEnforcementStatus`

Queries `Get-LimitsEnforcementStatus` and displays the live enforcement values beside the estimate.

### `-InputObject`

Message trace rows received from the PowerShell pipeline. When pipeline input is present, the script does not run its own message trace query.

### `-MessageTraceCsv`

Path to a CSV containing previously exported message trace rows. This bypasses the live message trace query.

### `-CsvPath`

Optional path for exporting the top-sender ranking as CSV.

## Output

The script writes a summary to the host and returns an object with these principal properties:

- `TraceRows`: Number of message trace rows evaluated.
- `ExternalRecipientsCounted`: Estimated count of external message-recipient pairs.
- `DistinctExternalRecipients`: Number of distinct external recipient addresses.
- `DistinctOutboundMessages`: Number of distinct messages with at least one counted external recipient.
- `AcceptedRecipientRows`: Rows excluded because the recipient domain is accepted.
- `ExchangeOnlineJournalRows`: Rows identified and excluded as Exchange Online journal reports.
- `TopSenders`: Sender ranking with estimated external recipients, distinct messages, and percentage of the estimate.
- `TopRecipientDomains`: External recipient-domain ranking.
- `Exclusions`: Counts grouped by exclusion reason.

When `-CsvPath` is specified, only the `TopSenders` table is exported.

## Examples

### Live query

Connect to Exchange Online, then estimate the previous 24 hours. Accepted domains and Exchange Online journal settings are discovered automatically.

```powershell
Connect-ExchangeOnline
.\Get-TerrlExternalRecipientEstimate.ps1
```

### Compare the estimate with live enforcement

```powershell
.\Get-TerrlExternalRecipientEstimate.ps1 -CompareToEnforcementStatus
```

The estimate helps attribute volume. The `Get-LimitsEnforcementStatus` values remain authoritative for the current live TERRL state.

### Analyze an offline CSV

```powershell
.\Get-TerrlExternalRecipientEstimate.ps1 `
    -MessageTraceCsv ".\MessageTrace.csv" `
    -AcceptedDomain "contoso.com", "contoso.onmicrosoft.com"
```

### Analyze pipeline input

```powershell
Get-MessageTraceV2 `
    -StartDate (Get-Date).AddHours(-4) `
    -EndDate (Get-Date) `
    -ResultSize 5000 |
    .\Get-TerrlExternalRecipientEstimate.ps1 `
        -AcceptedDomain "contoso.com", "contoso.onmicrosoft.com"
```

### Export the top-sender ranking

```powershell
$result = .\Get-TerrlExternalRecipientEstimate.ps1 `
    -AcceptedDomain "contoso.com", "contoso.onmicrosoft.com" `
    -CsvPath ".\TerrlTopSenders.csv"

$result.TopRecipientDomains |
    Export-Csv -LiteralPath ".\TerrlTopRecipientDomains.csv" -NoTypeInformation
```
