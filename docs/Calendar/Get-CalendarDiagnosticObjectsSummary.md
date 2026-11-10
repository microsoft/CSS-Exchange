# Get-CalendarDiagnosticObjectsSummary

Download the latest release: [Get-CalendarDiagnosticObjectsSummary.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-CalendarDiagnosticObjectsSummary.ps1)

This script runs the Get-CalendarDiagnosticObjects cmdlet and returns a summarized timeline of actions in clear English as well as the Calendar Diagnostic Objects in Excel.

> **Exception collection behavior:** Fast exception collection is now the default behavior for recurring meetings. The script parses `AppointmentRecurrenceBlob` to identify exception dates first, then collects those occurrences directly. By default, it collects the last 3 months of exception dates. Add `-AllExceptions` to collect every exception date instead. Use `-ClassicExceptions` to force the legacy per-appointment collector.

## Prerequisites

1. Install the [ImportExcel](https://github.com/dfinke/ImportExcel) module (required for the default Excel export):

    ```PowerShell
    Install-Module -Name ImportExcel
    ```

2. Connect to [Exchange Online PowerShell](https://learn.microsoft.com/powershell/exchange/connect-to-exchange-online-powershell):

    ```PowerShell
    Import-Module ExchangeOnlineManagement
    Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
    ```

Use **-ExportToCSV** to export to CSV files instead if ImportExcel is not available.

## Cmdlet List

The script uses the following Exchange cmdlets. These queries do not change mailbox settings; local PowerShell commands used for processing and exporting results are not listed.

| Cmdlet | Runs against | Why |
|---|---|---|
| `Get-ConnectionInformation` | The current Exchange Online PowerShell session, when the cmdlet is available | Checks for an active connection and identifies the Exchange Online endpoint before collecting logs. |
| `Get-Mailbox` | Each mailbox supplied through `-Identity` (calendar owner, organizer, attendee, delegate, or room/resource); also used as a group-mailbox fallback when a lookup fails | Validates the collection mailboxes and reads properties such as mailbox type and `CalendarVersionStoreDisabled` to identify potentially incomplete logs. |
| `Get-CalendarDiagnosticObjects` | Each validated mailbox supplied through `-Identity` | Collects diagnostic logs for the specified meeting ID or subject to build the timeline. Also collects tracking and recurring-meeting exception logs when applicable and enabled. |
| `Get-Recipient` | Senders and responsible users referenced in the collected logs, which can include the owner or delegates | Resolves directory identities to display names and SMTP addresses so the output identifies who performed an action. This lookup does not collect those recipients' calendar logs unless they are also supplied through `-Identity`. |

## Who to collect from

Collect from **all key participants** upfront. Partial collections produce incomplete analysis.

| Participant | When to include |
|---|---|
| **Organizer** | Always — the authoritative copy |
| **Affected attendee(s)** | Always — 1–2 is usually enough |
| **Delegate(s)** | If delegates manage the organizer's or attendee's calendar |
| **Room/resource mailbox** | If the issue involves a room booking |
| **Modern Sharing partners** | If the calendar is shared via Modern Sharing |

> **Note:** Calendar diagnostic logs are start to get cleaned up after 31 days. Collect promptly.

## Parameters

Using **-MeetingID** (the `CleanGlobalObjectId`) is the preferred collection method. It produces more detailed logs than a subject search and allows collecting for multiple participants in a single run.

Using **-Subject** performs a case-insensitive substring match. Only a single `-Identity` can be used with `-Subject`. If multiple meetings match, the script creates a separate file for each match. Exception collection still runs by default only when the subject search resolves to exactly one `MeetingID`. Tracking logs still require **-MeetingID**.

| Parameter | Explanation |
|:--- |:---|
| **-Identity** | One (or more) SMTP Address of EXO User Mailbox to query. |
| **-Subject** | Subject of the meeting to query. Case-insensitive substring match. Only valid with a single Identity. |
| **-MeetingID** | The `CleanGlobalObjectId` of the meeting to query. <BR> - Preferred way to get CalLogs. |
| **-TrackingLogs** | Populate attendee tracking columns in the output. Collected by default; use `-NoTrackingLogs` to skip. <BR> - Only usable with the MeetingID parameter. |
| **-NoTrackingLogs** | Do not collect Tracking Logs. |
| **-Exceptions** | Include Exception objects in the output (exceptions are collected by default for recurring meetings unless `-NoExceptions` is used). |
| **-AllExceptions** | When using default fast exception collection, collect **all** exception dates instead of the default last 3 months. |
| **-NoExceptions** | Do not collect Exception Meetings. |
| **-ExceptionDate** | Date of a specific Exception Meeting to collect logs for. <BR> - Fastest way to get logs for a single occurrence of a recurring meeting. |
| **-ClassicExceptions** | Use the legacy per-appointment Exception collector instead of the default fast `AppointmentRecurrenceBlob`-based collector. |
| **-ExportToExcel** | Export the output to an Excel file with formatting (Default). <BR> - Creates three tabs per user (Enhanced, Raw, Timeline) plus a shared Script Info tab. <BR> - To add more users later, close the file and rerun with the new user only. |
| **-ExportToCSV** | Export the output to 3 CSV files per user instead of Excel. |
| **-CaseNumber** | Case Number to include in the Filename of the output. <BR> - Prepend `<CaseNumber>_` to filename. |
| **-ShortLogs** | Limit Logs to 500 instead of the default 2000, in case the server has trouble responding with the full logs. |
| **-MaxLogs** | Increase log limit to 12,000 in case the default 2000 does not contain the needed information. <BR> - Note: this can be time consuming and **does not contain all log types such as User Responses**. |
| **-CustomProperty** | Add custom properties to the RAW output. <BR> - Properties must be in the format of `"PropertyName1, PropertyName2, PropertyName3"`. <BR> - Properties will only be added to the RAW output. |

## Output

Filename pattern: `<CaseNumber>_CalLogSummary_<short meeting ID>.xlsx`

The Excel workbook contains the following worksheets (in tab order):

| Worksheet | Tab Color | Description |
|---|---|---|
| **\<user\>** | Orange / Green / Blue / Red | **Enhanced CalLogs** — the primary analysis source. Contains processed calendar diagnostic objects with friendly column names, color coding, and LogRowType classification. Tab color reflects the role: **Orange** = Organizer, **Green** = Room/Resource, **Blue** = Attendee. **Red** = CalLogs are disabled for this user. |
| **Script Info** | Grey | Script version, age, runtime, command line, identities processed, and any errors. Each run appends to this tab so you have a history of all collections for this meeting. |
| **\<user\>_Raw** | *(same as Enhanced)* | **Raw CalLogs** — the unprocessed calendar diagnostic data. Useful for escalations or when you need fields not in the Enhanced tab. |
| **\<user\>_TimeLine** | *(same as Enhanced)* | **Timeline** — a human-readable summary of key events for the meeting in chronological order. |

Three worksheets are created per user (Enhanced, Raw, Timeline) plus the shared Script Info tab. To add another participant after the initial run, close the Excel file and rerun the script passing in only the new user.

### Pre-filtered columns

The **LogRowType** column is pre-filtered to hide noisy row types by default:

- `OtherAssistant`
- `MeetingMessageChange`
- `DeletedSeriesException`

To see all rows, clear the filter on the LogRowType column dropdown in Excel.

---

## Syntax

Example to return timeline for a user with MeetingID:
```PowerShell
.\Get-CalendarDiagnosticObjectsSummary.ps1 -Identity user@contoso.com -MeetingID 040000008200E00074C5B7101A82E0080000000010E4301F9312D801000000000000000010000000996102014F1D484A8123C16DDBF8603E
```

Example to return timeline for a user with Subject:

```PowerShell
.\Get-CalendarDiagnosticObjectsSummary.ps1 -Identity user@contoso.com -Subject Test_OneTime_Meeting_Subject
```
Get CalLogs for 3 users:
```PowerShell
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity User1, User2, Delegate -MeetingID $MeetingID
```
Add Tracking Logs without Exceptions:
```PowerShell
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -NoExceptions
```
Skip Tracking Logs:
```PowerShell
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -NoTrackingLogs
```
Export CalLogs to Excel with a Case Number (Exceptions and Excel are both default):
```PowerShell
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -ExportToExcel -CaseNumber 123456
```
Will create file like  `.\123456_CalLogSummary_<MeetingID>.xlsx` in current directory.

Collect logs for a specific Exception date:
```PowerShell
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -ExceptionDate "01/28/2024" -CaseNumber 123456
```

Collect all recurring meeting exception dates with default fast collection:
```PowerShell
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -AllExceptions
```

Use the legacy collector instead of default fast collection:
```PowerShell
Get-CalendarDiagnosticObjectsSummary.ps1 -Identity $Users -MeetingID $MeetingID -ClassicExceptions
```

## Validate your collection

Before analyzing, verify:

- [ ] Participant worksheets exist for each participant (Enhanced, Raw, Timeline), and the shared Script Info worksheet is present
- [ ] All key participants are included (organizer, affected attendees, delegates, room mailboxes)
- [ ] LogTimestamp range covers the incident timeframe
- [ ] Response rows exist (if investigating response issues — collected by default, use `-NoTrackingLogs` to skip)
- [ ] Exception rows exist (if investigating recurring meeting issues)
- [ ] `CalendarVersionStoreDisabled` is not `True` — if True, logs are fundamentally incomplete
- [ ] Row count is not at the exact 2,000 limit — if it is, recollect with `-MaxLogs`

## Known issues

**`New-ConditionalText : The term 'New-ConditionalText' is not recognized...`**

This error occurs when the ImportExcel module conflicts with the Exchange Online session. To resolve:

1. Run `Disconnect-ExchangeOnline`
2. Close the PowerShell session and start a new one as administrator
3. Reconnect to Exchange Online and rerun the script

## More information

- [How to Get Calendar Logs](https://learn.microsoft.com/exchange/troubleshoot/calendars/cdl/get-calendar-diagnostic-logs)
- [How to Analyze Calendar Logs](https://learn.microsoft.com/exchange/troubleshoot/calendars/cdl/analyze-calendar-diagnostic-logs)
