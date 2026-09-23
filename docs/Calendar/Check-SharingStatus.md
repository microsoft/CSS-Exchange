# Check-SharingStatus

<!-- cSpell:ignore Sharee -->

Download the latest release: [Check-SharingStatus.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Check-SharingStatus.ps1)

This script validates the calendar sharing relationship between an owner and a receiver. It collects configuration and diagnostic data, identifies known issues, and provides recommended next diagnostic steps.

The script is intended to establish whether the sharing relationship is configured correctly before investigating individual meeting synchronization.

## Terminology

- **Owner** - The mailbox that owns and shares the calendar.
- **Receiver** - The mailbox that receives and opens the shared calendar.
- **Local folder** - The copy of the owner's calendar created in the receiver's mailbox for Modern Sharing.
- **Modern Sharing** - The REST-based sharing model in which Exchange synchronizes the owner's calendar to a local folder in the receiver's mailbox.
- **Old Model Sharing** - The legacy MAPI-based model in which the client connects directly to the owner's mailbox.

## Requirements

- An Exchange Online PowerShell session.
- Permission to query both mailboxes and their calendar configuration.
- PII access for the mailbox databases when pair-specific folder names or recipients are redacted.
- The `Get-CalendarActiveSharingInformation` and `Get-CalendarEntries` cmdlets provide additional validation when they are available in the current session.

Unavailable cmdlets, inaccessible data, and non-mailbox-name redacted evidence are reported under **Incomplete Checks** rather than being treated as proof that the sharing relationship is unhealthy. A redacted Owner or Receiver mailbox name is a fatal prerequisite failure because folder selection and correlation cannot proceed reliably.

## Usage

### Syntax

```powershell
.\Check-SharingStatus.ps1 -Owner <String> -Receiver <String> [-OwnerCalendarFolderPath <String>] [-ModernSharingOnly <Boolean>] [-IncludeSensitiveData]
```

### Parameters

| Parameter | Description |
| --- | --- |
| `Owner` | Mailbox that owns and shares the calendar. |
| `Receiver` | Mailbox that receives the shared calendar. |
| `OwnerCalendarFolderPath` | Optional owner-mailbox-relative calendar folder path. Slash and backslash separators and an optional leading separator are accepted. Do not include a mailbox identity prefix. When omitted, the folder whose `FolderType` is `Calendar` is selected. |
| `ModernSharingOnly` | Defaults to `$true`. Set to `$false` to include Old Model Sharing entries and Internet Calendar information. |
| `IncludeSensitiveData` | Retains full-fidelity values in structured in-memory findings and errors. Console output is always full fidelity. |

The default owner calendar is selected when `-OwnerCalendarFolderPath` is omitted:

```powershell
.\Check-SharingStatus.ps1 -Owner owner@contoso.com -Receiver receiver@contoso.com
```

To inspect a nested owner calendar, provide only its owner-mailbox-relative path:

```powershell
.\Check-SharingStatus.ps1 -Owner owner@contoso.com -Receiver receiver@contoso.com -OwnerCalendarFolderPath "Calendar\Project Calendar"
```

`Calendar\Project Calendar`, `/Calendar/Project Calendar`, and `\Calendar\Project Calendar` identify the same folder. A full mailbox-folder identity such as `owner@contoso.com:\Calendar\Project Calendar` is rejected. The requested path must match exactly one Calendar-scope folder; the script does not fall back to the default calendar when the requested path is missing or ambiguous.

Exchange may report a user-created Calendar-scope folder as `/Project Calendar` in `Get-MailboxFolderStatistics`, omitting the default Calendar segment. The public parameter remains Calendar-relative (`Calendar\Project Calendar`). The script uses the mailbox's default `FolderType Calendar` name as the identity root and accepts either `/Project Calendar` or `/Calendar/Project Calendar` from folder statistics when both identify the same exact path.

When a selected subfolder is requested, receiver folder matching, sharing entries, and accept-log output are scoped to that selected calendar name. Other calendars shared by the same owner do not satisfy the selected-calendar checks.

By default, the script focuses on Modern Sharing. To include Old Model Sharing entries and Internet Calendar publishing/subscription information:

```powershell
.\Check-SharingStatus.ps1 -Owner owner@contoso.com -Receiver receiver@contoso.com -ModernSharingOnly $false
```

The detailed console output always contains full-fidelity values. Structured diagnostic evidence is privacy-safe by default. To retain full-fidelity values in the structured in-memory findings and error records:

```powershell
.\Check-SharingStatus.ps1 -Owner owner@contoso.com -Receiver receiver@contoso.com -IncludeSensitiveData
```

`-IncludeSensitiveData` does not change the console output. It controls only the structured diagnostic records intended for later programmatic output.

## What the script validates

### Owner

- Mailbox information and Send-on-Behalf grants.
- Selected calendar folder statistics and permissions. The selected folder is the default calendar unless `-OwnerCalendarFolderPath` is supplied.
- Selected calendar size greater than 1 GB.
- Selected calendar item count greater than 100,000 visible items.
- Whether the selected owner-side folder is itself a shared copy owned by another mailbox. If it belongs to the supplied receiver, the script reports that Owner and Receiver appear reversed.
- Sharing invite logs for the specified receiver.
- Modern Sharing folder flags, including `SharedOut` and `ExchangeShareFolder`.
- The specified receiver's active sharing relationship.
- Non-default `ActiveShareeFlags`.

### Receiver

- Mailbox information and the likely sharing type.
- The local folder corresponding to the selected owner calendar.
- Missing, duplicate, or numerically suffixed local folders.
- Accepted sharing invite logs.
- Pair-specific New and Old sharing-model entries.
- Orphaned sharing entries.
- Local folder flags, including `SharedIn` and `ExchangeShareFolder`.
- `CalendarSharingOwnerSmtpAddress`.
- Owner, receiver-folder, and active-sharing permission consistency.
- A visible-item and folder-size comparison between the selected owner calendar and the uniquely matched receiver local folder.
- Periodic synchronization timestamps.
- `SharedCalendarSyncStartDate`.

### Owner and receiver statistics comparison

After the receiver folder is matched, the script always displays the selected owner and receiver values for `VisibleItemsInFolder` and `FolderAndSubfolderSize`, together with the receiver-minus-owner delta and receiver-to-owner ratio. `FolderSize` is used only when `FolderAndSubfolderSize` is unavailable. A metric that cannot be converted is displayed as unavailable and its corresponding rule is reported as `NotEvaluated`.

The comparison adds these asymmetric warning rules:

- `SHR432` is detected only when the receiver has more visible items than the owner, has at least twice the owner's visible-item count, and exceeds the owner by at least 100 items.
- `SHR433` is detected only when the receiver is larger than the owner, is at least twice the owner's size, and exceeds the owner by at least 1 MiB (1,048,576 bytes).

An owner calendar that is larger than the receiver copy does not trigger either warning. That direction is informational because the receiver synchronization window may be bounded by `SharedCalendarSyncStartDate` and may contain only the last year's data.

When `-ModernSharingOnly $false` is used, the script also displays Old Model Sharing entries and Internet Calendar subscription information.

## Understanding the summary

Before detailed diagnostics, the script resolves these fatal prerequisites in order:

1. Owner mailbox.
2. Owner mailbox name and PII availability.
3. Receiver mailbox.
4. Receiver mailbox name and PII availability.
5. Requested or default selected owner calendar folder.
6. Ownership of the selected owner calendar folder.

Mailbox results are cached and reused by the detailed diagnostics. If a prerequisite fails, the script stops before dependent invite, accept, calendar-entry, receiver-folder, synchronization, and comparison checks.

The final console displays a red **Fatal prerequisite failure** section containing only the root `SHR100`, `SHR101`, `SHR200`, `SHR201`, `SHR110`, or `SHR123` finding. A confirmed mailbox lookup with no object or confirmed mailbox-name redaction is `Detected`; an exception or unavailable prerequisite is `NotEvaluated`. Every non-root rule remains present in the structured all-rules contract as `NotApplicable` with a bounded skip reason. The fatal summary does not claim that the sharing relationship is healthy or that it uses Modern Sharing.

When all prerequisites succeed, the script retains the detailed command output and ends with three normal summary areas.

### Sharing status

The first section reports the detected sharing type and whether the available evidence indicates that the backend is using Modern Calendar Sharing.

### Detected Issues

Confirmed findings are sorted by severity and contain:

| Field | Description |
| --- | --- |
| `severity` | Relative importance of the finding: `Critical`, `Error`, `Warning`, or `Information`. |
| `ruleId` | Stable identifier for the diagnostic rule, such as `SHR121`. |
| `title` | A concise description of the detected condition. |
| `evidence` | The values or observations supporting the finding. |
| `recommendedNextStep` | The next diagnostic action to take. |

Each implemented rule is represented exactly once in the structured diagnostic model. The console displays only rules whose status is `Detected`.

### Incomplete Checks

This section displays rules whose status is `NotEvaluated`, together with collection or evaluation failures. Common reasons include:

- A required cmdlet is unavailable.
- A cmdlet failed or returned no data.
- Non-mailbox-name evidence needed by a detailed check is redacted.
- A receiver local folder could not be matched uniquely.
- Owner or receiver calendar statistics required for comparison are unavailable or cannot be converted.
- A timestamp or diagnostic log could not be parsed.

Do not consider the relationship healthy until relevant incomplete checks have been resolved. An incomplete check is not, by itself, a confirmed sharing failure.

## Structured diagnostic model

The script maintains structured findings in memory for later automation and JSON support. It does not write a JSON file in the current version.

Every finding contains:

| Property | Description |
| --- | --- |
| `ruleId` | Stable `SHRxxx` identifier. |
| `severity` | `Critical`, `Error`, `Warning`, or `Information`. |
| `status` | `Detected`, `NotDetected`, `NotEvaluated`, or `NotApplicable`. |
| `title` | Stable rule title. |
| `evidence` | Structured evidence associated with the rule. |
| `recommendedNextStep` | Suggested next diagnostic action. |

The rule ranges identify the diagnostic area:

| Rule range | Area |
| --- | --- |
| `SHR1xx` | Owner mailbox and calendar configuration |
| `SHR2xx` | Receiver mailbox and local-folder configuration |
| `SHR3xx` | Owner/receiver sharing relationship |
| `SHR4xx` | Synchronization and calendar performance |

Rule statuses have the following meanings:

- `Detected` - The collected evidence confirms the condition.
- `NotDetected` - The rule was evaluated and the condition was not present.
- `NotEvaluated` - Required evidence was unavailable or evaluation failed.
- `NotApplicable` - The rule does not apply to the selected scenario or parameters.

The script also maintains:

- Collector status for each independent Exchange data source.
- Collection errors for failures while retrieving evidence.
- Evaluation errors for failures while interpreting collected evidence.

Collection failures do not become confirmed configuration problems. Instead, the affected rules are marked `NotEvaluated`.

### Privacy behavior

Structured evidence is sanitized by default:

- The requested mailboxes use stable owner and receiver placeholders.
- Other identities receive deterministic generic placeholders.
- Folder names, folder paths, publishing URLs, and unbounded remote diagnostic details are omitted or replaced.
- Error text is bounded and remote diagnostic internals are not retained.

Use `-IncludeSensitiveData` only when full-fidelity structured evidence is required. Regardless of this switch, treat the normal console output as sensitive because it preserves the detailed Exchange output.

## Synchronization results

`LastAttemptedSyncTime` and `LastSuccessfulSyncTime` describe periodic synchronization by the sharing assistant. They do not directly measure Modern Sharing instant-sync latency.

- Equal, recent timestamps indicate that the latest periodic synchronization attempt succeeded.
- Different timestamps indicate that the latest periodic attempt did not succeed.
- If both timestamps are more than 24 hours old, the script reports periodic synchronization as stale.
- If either timestamp is missing, synchronization health is reported as incomplete.
- Exchange can return year-1 `DateTime` sentinel values for uninitialized synchronization properties. If both periodic synchronization timestamps have year 1, `SHR403` reports that the selected receiver calendar appears never to have synchronized. These values are not classified as stale dates.
- If only one periodic synchronization timestamp has year 1, it is treated as unavailable and synchronization health remains incomplete.

For a specific missing or delayed meeting, collect Calendar Diagnostic Logs from both the owner and receiver. Use [Get-CalendarDiagnosticObjectsSummary](./Get-CalendarDiagnosticObjectsSummary.md) and correlate the same meeting by its `CleanGlobalObjectId`.

`SharedCalendarSyncStartDate` controls how far back calendar data is synchronized to the receiver's local folder. A recent value may indicate that the folder was recreated or is still backfilling; it does not prove that synchronization failed. A year-1 value is an uninitialized sentinel, is handled by the existing unavailable start-date rule, and is never displayed as a valid data-back boundary.

## Troubleshooting workflow

1. Confirm the owner, receiver, and sharing type.
2. Resolve any red **Fatal prerequisite failure** before interpreting dependent checks.
3. Review **Detected Issues** from highest to lowest severity.
4. Resolve or collect the data required by **Incomplete Checks**.
5. Follow each finding's `RecommendedNextStep`.
6. If the configuration is healthy but an individual meeting is missing or delayed, collect Calendar Diagnostic Logs from both mailboxes.

The script recommends diagnostic actions such as reviewing sharing invite/accept logs, Sharing Sync Assistant logs, or calendar validation data. Avoid removing and re-adding permissions or shared calendars as a generic first troubleshooting step.
