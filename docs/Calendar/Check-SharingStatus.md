# Check-SharingStatus

<!-- cSpell:ignore Sharee -->

Download the latest release: [Check-SharingStatus.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Check-SharingStatus.ps1)

This script validates the calendar sharing relationship between an owner and a receiver. It collects configuration and diagnostic data, identifies known issues, and provides recommended next diagnostic steps.

The script is intended to establish whether the sharing relationship is configured correctly before investigating individual meeting synchronization.

## Source layout

The development entry script loads sharing-specific path and identity utilities from `Calendar/Helpers` and output functions from `Calendar/Writers`. Permission identity and error normalization use the same `Calendar/CalendarHelpers/CalendarDiagnosticHelpers.ps1` infrastructure as RBA diagnostics. Sharing-specific error redaction, finding schemas, and collection failure behavior remain unchanged. The release build embeds the dependencies into the standalone script; users do not need to download the helper files separately.

## Terminology

- **Owner** - The mailbox that owns and shares the calendar.
- **Receiver** - The mailbox that receives and opens the shared calendar.
- **Local folder** - The copy of the owner's calendar created in the receiver's mailbox for Modern Sharing.
- **Modern Sharing** - The REST-based sharing model in which Exchange synchronizes the owner's calendar to a local folder in the receiver's mailbox.
- **Old Model Sharing** - The legacy MAPI-based model in which the client connects directly to the owner's mailbox.
- **Published Calendar** - An Internet Calendar subscription in which the owner exposes an ICS URL and the receiver stores a local subscription folder.

## Requirements

- An Exchange Online PowerShell session with permission to query both mailboxes and their calendar configuration. Use primary SMTP addresses for both mailboxes.
- Access to `Get-Mailbox`, `Get-MailboxFolderStatistics`, and `Get-MailboxCalendarFolder` for the prerequisite checks.
- Access to `Get-MailboxFolderPermission`, `Get-MailboxPermission`, and `Export-MailboxDiagnosticLogs` for permission and log checks.
- Readable personally identifiable information (PII), including mailbox and folder names, for pair-specific correlation.

The following diagnostic cmdlets affect how much the script can determine:

| Cmdlet | Purpose and availability impact |
| --- | --- |
| `Get-CalendarActiveSharingInformation` | Validates the receiver's active sharing relationship and flags. If unavailable, the dependent checks are incomplete. |
| `Get-CalendarEntries` | Queries New and Old sharing-model entries and enables legacy MAPI and Published Calendar classification. If the cmdlet is unavailable in the session, those classifications do not run, and the script cannot reliably distinguish those scenarios from missing Modern Sharing evidence. |

Cmdlet availability and access to diagnostic properties depend on the session and permissions. Do not assume that a tenant administrator role exposes every diagnostic cmdlet or makes every property readable. If a required cmdlet is not exposed, or values remain redacted, involve Microsoft Support to obtain the appropriate diagnostic access or complete the affected checks.

A mailbox lookup or selected-owner-calendar prerequisite failure stops dependent diagnostics and produces a **Fatal prerequisite failure** summary. Redacted owner or receiver mailbox names also cause a fatal stop.

After those prerequisites succeed, unavailable evidence generally appears under **Incomplete Checks**. Receiver folder-name redaction is a specific exception: it produces a nonfatal **Detected `SHR201`** warning, while checks that depend on readable folder names can remain incomplete. This warning identifies an access limitation, not proof that calendar sharing is broken.

## Usage

### Quick start

**Privacy warning:** Console output always contains full-fidelity mailbox and diagnostic values, potentially including other recipients and published-calendar URLs. Treat the output, transcripts, and screenshots as sensitive, even when `-IncludeSensitiveData` is not used.

Check the default owner calendar:

```powershell
.\Check-SharingStatus.ps1 -Owner owner@contoso.com -Receiver receiver@contoso.com
```

Check a nested owner calendar by supplying its owner-mailbox-relative path:

```powershell
.\Check-SharingStatus.ps1 -Owner owner@contoso.com -Receiver receiver@contoso.com -OwnerCalendarFolderPath "Calendar\Project Calendar"
```

Start with the final summary. Resolve any fatal prerequisite failure, then review **Detected Issues** and **Incomplete Checks** before interpreting the detailed command output.

### Syntax

```powershell
.\Check-SharingStatus.ps1 -Owner <String> -Receiver <String> [-OwnerCalendarFolderPath <String>] [-IncludeSensitiveData]
```

### Parameters

| Parameter | Description |
| --- | --- |
| `Owner` | Primary SMTP address of the mailbox that owns and shares the calendar. |
| `Receiver` | Primary SMTP address of the mailbox that receives the shared calendar. |
| `OwnerCalendarFolderPath` | Optional owner-mailbox-relative calendar folder path. Slash and backslash separators and an optional leading separator are accepted. Do not include a mailbox identity prefix. When omitted, the folder whose `FolderType` is `Calendar` is selected. |
| `IncludeSensitiveData` | Retains full-fidelity values in structured in-memory findings and errors. Console output is always full fidelity. |

### Selecting an owner calendar folder

`Calendar\Project Calendar`, `/Calendar/Project Calendar`, and `\Calendar\Project Calendar` identify the same folder. A full mailbox-folder identity such as `owner@contoso.com:\Calendar\Project Calendar` is rejected. The requested path must match exactly one Calendar-scope folder; the script does not fall back to the default calendar when the requested path is missing or ambiguous.

Exchange may report a user-created Calendar-scope folder as `/Project Calendar` in `Get-MailboxFolderStatistics`, omitting the default Calendar segment. The public parameter remains Calendar-relative (`Calendar\Project Calendar`). The script uses the mailbox's default `FolderType Calendar` name as the identity root and accepts either `/Project Calendar` or `/Calendar/Project Calendar` from folder statistics when both identify the same exact path.

When a selected subfolder is requested, receiver folder matching, pair-specific sharing-entry checks, and accept-log output are scoped to that selected calendar name. Other calendars shared by the same owner do not satisfy the selected-calendar checks. The detailed New Model Calendar Sharing Entries table can still include entries for other calendars.

## Understanding the summary

### Fatal prerequisite failure

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

The first section reports the sharing type and whether the available backend evidence indicates Modern Calendar Sharing, legacy MAPI sharing, or a published Internet Calendar subscription. If the evidence is insufficient, the model is reported as undetermined.

Backend Modern Sharing evidence does not establish which sharing model a particular client is using or measure instant-sync latency.

### Detected Issues

Confirmed findings are sorted by severity and contain:

| Field | Description |
| --- | --- |
| `severity` | Relative importance of the finding: `Critical`, `Error`, `Warning`, or `Information`. |
| `ruleId` | Stable identifier for the diagnostic rule, such as `SHR121`. |
| `title` | A concise description of the detected condition. |
| `evidence` | The values or observations supporting the finding. |
| `recommendedNextStep` | The next diagnostic action to take. |

The **Detected Issues** section displays only rules whose status is `Detected`. Recommended next steps are printed below the findings table.

A detected condition is not always a confirmed synchronization failure. For example, receiver folder-name redaction produces a nonfatal `SHR201` access warning, and a recent synchronization start date produces informational context.

### Incomplete Checks

This section displays rules whose status is `NotEvaluated`, together with collection or evaluation failures. Common reasons include:

- A required cmdlet is unavailable.
- A cmdlet failed or returned no data.
- Redacted receiver folder names prevent dependent folder checks.
- A receiver local folder could not be matched uniquely.
- Owner or receiver calendar statistics required for comparison are unavailable or cannot be converted.
- A timestamp or diagnostic log could not be parsed.

Do not consider the relationship healthy until relevant incomplete checks have been resolved. An incomplete check is not, by itself, a confirmed sharing failure.

## What the script validates

### Owner

- Mailbox information and Send-on-Behalf grants.
- Selected calendar folder statistics and permissions. The selected folder is the default calendar unless `-OwnerCalendarFolderPath` is supplied.
- A receiver-specific permission summary across the owner calendar folder and owner mailbox. If no direct receiver entry exists, the output notes that access may come from the `Default` entry or a group.
- Selected calendar size greater than 1 GB (1,000,000,000 bytes).
- Selected calendar item count greater than 100,000 visible items.
- Calendar folders whose names end in a one- or two-digit numeric suffix such as `(1)` or `(12)`.
- Whether the selected owner-side folder is itself a shared copy owned by another mailbox. If it belongs to the supplied receiver, the script reports that Owner and Receiver appear reversed.
- Sharing invite logs for the specified receiver.
- Modern Sharing folder flags, including `SharedOut` and `ExchangeShareFolder`.
- The specified receiver's active sharing relationship.
- Non-default `ActiveShareeFlags`.

### Receiver

- Mailbox information and the likely sharing type.
- The local folder corresponding to the selected owner calendar.
- Missing or duplicate local folders.
- Calendar folders whose names end in a one- or two-digit numeric suffix such as `(1)` or `(12)`.
- Redacted receiver folder names, with guidance to obtain more access before matching the owner's calendar.
- Accepted sharing invite logs.
- Pair-specific New and Old sharing-model entries.
- Orphaned sharing entries.
- Local folder flags, including `SharedIn` and `ExchangeShareFolder`.
- `CalendarSharingOwnerSmtpAddress`.
- Owner, receiver-folder, and active-sharing permission consistency.
- A visible-item comparison between the selected owner calendar and the uniquely matched receiver local folder.
- Periodic synchronization timestamps.
- `SharedCalendarSyncStartDate`.

### Sharing models and published calendars

The script evaluates the available Modern Sharing and pair-specific legacy MAPI evidence automatically; no sharing-model switch is required. Legacy MAPI and Published Calendar classification requires `Get-CalendarEntries` to be available, as described under **Requirements**.

Pair-specific Old-model entries are displayed automatically when present, including when New-model entries also exist.

For internal relationships classified as legacy MAPI sharing, the script reports Modern-only rules as `NotApplicable`, displays any pair-specific Old-model entries, and recommends upgrading by following [Calendar sharing in Microsoft 365](https://support.microsoft.com/en-us/outlook/calendar-sharing-in-microsoft-365). A Modern Sharing local receiver folder is not expected for this model.

InternetCalendar information is collected only when the selected owner calendar has `PublishEnabled` set. When the relationship is classified as Published Calendar rather than Modern Sharing, the script compares the owner's `PublishedICalUrl` with the receiver's InternetCalendar subscriptions and checks for the matching local receiver folder. Modern-only rules are reported as `NotApplicable`.

| Rule | Published Calendar finding |
| --- | --- |
| `SHR421` | No receiver subscription matches the owner's `PublishedICalUrl`. |
| `SHR422` | A matching subscription exists, but its local receiver calendar folder is missing. |
| `SHR423` | Publishing is enabled, but the owner's `PublishedICalUrl` is unavailable. |

Publishing being enabled does not by itself establish that this receiver uses a published subscription.

### Duplicate-style folder names

Owner and receiver naming checks flag terminal one- or two-digit numeric suffixes such as `Calendar (1)` or `Calendar (12)`. These names suggest possible duplicates; confirm folder identifiers and sharing entries before making changes.

Names containing parentheses elsewhere, such as `CUB01-3 McKinley (16-32) Public`, and names ending in three or more digits, such as `Archive (123)`, do not trigger duplicate-style folder warnings.

### Accept-log history

The receiver accept-log parser uses timestamped calendar-creation entries, not references to sharing methods in diagnostic stack traces.

The displayed history normally includes only entries from the last **180 days**. By default, it can include calendars from other owners; when `-OwnerCalendarFolderPath` is supplied, it is filtered by both the expected owner and the selected calendar name.

If timestamp parsing fails, the script reports an incomplete accept-log check (`SHR220`) and displays the selected entries without the date filter. An empty recent-history table is not proof that a calendar was never accepted.

### Owner and receiver statistics comparison

For Modern Sharing checks, after a receiver folder is matched, the script displays the selected owner and receiver values for `VisibleItemsInFolder`, together with the receiver-minus-owner delta and receiver-to-owner ratio. A count that cannot be converted is displayed as unavailable and its corresponding rule is reported as `NotEvaluated`. The ratio is unavailable when the owner count is zero.

`SHR432` is detected only when the receiver has more visible items than the owner, has at least twice the owner's visible-item count, and exceeds the owner by at least 100 items. If the owner count is zero, a receiver count of at least 100 meets the warning criteria.

An owner calendar with more visible items than the receiver copy does not trigger this warning. That direction is informational because the receiver synchronization window may be bounded by `SharedCalendarSyncStartDate` and may contain only the last year's data.

## Synchronization results

### Periodic synchronization

`LastAttemptedSyncTime` and `LastSuccessfulSyncTime` describe periodic synchronization by the sharing assistant. They do not directly measure Modern Sharing instant-sync latency.

Exchange can return year-1 `DateTime` sentinel values for uninitialized properties. The script applies the following classifications in order:

| Condition | Interpretation |
| --- | --- |
| Both timestamps have year 1 | `SHR403`: the selected receiver calendar appears never to have synchronized. The values are not treated as stale dates. |
| Either timestamp is missing or cannot be parsed, or only one has year 1 | `SHR401`: periodic synchronization health is incomplete. |
| Both valid timestamps are more than 24 hours old | `SHR400`: periodic synchronization is stale, even if the timestamps differ. The failed-attempt rule is not also detected. |
| Both valid timestamps are equal and are not both stale | The latest periodic synchronization attempt succeeded. |
| Both valid timestamps differ and are not both stale | `SHR402`: the latest periodic synchronization attempt did not succeed. |

### Synchronization start date

`SharedCalendarSyncStartDate` controls how far back calendar data is synchronized to the receiver's local folder. The script evaluates it separately from periodic synchronization health:

| Rule | Condition and meaning |
| --- | --- |
| `SHR413` | A null or year-1 start date is unavailable. A year-1 value is never displayed as a valid data-back boundary. |
| `SHR410` | A non-null value other than a year-1 sentinel cannot be interpreted as a date. The check is incomplete. |
| `SHR411` | The start date is later than the local folder's `CreationTime`. This is a warning to investigate whether backfill was restarted. If the start date is valid but `CreationTime` cannot be parsed, this check is incomplete. |
| `SHR412` | The start date is newer than the 24-hour cutoff. This is informational context that may reflect backfill or folder recreation, not proof of a synchronization failure. |

When the calendar appears never to have synchronized (`SHR403`), the start-date comparisons are skipped. A null or year-1 start date can still produce `SHR413`.

## Troubleshooting workflow

1. Confirm the owner, receiver, and sharing type.
2. Resolve any red **Fatal prerequisite failure** before interpreting dependent checks.
3. Review **Detected Issues** from highest to lowest severity.
4. Resolve or collect the data required by **Incomplete Checks**.
5. Follow each finding's `RecommendedNextStep`.
6. If the configuration is healthy but an individual meeting is missing or delayed, collect Calendar Diagnostic Logs from both mailboxes. Use [Get-CalendarDiagnosticObjectsSummary](./Get-CalendarDiagnosticObjectsSummary.md) and correlate the same meeting by its `CleanGlobalObjectId`.
7. If required checks cannot be completed in your session, or the next step calls for assistant or calendar-sharing validator diagnostics you cannot access, involve Microsoft Support. Provide the identities and selected calendar path used, relevant rule IDs, incomplete-check reasons, and diagnostic output through an approved support channel.

The script recommends diagnostic actions such as reviewing sharing invite/accept logs, Sharing Sync Assistant logs, or calendar validation data. Treat these as diagnostic recommendations, not commands guaranteed to be available in every tenant administrator session.

Avoid removing and re-adding permissions or shared calendars as a generic first troubleshooting step. Follow a specific remediation only after confirming the relevant finding; for example, `SHR422` recommends re-adding a published subscription whose local folder is missing.

## Structured diagnostic model

This advanced reference describes the structured findings maintained in memory for later automation and JSON support. The script does not write a JSON file in the current version.

Each implemented rule is represented exactly once in the structured diagnostic model. Every finding contains:

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

To retain full-fidelity values in the structured in-memory findings and error records:

```powershell
.\Check-SharingStatus.ps1 -Owner owner@contoso.com -Receiver receiver@contoso.com -IncludeSensitiveData
```

Use `-IncludeSensitiveData` only when full-fidelity structured evidence is required. It does not change console output. Regardless of this switch, treat the normal console output as sensitive because it preserves the detailed Exchange output.
