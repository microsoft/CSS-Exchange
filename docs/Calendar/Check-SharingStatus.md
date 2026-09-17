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

Unavailable cmdlets, inaccessible data, and redacted information are reported under **Incomplete Checks** rather than being treated as proof that the sharing relationship is unhealthy.

## Usage

```powershell
.\Check-SharingStatus.ps1 -Owner owner@contoso.com -Receiver receiver@contoso.com
```

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
- Default calendar folder statistics and permissions.
- Calendar size greater than 1 GB.
- Calendar item count greater than 100,000 visible items.
- Sharing invite logs for the specified receiver.
- Modern Sharing folder flags, including `SharedOut` and `ExchangeShareFolder`.
- The specified receiver's active sharing relationship.
- Non-default `ActiveShareeFlags`.

### Receiver

- Mailbox information and the likely sharing type.
- The local folder corresponding to the owner.
- Missing, duplicate, or numerically suffixed local folders.
- Accepted sharing invite logs.
- Pair-specific New and Old sharing-model entries.
- Orphaned sharing entries.
- Local folder flags, including `SharedIn` and `ExchangeShareFolder`.
- `CalendarSharingOwnerSmtpAddress`.
- Owner, receiver-folder, and active-sharing permission consistency.
- Periodic synchronization timestamps.
- `SharedCalendarSyncStartDate`.

When `-ModernSharingOnly $false` is used, the script also displays Old Model Sharing entries and Internet Calendar subscription information.

## Understanding the summary

The script retains the detailed command output and ends with three summary areas.

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
- PII is redacted.
- A receiver local folder could not be matched uniquely.
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

For a specific missing or delayed meeting, collect Calendar Diagnostic Logs from both the owner and receiver. Use [Get-CalendarDiagnosticObjectsSummary](./Get-CalendarDiagnosticObjectsSummary.md) and correlate the same meeting by its `CleanGlobalObjectId`.

`SharedCalendarSyncStartDate` controls how far back calendar data is synchronized to the receiver's local folder. A recent value may indicate that the folder was recreated or is still backfilling; it does not prove that synchronization failed.

## Troubleshooting workflow

1. Confirm the owner, receiver, and sharing type.
2. Review **Detected Issues** from highest to lowest severity.
3. Resolve or collect the data required by **Incomplete Checks**.
4. Follow each finding's `RecommendedNextStep`.
5. If the configuration is healthy but an individual meeting is missing or delayed, collect Calendar Diagnostic Logs from both mailboxes.

The script recommends diagnostic actions such as reviewing sharing invite/accept logs, Sharing Sync Assistant logs, or calendar validation data. Avoid removing and re-adding permissions or shared calendars as a generic first troubleshooting step.
