# Get-RBASummary

Download the latest release: [Get-RBASummary.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-RBASummary.ps1)

Download the adjacent analysis skill: [EXO-RBA-Troubleshooting-SKILL.md](https://github.com/microsoft/CSS-Exchange/releases/latest/download/EXO-RBA-Troubleshooting-SKILL.md)

`Get-RBASummary.ps1` collects Resource Booking Assistant (RBA) configuration and recent processing evidence for one room, equipment, or Workspace mailbox. It produces a readable text summary and a structured JSON report that can be analyzed with the adjacent EXO RBA troubleshooting skill.

The script validates mailbox type, booking policy, request routing, delegate configuration, post-processing, room properties, permissions, and recent RBA log activity. It first resolves the identity with `Get-Mailbox`, including a targeted soft-deleted-mailbox fallback. Collection stops if no mailbox is resolved or the resolved object is not a room or equipment mailbox. After this prerequisite validation, collection is best effort: it independently attempts `Get-Place`, `Get-InboxRule`, `Get-CalendarProcessing`, Calendar and mailbox permissions, and `Export-MailboxDiagnosticLogs`. If one of those collectors fails, the remaining collectors still run and evaluations that require unavailable evidence are safely skipped.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 or later.
- The Exchange Online PowerShell module and an active `Connect-ExchangeOnline` session.
- Permission to read the target mailbox, CalendarProcessing configuration, mailbox diagnostic logs, and applicable permissions.
- A room or equipment mailbox. Workspace-specific validation applies when the mailbox resource type is `Workspace`.

## Syntax

```powershell
.\Get-RBASummary.ps1 -Identity <ResourceMailbox> [-Subject <String> | -MeetingId <String>] [-IncludeSensitiveData] [-SkipVersionCheck] [-Verbose]
```

| Parameter | Required | Description |
|---|---|---|
| `Identity` | Yes | Resource mailbox identity. An SMTP address is recommended. |
| `Subject` | No | Case-insensitive literal subject substring used to discover meeting IDs. After discovery, only blocks carrying those IDs are correlated. This adds sensitive meeting evidence to the JSON report. The former `MeetingSubject` name remains available as an alias. Cannot be combined with `MeetingId`. |
| `MeetingId` | No | Clean global object ID used to select all matching retained RBA processing blocks directly. A comma in the documented `040000008,` prefix is normalized. Cannot be combined with `Subject`. |
| `IncludeSensitiveData` | No | Includes full identities, target mailbox identifiers, the complete RBA log, and the text transcript in JSON. |
| `SkipVersionCheck` | No | Skips the automatic script update check. |
| `Verbose` | No | Displays additional policy and post-processing explanations. |

Examples:

```powershell
# Standard sanitized report
.\Get-RBASummary.ps1 -Identity Room1@Contoso.com

# Include verbose policy explanations
.\Get-RBASummary.ps1 -Identity Room1@Contoso.com -Verbose

# Collect targeted evidence for one meeting subject
.\Get-RBASummary.ps1 -Identity Room1@Contoso.com -Subject "Quarterly planning"

# Re-run targeted analysis directly with the meeting ID discovered above
.\Get-RBASummary.ps1 -Identity Room1@Contoso.com -MeetingId "04000000800E00074C5A7101A82E00700000000..."

# Include all sensitive evidence
.\Get-RBASummary.ps1 -Identity Room1@Contoso.com -IncludeSensitiveData
```

## Output files

Every run that passes the script update self-check attempts to create timestamp-correlated text and JSON reports. The text transcript and JSON metadata record a canonical command line with the resolved values of every supplied parameter. The JSON report also contains a schema version, collection status, per-collector status, collection errors, minimal configuration and log-summary evidence, and findings with stable rule IDs. A status of `Partial` or `Failed` means the collection errors and `NotEvaluated` findings should be reviewed before drawing conclusions. `NotApplicable` means that evidence was available but the rule does not apply to the resource or its routing configuration.

A collector is successful only when collection and its immediate evidence processing both finish successfully. If processing fails after evidence was retrieved, that collector is marked `Failed`, the overall status cannot be `Complete`, and other successfully collected evidence remains in the report. Collector and evaluation errors retain their existing `error` or `message` strings and include bounded `exceptionType`, `category`, `fullyQualifiedErrorId`, and `innerExceptionMessage` metadata when available. Stack traces, invocation details, target objects, and remote position details are not exported.

Output is written to the current working directory. All files from one run share the same timestamp.

| File | Contents |
|---|---|
| `RBA-Summary-For_<mailbox-name>_<yyyy-MM-dd_HH-mm-ss>.txt` | Human-readable transcript and configuration summary. |
| `RBA-Summary-For_<mailbox-name>_<yyyy-MM-dd_HH-mm-ss>.json` | Structured evidence, collector status, errors, and stable findings for skill analysis. |
| `RBA-Logs_<mailbox-name>_<yyyy-MM-dd_HH-mm-ss>.txt` | Readable retained RBA diagnostic log when log evidence is available. |

For example, running the script for `Room1@Contoso.com` creates a filename similar to `RBA-Summary-For_Room1_2026-08-28_15-42-10.json`. The timestamp matches the associated text summary produced by the same run.

The JSON uses schema version `1.0-preview` and records an overall `Complete`, `Partial`, or `Failed` collection status. Review `collectors`, `collectionErrors`, `evaluationErrors`, and `NotEvaluated` findings before drawing conclusions from a partial report. `NotApplicable` means that evidence was available but the finding does not apply to the resource or routing configuration.

## Privacy modes

The report identifies its handling mode in `metadata.privacyMode`:

| Mode | Trigger | Included evidence |
|---|---|---|
| `Sanitized` | Default | Keeps the target mailbox identity and summary but replaces other identities with placeholders. Omits complete logs, transcript content, stable identifiers, and sensitive response text. |
| `TargetedMeeting` | `-Subject` or `-MeetingId` without `-IncludeSensitiveData` | Adds only RBA blocks correlated by an extracted or supplied meeting ID. If a subject matches but has no extractable ID, only its matching blocks are added. These blocks can contain subjects, identities, and processing details. |
| `Full` | `-IncludeSensitiveData` | Adds full identities, target proxy addresses and stable identifiers, complete RBA log, transcript content, and additional response text. |

Treat `TargetedMeeting` and `Full` reports as sensitive customer data.

## Targeted meeting log search

With `-Subject`, the script searches the retained RBA log, extracts meeting IDs from matching processing blocks, and then switches to meeting-ID correlation. Once at least one ID is discovered, only retained blocks carrying those IDs are included; an additional subject-only block is not treated as the same meeting. If a subject resolves to multiple IDs, the text output reports each meeting independently and warns the operator to rerun with `-MeetingId` for focused analysis. The JSON `meetings` array likewise contains one outcome summary per ID; do not treat the top-level targeted counts as one meeting in that case. With `-MeetingId`, discovery is skipped and all retained blocks carrying the supplied ID are selected directly. The text summary states whether the requested meeting was found and prints every resolved ID so it can be reused with `-MeetingId` or downstream Calendar Diagnostic Log tools.

The decoder recognizes the existing ID labels plus the exact `Begin ProcessRequest Goid:` and `Begin ProcessUpdateRequest Goid:` formats. For correlation, it normalizes the documented comma after the `040000008` GOID prefix; the complete unchanged source line remains in the raw block. This allows the skill to follow separate initial request, update, and cancellation processing even when later blocks omit the subject. If the same subject resolves to multiple meeting IDs, their timelines remain separate.

Exported RBA logs are newest-first: the newest result or END lines are at the top, and a processing unit's oldest START line is at the bottom. Because RBA processing is single-threaded, targeted extraction treats each processing unit as one contiguous range. The only recognized boundary is the exact line ending:

`START - HandleEventInternal Automatic Booking is enabled for resource.`

A block includes every source line after the preceding newer exact START boundary through and including its own exact START boundary. Generic `START -` text does not split a block. The `events` array remains in top-down, newest-first source order, and each event's complete `rawLog` also remains newest-first. Read an individual `rawLog` **bottom-up** for chronological processing: START, entry/classification, policy evaluation, decision, optional post-processing, and result or END. For an oldest-to-newest history across events, traverse the event array from highest `sequence` to lowest.

Each targeted event reports `startMarker`, `startTimeText`, `startBoundaryFound`, and `boundaryStatus`. `startMarker` is the complete exact START row, and `startTimeText` is the timestamp printed on that row; the compatibility field `eventTimeText` has the same value and is not a completion time. `SourceStartToExactStart` means the newest block begins at the top of the export. `BetweenExactStartBoundaries` means both contiguous source boundaries are known. `MissingStartBoundary` identifies retained lines that cannot be closed by an exact START row; treat that evidence as partial and do not attach it to a neighboring block. The absence of an END marker alone does not prove incomplete processing because the manual does not document one universal END marker for every outcome.

Possible search statuses are:

- `NotRequested`: neither a meeting subject nor meeting ID was supplied, so counts and event collections are empty;
- `Found`: a subject resolved to at least one meeting ID, or the supplied meeting ID occurs in at least one retained block;
- `FoundWithoutMeetingId`: the subject matched, but other processing blocks cannot be correlated safely;
- `NotFound`: no subject match or supplied meeting ID exists in the retained log; and
- `LogUnavailable`: RBA log collection failed.

`NotRequested` remains in the default `Sanitized` privacy mode. `NotFound` does not mean the meeting was never processed. The RBA log retains only bounded recent history, and older processing can roll off. Targeted raw blocks can contain meeting subjects, identities, and processing details and must be handled as sensitive customer evidence.

For a resolved meeting, `firstLogTimeText` is the timestamp on the oldest retained `Begin ProcessRequest` row, `lastLogTimeText` is the newest recognized meeting-processing timestamp in the correlated evidence, and `lastUpdateTimeText` is the newest retained `Begin ProcessUpdateRequest` or `End ProcessUpdateRequest` timestamp. `recurrenceStatus` is `Recurring` or `NotRecurring` only when an explicit supported marker exists; otherwise it is `Unknown`. The report also summarizes explicit policy, disposition, tentative-response, and delegate-forwarding markers in `policyResult`, `disposition`, `tentativeResponseSent`, `forwardedToDelegates`, and `delegateMessageCount`. The human-readable report prints these meeting-specific values after the aggregate last-activity lines. It does not print meeting-specific detail rows for `NotFound`.

The targeted event fields identify exact retained markers:

| JSON field | RBA log marker or meaning |
|---|---|
| `actions` | `Action:Accept`, `Action:Decline`, or `Action:Tentative` |
| `policyResult` | `Defaulting to in policy.` or `Not in policy.` |
| `disposition` | `Meeting request evaluate returns result <Action>` or an `Action:<Action>` marker |
| `updateDetected` | `Begin ProcessUpdateRequest` |
| `cancellationDetected` | `It's a meeting cancellation.` |
| `delegateReferralDetected` | `Forwarding Request To Delegates` |
| `delegateMessageCount` | `Sending approval messages to <count> delegates.` |
| `tentativeResponseSent` | `END - Sending the tentatively acceptance response to organizer.` |
| `externalProcessingSkipped` | External processing was skipped because the corresponding setting was false. |
| `horizonDeclineDetected` | A recurring request exceeded the booking window and was explicitly declined. |
| `recurrenceTruncateDetected` | A recurring request was explicitly truncated at the booking window. |

These observations establish what the retained RBA log recorded. They do not establish message delivery, final calendar state, responsible actor, or a decline reason unless an approved exact reason marker occurs in the same processing block.

## Troubleshooting skill usage flow

1. Connect to Exchange Online with permission to read the target resource mailbox.
2. Run `Get-RBASummary.ps1`. Add `-Subject` when investigating a recent specific meeting.
3. Note the JSON path displayed at the end of the run.
4. Add the JSON report and `EXO-RBA-Troubleshooting-SKILL.md` to Copilot or another compatible assistant.
5. Ask the assistant to analyze the JSON by using the EXO RBA troubleshooting skill. The skill validates evidence, ranks detected findings, identifies collection gaps, and recommends tenant-admin commands with impact and rollback guidance. It does not execute configuration changes.

You can try the RBA troubleshooting skill to get deeper information from the report. When a meeting-specific answer requires final item state, delivery, recurrence exceptions, or actor attribution, collect Calendar Diagnostic Logs from the resource and, when available, the organizer, correlated by the same meeting ID.

## High-level RBA processing

1. Determine whether the meeting request is in policy or out of policy.
2. For an out-of-policy request, determine whether the organizer can request approval and, if allowed, route it to resource delegates.
3. For an in-policy request, book it automatically or route it to resource delegates according to the configured recipient wells.
4. If accepted, perform the configured post-processing steps, such as changing the subject or removing attachments.


When RBA receives a meeting request, it compares meeting properties with the resource's policy configuration. If all applicable checks pass, the request is in policy; otherwise, it is out of policy.

For either policy result, RBA reads the request-routing configuration to determine whether to act automatically or involve a resource delegate. By default, out-of-policy requests are rejected and in-policy requests are accepted, but CalendarProcessing supports other routing combinations.

If the meeting is accepted, RBA formats the resource's calendar item according to its post-processing configuration.

## Common CalendarProcessing policy findings

The JSON findings call out these frequently relevant policies:

- `BookingWindowInDays` sets how far in advance the resource can be reserved; `0` means today and the supported maximum is 1,080 days.
- `MaximumDurationInMinutes` limits each meeting or each instance in a recurring series; `0` means unlimited.
- `AllowRecurringMeetings` controls whether recurring requests are allowed.
- For an allowed recurring series that starts within the booking window but ends beyond it, `EnforceSchedulingHorizon` set to true declines the entire series. When set to false, the series can be accepted but is truncated at the booking-window boundary, and nothing beyond that boundary exists on the resource calendar. Separate log findings report when either behavior was actually observed.
- `ScheduleOnlyDuringWorkHours` rejects meetings outside the resource mailbox's configured work days, hours, and time zone. Those work-hour values come from `Get-MailboxCalendarConfiguration` and aren't collected by this report.
- `AllowConflicts` set to true accepts all conflicts without percentage or count limits, so `ConflictPercentageAllowed` and `MaximumConflictInstances` aren't evaluated. This is required for Workspaces with capacity enforcement, but can permit overlapping reservations on other resources. When conflicts aren't generally allowed, the two thresholds determine how many conflicting occurrences a new recurring series can contain before the series is declined; exceeding either threshold declines the series. If neither threshold is exceeded, the series can be accepted while the conflicting occurrences are declined.
- `ProcessExternalMeetingMessages` set to false prevents RBA from processing meeting requests that Transport classified as external during routing and delivery. A separate RBA-log finding reports when skipped external messages were actually observed. If internal senders are unexpectedly classified as external, validate mail routing before enabling external processing, because enabling it can also permit genuinely external requests.
- `RemovePrivateProperty` set to true clears the private flag from incoming meetings; false preserves it.
- `DeleteSubject` removes the original subject, while `AddOrganizerToSubject` replaces the subject with the organizer's name. These settings apply to `AutoAccept` resource processing. Calendar folder permissions independently control whether a viewer can see subjects.
- `RemoveCanceledMeetings` set to true automatically deletes organizer-canceled meetings from an Exchange Online resource calendar; false retains them.

These are configuration consequences, not proof that a setting caused a particular historical outcome. RBA reads the current `CalendarProcessing` configuration for each item, while the report captures only the values present at its collection timestamp. Correlate the meeting's recurrence, dates, duration, sender, conflicts, global object identifier, RBA log, response, and calendar-item evidence before assigning causality. Use the EXO RBA troubleshooting skill for deeper analysis and read-only verification guidance.

## Mailbox lifecycle and item propagation

The report and troubleshooting skill provide bounded coverage for common lifecycle questions:

- A targeted fallback lookup identifies when the supplied identity resolves only as a recoverable soft-deleted mailbox. Recovery or purge decisions remain outside RBA troubleshooting.
- The mailbox summary shows whether the supplied identity matches the current primary SMTP address, a proxy address, or another resolvable identity. A proxy match can confirm that an old address still reaches the current mailbox, but it does not prove that or when a rename occurred.
- Current creation and change timestamps are observations only. A change timestamp does not identify the changed property, and one resolved target cannot prove that no duplicate or stale object exists elsewhere in the tenant.
- `RemoveCanceledMeetings` and aggregate RBA update and cancellation counts can explain configured retention and whether the available RBA log contains those operation types. They cannot establish whether a specific update or cancellation changed a specific item.
- Recurrence policy and RBA log findings can identify booking-window declines or truncations. They cannot establish that a current series is orphaned.
- With `-Subject`, targeted RBA blocks can establish that RBA logged an accept, decline, tentative action, update, cancellation, delegate referral, external-message skip, horizon decline, or recurrence truncation for an extracted meeting ID. They still do not establish final calendar state.
- Targeted blocks preserve the exported newest-first order. Read each raw block bottom-up from its exact START boundary; printed timestamps support their own rows but should not reorder equal or ambiguous entries.

Former-organizer reservations, stale calendar items, specific update or cancellation propagation, and orphaned recurring series require item-level Calendar Diagnostic Log evidence from the resource and, when available, the organizer. Correlate both mailboxes by the same meeting ID; subject and timestamp are secondary correlation values. Tenant-wide duplicate or obsolete room objects require a recipient inventory or object-lifecycle workflow.

An observed `Action:Decline` does not by itself explain why a meeting declined. The skill uses only documented exact reason markers from the same processing block. Current configuration can corroborate expected behavior but cannot establish the historical reason. If no approved marker is present, the result remains "decline observed; reason not established by the current decoder."

## Permissions and visibility boundaries

The report collects the resource's localized Calendar folder permissions and explicit mailbox Full Access grants. Its findings preserve these separate control planes:

- Calendar folder permissions control who can view or modify items in the resource Calendar folder. The `Default` access level is always reported.
- `ResourceDelegates` controls who can receive booking requests for approval. It is not the same as Calendar visibility or mailbox Full Access.
- The booking-policy recipient lists and all-user switches control who can book automatically or request approval. They do not grant Calendar folder access.
- `DeleteSubject`, `AddOrganizerToSubject`, and `RemovePrivateProperty` are RBA post-processing settings. They change stored meeting properties but do not grant folder access.
- Calendar `Owner` and explicit mailbox Full Access grants are warnings because they permit access outside normal RBA ownership. Their presence does not prove that anyone directly edited a meeting.
- If a configured resource delegate has no matching direct Calendar `Editor` or `Owner` entry, validate effective access separately. The user might receive access through a group or another assignment path.

Direct editing is deliberately not inferred from permissions. Establishing that a user or client modified the resource calendar requires Calendar Diagnostic Log evidence. The `RBA830` identifier is reserved for that future evidence and is not emitted by the current report.
