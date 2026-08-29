# Get-RBASummary

Download the latest release: [Get-RBASummary.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-RBASummary.ps1)

Download the adjacent analysis skill: [EXO-RBA-Troubleshooting-SKILL.md](https://github.com/microsoft/CSS-Exchange/releases/latest/download/EXO-RBA-Troubleshooting-SKILL.md)

This script runs the Get-CalendarProcessing cmdlet and returns the output with more details in clear English, highlighting the key settings that affect RBA and some of the common errors in configuration.

The script also validates the mailbox type and checks for delegate rules that can interfere with RBA functionality. Collection is best effort: it independently attempts `Get-Mailbox`, `Get-Place`, `Get-InboxRule`, `Get-CalendarProcessing`, Calendar and mailbox permissions, and `Export-MailboxDiagnosticLogs`. If the active mailbox lookup fails, the same mailbox collector performs a targeted soft-deleted-mailbox lookup. If one collector fails, the remaining collectors still run and evaluations that require unavailable evidence are safely skipped.

Every run that passes the script update self-check attempts to create timestamp-correlated text and JSON reports. The JSON report contains a schema version, collection status, per-collector status, collection errors, minimal configuration and log-summary evidence, and findings with stable rule IDs. A status of `Partial` or `Failed` means the collection errors and `NotEvaluated` findings should be reviewed before drawing conclusions. `NotApplicable` means that evidence was available but the rule does not apply to the resource or its routing configuration.

A collector is successful only when collection and its immediate evidence processing both finish successfully. If processing fails after evidence was retrieved, that collector is marked `Failed`, the overall status cannot be `Complete`, and other successfully collected evidence remains in the report. Collector and evaluation errors retain their existing `error` or `message` strings and include bounded `exceptionType`, `category`, `fullyQualifiedErrorId`, and `innerExceptionMessage` metadata when available. Stack traces, invocation details, target objects, and remote position details are not exported.

The JSON is saved in the current working directory with the following filename format:

`RBA-Summary-For_<mailbox-name>_<yyyy-MM-dd_HH-mm-ss>.json`

For example, running the script for `Room1@Contoso.com` creates a filename similar to `RBA-Summary-For_Room1_2026-08-28_15-42-10.json`. The timestamp matches the associated text summary produced by the same run.


#### Syntax:

Example to display the setting of room mailbox.
```PowerShell
.\Get-RBASummary.ps1 -Identity Room1@Contoso.com

.\Get-RBASummary.ps1 -Identity Room1 -Verbose
```

By default, JSON uses sanitized privacy mode. The target identity and its current display name, alias, primary SMTP address, address count, resolution type, object state, and available creation/change timestamps remain visible. Other identities in policy and delegate lists are replaced with placeholders, full proxy-address and stable-identifier values are omitted, full RBA log and transcript content are omitted, and only the `AddAdditionalResponse` boolean is retained—not the potentially sensitive `AdditionalResponse` text. Full-fidelity mode adds the target mailbox's proxy addresses, Exchange GUID, and external directory object ID. Use it only when the report will be handled as sensitive tenant data:

```PowerShell
.\Get-RBASummary.ps1 -Identity Room1@Contoso.com -IncludeSensitiveData
```

To investigate one meeting, provide a case-insensitive subject substring. This explicitly includes sensitive targeted log content in the JSON and sets `metadata.privacyMode` to `TargetedMeeting` unless full-fidelity mode was also requested:

```PowerShell
.\Get-RBASummary.ps1 -Identity Room1@Contoso.com -MeetingSubject "Quarterly planning"
```

The script searches the retained RBA log for the subject, extracts meeting IDs from matching processing blocks, and includes every retained block with those IDs. It recognizes the existing ID labels plus the exact `Begin ProcessRequest Goid:` and `Begin ProcessUpdateRequest Goid:` formats. For correlation, it normalizes the documented comma after the `040000008` GOID prefix; the complete unchanged source line remains in the raw block. This allows the skill to follow separate initial request, update, and cancellation processing even when later blocks omit the subject. If the same subject resolves to multiple meeting IDs, their timelines remain separate.

Exported RBA logs are newest-first: the newest result or END lines are at the top, and a processing unit's oldest START line is at the bottom. Because RBA processing is single-threaded, targeted extraction treats each processing unit as one contiguous range. The only recognized boundary is the exact line ending:

`START - HandleEventInternal Automatic Booking is enabled for resource.`

A block includes every source line after the preceding newer exact START boundary through and including its own exact START boundary. Generic `START -` text does not split a block. The `events` array remains in top-down, newest-first source order, and each event's complete `rawLog` also remains newest-first. Read an individual `rawLog` **bottom-up** for chronological processing: START, entry/classification, policy evaluation, decision, optional post-processing, and result or END. For an oldest-to-newest history across events, traverse the event array from highest `sequence` to lowest.

Each targeted event reports `startMarker`, `startTimeText`, `startBoundaryFound`, and `boundaryStatus`. `startMarker` is the complete exact START row, and `startTimeText` is the timestamp printed on that row; the compatibility field `eventTimeText` has the same value and is not a completion time. `SourceStartToExactStart` means the newest block begins at the top of the export. `BetweenExactStartBoundaries` means both contiguous source boundaries are known. `MissingStartBoundary` identifies retained lines that cannot be closed by an exact START row; treat that evidence as partial and do not attach it to a neighboring block. The absence of an END marker alone does not prove incomplete processing because the manual does not document one universal END marker for every outcome.

Possible search statuses are:

- `Found`: the subject matched and at least one meeting ID was extracted;
- `FoundWithoutMeetingId`: the subject matched, but other processing blocks cannot be correlated safely;
- `NotFound`: no subject match exists in the retained log; and
- `LogUnavailable`: RBA log collection failed.

`NotFound` does not mean the meeting was never processed. The RBA log retains only bounded recent history, and older processing can roll off. Targeted raw blocks can contain meeting subjects, identities, and processing details and must be handled as sensitive customer evidence.

## Troubleshooting skill usage flow

1. Connect to Exchange Online with permission to read the target resource mailbox.
2. Run `Get-RBASummary.ps1` and note the JSON path shown at the end of the run.
3. Start Copilot (or other LLM), add the JSON file and the "EXO-RBA-Troubleshooting-SKILL.md" file.
4. Ask Copilot to analyze the JSON with the "EXO-RBA-Troubleshooting-SKILL.md". It validates the preview schema and evidence, ranks detected findings, identifies collection gaps, and recommends tenant-admin commands with impact and rollback guidance. It does not execute configuration changes.

##### High-level steps for RBA processing: <br>

1. Determine if the Meeting Request is in policy or out of policy.<br>
2. If the meeting request is Out of Policy, see if the user has rights to create an Out of Policy request and if so, forward it to the Delegates.<br>
3. If it is In Policy, then either book it or forward it to the delegate based on the settings.<br>
4. Lastly the RBA does the configured Post Processing steps to format the meeting (delete attachments, rename meeting, etc.)<br>


When the RBA receives a Meeting Request, the first thing that it will do is to determine if the meeting is in or out of policy.  How does the RBA do this? The RBA compares the Meeting properties to the Policy Configuration. If all the checks 'pass', then the meeting request is In Policy, otherwise it is Out of Policy.

Whether the meeting is in or out of policy, the RBA will look up the configuration that will tell it what to do with the meeting. By default, all out of policy meetings are rejected, and all in policy meetings are accepted, but there is a larger range of customization that you can do to get the RBA to treat this resource the way you want it to.

If the meeting is accepted, the RBA will Post Process it based on the Post Processing configuration.

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
- With `-MeetingSubject`, targeted RBA blocks can establish that RBA logged an accept, decline, tentative action, update, cancellation, delegate referral, external-message skip, horizon decline, or recurrence truncation for an extracted meeting ID. They still do not establish final calendar state.
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
