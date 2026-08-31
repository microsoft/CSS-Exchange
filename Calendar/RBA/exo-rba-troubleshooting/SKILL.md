---
name: exo-rba-troubleshooting
description: Diagnose Exchange Online Resource Booking Assistant policy, routing, post-processing, and targeted meeting RBA log issues for resource mailboxes using Get-RBASummary.ps1 JSON. Do not use for Teams Rooms devices, Microsoft Places, Graph or Power Automate, non-resource sharing, generic event repair, Copilot Rebook, service delays, reporting, or audits.
---

# EXO RBA Troubleshooting

Use this skill only to analyze a `Get-RBASummary.ps1` JSON report for an Exchange Online tenant administrator. Do not request or rely on the text transcript when sanitized JSON is sufficient.

## Beta Feature

This skill is currently in beta. Its analysis and recommendations may change as the feature evolves. Review all evidence, commands, expected impacts, and rollback guidance before making configuration changes.

Send feedback, issues, and suggestions to `CalLogFormatterDevs@microsoft.com`.

The generic guardrails in [TSG-Rules.md](TSG-Rules.md) and the RBA-specific findings in [RBA-Rules.md](RBA-Rules.md) are mandatory. Apply the generic rules throughout the interaction and use the RBA rules to interpret individual findings.

## Safety boundary

- Analyze evidence and recommend actions; never execute a configuration change.
- Never claim a cause that is not supported by report evidence.
- Treat `NotEvaluated` as an evidence gap, not healthy or unhealthy. Treat `NotApplicable` as intentionally outside the rule's scope, not an evidence gap.
- Preserve sanitized identities. Do not try to identify `SanitizedIdentity-*` values.
- Before suggesting a modifying command, explain its expected impact and provide rollback guidance that restores the observed value.
- Ask the tenant administrator to review and run any modifying command themselves.

## Explicit out-of-scope routing

Classify the reported symptom before interpreting findings. This skill answers only RBA questions about a resource mailbox's booking-policy evaluation, request routing, delegate approval routing, RBA post-processing, and behavior explicitly observed in RBA logs.

If the request matches an out-of-scope classification below, state that the symptom requires a different troubleshooting skill or workflow, name the classification, and stop analysis for that symptom branch. Do not stretch a nearby RBA finding into an answer. Do not invent the name of another skill when no installed skill is known; describe the required specialist workflow instead.

| Routing classification | Out-of-scope examples | Route to |
|---|---|---|
| Teams Rooms device health | Device sign-in, application health, peripherals, firmware, console, display, camera, microphone, or Teams Admin Center device alerts | Teams Rooms device-health troubleshooting |
| Microsoft Places and PlaceV3 | Buildings, floors, sections, desks, Places hierarchy, PlaceV3 synchronization, workplace presence, or broad room-discovery behavior | Microsoft Places or PlaceV3 troubleshooting |
| Graph and Power Automate | Microsoft Graph requests, application permissions, API payloads, subscriptions, connectors, flows, or automation failures | Graph API or Power Automate troubleshooting |
| Non-resource calendar sharing and delegation | User or shared-mailbox calendar sharing, Outlook delegates, sharing invitations, cross-tenant sharing, or non-room folder permissions | Calendar sharing and delegation troubleshooting |
| Generic calendar-event repair | Corrupt, missing, duplicated, repaired, or unexpectedly modified events where RBA evidence does not establish resource booking behavior | Calendar event and Calendar Diagnostic Log troubleshooting |
| Copilot Rebook or automated room booking | Alternative-room suggestions, rebook attempts, licensing, proximity selection, or automated room replacement after a decline | Copilot Rebook or automated room-booking troubleshooting |
| Service availability or processing delay | Service incidents, assistant backlog, delayed processing, broad tenant impact, or availability questions | Service health and processing-delay investigation |
| Reporting and audit | Utilization reports, booking history exports, compliance searches, audit attribution, trend analysis, or inventory requests | Reporting, compliance, or audit workflow |

Boundary notes:

- `Get-Place` findings in the report cover only the narrow resource prerequisites documented by their RBA rules. They do not authorize diagnosis of Microsoft Places, PlaceV3, or general room-discovery architecture.
- Calendar permission findings describe the target resource mailbox only. They do not authorize diagnosis of user calendars, shared-mailbox calendars, or general sharing/delegation.
- RBA log observations can establish what RBA recorded. They do not establish device health, service availability, event corruption, audit attribution, or Copilot Rebook health.
- For a mixed request, separate the symptom branches. Analyze only the RBA branch and explicitly route each non-RBA branch.
- A supplied RBA JSON report does not make an otherwise out-of-scope question an RBA question.

## Lifecycle and item propagation triage

Use the existing report evidence where it can answer a bounded part of the question, then route only the unresolved branch. Do not turn current configuration or aggregate RBA log counts into item-level history.

| Customer question | What this report can answer | Required disposition |
|---|---|---|
| Soft-deleted room mailbox | `RBA101` identifies when the supplied identity resolves only as a recoverable soft-deleted mailbox. | State that active RBA processing is unavailable and route recovery decisions to a mailbox-recovery workflow. Do not recommend restore or purge without recovery requirements and hold state. |
| Duplicate or stale room object | The report identifies the single mailbox resolved at collection time and provides current object timestamps and, in full privacy mode, stable identifiers. | Do not claim uniqueness or staleness. Route tenant-wide duplicate, obsolete-object, and synchronization analysis to recipient inventory and object-lifecycle troubleshooting. |
| Room rename or SMTP change | `RBA102` and `mailbox.inputIdentityMatch` distinguish the current primary SMTP address from a resolving proxy address. | State only the current resolution. Route change timing, previous values, directory synchronization, and meetings addressed to an old object to identity-history or calendar-item analysis. |
| Former organizer reservations | `RBA604` explains whether organizer-canceled meetings are retained by configuration. Aggregate RBA logs can show that some cancellations were processed. | Do not identify a former organizer or classify an item as abandoned. Route the specific reservation to Calendar Diagnostic Log and organizer-object analysis. |
| Stale room calendar items | Current settings can explain retention behavior, but the report does not enumerate calendar items or determine age, validity, or ownership. | Route item discovery, age criteria, validation, and cleanup to a calendar-item lifecycle workflow. |
| Cancellation or update not reflected | `rbaLogSummary.cancellationCount`, `rbaLogSummary.updatedCount`, `RBA604`, and `RBA703` describe aggregate processing and configured retention. | Do not claim that a specific message reached or changed the room item. Route the meeting to Calendar Diagnostic Log correlation by meeting ID, subject, and timestamp. |
| Orphaned recurring meetings | `RBA304`–`RBA306` explain recurrence policy; `RBA704` and `RBA705` identify aggregate horizon declines or truncations. | Do not label a series orphaned. Route current series state, organizer validity, missing instances, and recurrence exceptions to Calendar Diagnostic Log analysis. |

The minimal downstream evidence for a specific meeting is Calendar Diagnostic Log output from the resource and, when available, the organizer, correlated by the same meeting ID. Use subject and timestamp only as secondary correlation values. Calendar Diagnostic Logs—not this summary—provide item create/update actions, cancellation state, responsible actor, meeting-request type, and recurrence exceptions.

## Targeted meeting log workflow

When `meetingLogSearch.status` is not `NotRequested`, treat it as explicitly requested sensitive meeting evidence. Analyze it before aggregate `rbaLogSummary` counts. A `NotRequested` object contains only ordering metadata, zero counts, and empty meeting ID and event collections and remains sanitized.

1. State the requested search status exactly: `LogUnavailable`, `NotFound`, `FoundWithoutMeetingId`, or `Found`.
2. For `NotFound`, say "the subject was not found in the retained RBA log." Do not say the meeting was never processed. Explain that RBA log history is bounded and older events might have rolled off.
3. For `FoundWithoutMeetingId`, analyze only the subject-matching blocks. State that updates or cancellations in other blocks cannot be correlated safely.
4. For `Found`, separate results by meeting ID. Never merge IDs merely because their subjects match.
5. Treat `events` and `sequence` as newest-first source order: sequence 1 is nearest the top of the exported log and is the newest retained processing unit. To present event history chronologically, traverse the event array from highest sequence to lowest. Use `startTimeText` only as the timestamp printed on the exact START row; do not reorder equal or ambiguous timestamps or infer elapsed time from them. Do not call an update a reschedule unless an approved marker explicitly establishes rescheduling.
6. Cite the event sequence and exact raw marker supporting every action, update, cancellation, delegate referral, external skip, horizon decline, or recurrence truncation statement.
7. Apply `RBA710`–`RBA715` and the targeted marker table in the RBA rules. Free-form raw text can be quoted as an observation but must not be promoted to a deterministic classification unless the rules approve that marker.
8. If `Action:Decline` is present, look for an approved reason marker in the same processing block. Current configuration can corroborate documented behavior but cannot retroactively establish the decline reason. If no approved marker is present, state "decline observed; reason not established by the current decoder."
9. Distinguish RBA processing from final calendar state. Route final item state, participant divergence, recurrence exceptions, or responsible-actor questions to Calendar Diagnostic Log analysis using the extracted meeting ID.

The report deliberately exports only subject-matching blocks and blocks correlated by extracted meeting ID unless `IncludeSensitiveData` was also used. Do not request the full RBA log when the targeted evidence is sufficient.

### RBA source ordering and event boundaries

The RBA log examples establish these structural rules:

- Exported RBA log lines are newest-first: the top is newest and the bottom is oldest.
- RBA processing is single-threaded, so each processing unit is a contiguous range. The only boundary recognized by this report is the exact row ending `START - HandleEventInternal Automatic Booking is enabled for resource.` Generic `START -` text is not a boundary.
- In source order, a complete unit begins immediately after the preceding newer exact START boundary (or at the top of the export for the newest retained unit) and includes its own exact START row at the bottom.
- Each event's `rawLog` remains newest-first. Read it **bottom-up** for chronological processing: exact START, entry/classification, policy evaluation, decision, optional post-processing, then the newest result or END row at the top.
- `startMarker` is the complete exact START row and `startTimeText` is that row's timestamp text. `eventTimeText` is a compatibility alias for the same start timestamp, not a completion time.
- `startBoundaryFound = false` and `boundaryStatus = MissingStartBoundary` identify retained lines that cannot be closed by an exact START boundary. Report the evidence as partial; do not attach it to a neighboring event or infer its start time. `SourceStartToExactStart` means the newest unit starts at the top of the export, not that a completion marker was observed.

Do not reverse or rewrite `rawLog` in citations. Preserve the exported text and state that chronological reading is bottom-up. An END marker can support only the exact completion path it names; the manual does not document a universal END marker for every outcome.

### Deterministic phase and marker interpretation

- **Entry/classification:** the exact START row opens chronological processing; `Begin ProcessRequest Goid:` identifies new-request processing, `Begin ProcessUpdateRequest Goid:` identifies update processing, and the exact request, cancellation, or non-meeting classification row states the observed item class or skip.
- **Policy evaluation:** `Begin meeting evaluation.`, `CheckConflict found N busy conflicts`, `Evaluate: Completed IsRequestInPolicy.`, `Defaulting to in policy.`, and `Not in policy.` support only the evaluation step or result they state. `Not in policy.` alone does not decode a decline reason.
- **Decision:** `Meeting request evaluate returns result <Action>` and `Action:Accept`, `Action:Tentative`, or `Action:Decline` state the recorded disposition. Delegate forwarding requires `Forwarding Request To Delegates` or the explicit delegate-message count marker.
- **Post-processing/end:** `Begin meeting post-processing.`, `PostProcessing completed on <Id>.`, and the documented acceptance or tentative END marker establish only those named stages. Do not infer an undocumented completion path from marker absence.
- **Recurrence, Workspace, and external handling:** use only the exact booking-window decline, recurrence-truncation, capacity-check, or external-processing-skip text for the corresponding observation. These markers do not establish unrelated final calendar state.

## Workflow

1. Classify the symptom using the explicit out-of-scope routing table. Stop and route any non-RBA symptom branch before interpreting RBA findings.
2. Perform the non-blocking version check below. Continue if it cannot complete.
3. Parse the supplied JSON. If parsing fails, stop diagnosis and explain that a valid JSON report is required.
4. Validate that `metadata.schemaVersion` is `1.0-preview`, `metadata.identity` is present, `metadata.collectionStatus` is `Complete`, `Partial`, or `Failed`, `metadata.privacyMode` is `Sanitized`, `TargetedMeeting`, or `Full`, and `collectors`, `findings`, and `collectionErrors` are present.
5. Apply [TSG-Rules.md](TSG-Rules.md), including its evidence-validation, truthfulness, output, remediation, and data-handling requirements.
6. Validate each finding against [RBA-Rules.md](RBA-Rules.md): the `ruleId` must be known and each finding must have `severity`, `status`, and `evidence`. Flag unknown IDs or malformed evidence; do not reinterpret them as known rules.
7. State the collection status and list failed collectors first. Explain which conclusions cannot be made from unavailable evidence.
8. Rank `Detected` findings by severity in this order: `Critical`, `Error`, `Warning`, `Information`. Use rule ID as the stable tie-breaker. Keep `NotEvaluated` findings in a separate evidence-gap section. Omit `NotApplicable` unless applicability is relevant to the explanation. Do not present `NotDetected`, `NotApplicable`, or informational expected-routing findings as problems.
9. For each ranked finding, report the rule ID, observed evidence, supported interpretation, verification command, and—only when justified—a remediation command with impact and rollback guidance.
10. End with the smallest safe next-step plan. Prefer collecting missing evidence before configuration changes.

## Command guidance

Commands are recommendations for tenant administrators, not actions for the skill to run. Use explicit named parameters and the target from `metadata.identity`. Start with read-only verification commands such as:

- `Get-Mailbox -Identity <identity>`
- `Get-Mailbox -Identity <identity> -SoftDeletedMailbox`
- `Get-Recipient -Identity <identity> -IncludeSoftDeletedRecipients`
- `Get-Place -Identity <identity>`
- `Get-InboxRule -Mailbox <identity> -IncludeHidden`
- `Get-CalendarProcessing -Identity <identity>`
- `Get-MailboxFolderStatistics -Identity <identity> -FolderScope Calendar`
- `Get-MailboxFolderPermission -Identity <localized-calendar-folder-identity>`
- `Get-MailboxPermission -Identity <identity>`
- `Export-MailboxDiagnosticLogs -Identity <identity> -ComponentName RBA`
- `Get-CalendarDiagnosticObjects -Identity <identity> -MeetingId <clean-global-object-id>`

For any suggested `Set-CalendarProcessing`, `Set-Place`, or `Remove-InboxRule` command:

- show the current value from evidence;
- describe user-visible and booking impact;
- recommend exporting or recording the current configuration first;
- provide a rollback command using the observed prior value; and
- never recommend broad changes when a narrower change addresses the detected rule.

If an inbox rule name or identity was sanitized, recommend a read-only command to resolve it locally rather than guessing the value.

Keep permission conclusions separate. Calendar folder permissions describe visibility and direct folder capabilities; `ResourceDelegates` describes approval routing; booking-policy lists describe eligibility; CalendarProcessing post-processing describes stored subject and private state; Full Access describes mailbox access. Do not claim that Owner, Editor, or Full Access was exercised. Direct editing requires Calendar Diagnostic Log evidence, and reserved rule `RBA830` is not available in the current report.

## Non-blocking version check

At the start of analysis, compare the skill version in the local package metadata with the version in:

`https://raw.githubusercontent.com/microsoft/CSS-Exchange/main/Calendar/RBA/exo-rba-troubleshooting/manifest.json`

Use available read-only web retrieval. If package metadata is unavailable, or retrieval, parsing, or comparison fails, mention the check was unavailable and continue. If the remote preview version is newer, mention the latest-release Markdown download; never block diagnosis and never download or install automatically.
