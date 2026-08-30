# EXO RBA finding rules

These IDs are stable within the `1.0-preview` report schema. Number ranges identify the source or logic area and intentionally leave room for new rules.

| Range | Rule group |
|---|---|
| RBA000–RBA099 | Script execution and evidence collection |
| RBA100–RBA199 | Mailbox validation |
| RBA200–RBA299 | Inbox rules |
| RBA300–RBA399 | Calendar processing and policy configuration |
| RBA400–RBA499 | Delegate and request routing |
| RBA500–RBA599 | Place, Workspace, and Room Finder |
| RBA600–RBA699 | Meeting post-processing |
| RBA700–RBA799 | RBA diagnostic logs |
| RBA800–RBA829 | Permissions and visibility |
| RBA830–RBA899 | Reserved for Calendar Diagnostic Log observations |
| RBA900–RBA999 | Reserved for additional RBA logic groups |

- `Detected` means the documented condition was observed.
- `NotDetected` means the rule was applicable and its condition was not observed.
- `NotEvaluated` means required collector evidence was unavailable. It must not be treated as healthy or unhealthy.
- `NotApplicable` means the evidence was available, but the rule does not apply to this resource or routing configuration.

## Script execution and evidence collection (RBA000–RBA099)

Collector failures are evidence gaps, not configuration root causes. Fix collection before drawing conclusions that depend on the missing data.

| Rule ID | Severity | Applicability and supported interpretation | Required evidence |
|---|---|---|---|
| RBA001 | Error | Mailbox collection failed; mailbox-dependent configuration cannot be assessed. | `collectors.Mailbox.error` |
| RBA002 | Error | Place collection failed; Place-dependent checks cannot be completed. | `collectors.Place.error` |
| RBA003 | Error | Inbox-rule collection failed; blocking delegate rules cannot be ruled out. | `collectors.InboxRules.error` |
| RBA004 | Error | Calendar-processing collection failed; core RBA configuration cannot be assessed. | `collectors.CalendarProcessing.error` |
| RBA005 | Warning | RBA log collection failed; recent processing behavior cannot be assessed. | `collectors.RbaLog.error` |
| RBA006 | Warning | Calendar folder permission collection failed; Calendar visibility, Owner access, and direct delegate access cannot be assessed. | `collectors.CalendarFolderPermissions.error` |
| RBA007 | Warning | Mailbox permission collection failed; explicit Full Access grants cannot be assessed. | `collectors.MailboxPermissions.error` |

## Mailbox validation (RBA100–RBA199)

| Rule ID | Severity | Applicability and supported interpretation | Required evidence |
|---|---|---|---|
| RBA100 | Critical | Applicable when mailbox evidence is available. The target is not a room or equipment mailbox, so RBA is unsupported. | `mailbox.recipientTypeDetails` |
| RBA101 | Critical | Applicable when mailbox evidence is available. The active lookup failed and the same identity resolved only with Exchange Online's soft-deleted-mailbox lookup. A soft-deleted resource is recoverable but cannot perform active RBA processing. This does not choose or perform a recovery action. | `mailbox.objectState` |
| RBA102 | Information | Detected when the supplied identity resolved to the active or soft-deleted mailbox through one of its proxy addresses instead of its current primary SMTP address. This can confirm that an old address still resolves to the current object, but it does not prove that a rename occurred, when an address changed, or which address an existing meeting used. | `mailbox.inputIdentityMatch`, `mailbox.primarySmtpAddress` |

The mailbox summary also reports the current display name, alias, primary SMTP address, proxy-address count, and available creation/change timestamps. Full privacy mode adds the target mailbox's proxy addresses and stable Exchange identifiers for protected comparison. These are current-state observations: `WhenChangedUTC` does not identify which property changed, and one resolved mailbox does not rule out duplicate or stale objects elsewhere in the tenant.

## Inbox rules (RBA200–RBA299)

| Rule ID | Severity | Applicability and supported interpretation | Required evidence |
|---|---|---|---|
| RBA200 | Critical | Applicable when inbox-rule evidence is available. A user-style delegate inbox rule can block RBA processing. | `inboxRules.delegateRuleCount` |
| RBA201 | Warning | Applicable when inbox-rule evidence is available. Redacted names make delegate-rule validation incomplete; this does not prove that a blocking rule exists. | `inboxRules.redactedCount` |

## Calendar processing and policy configuration (RBA300–RBA399)

| Rule ID | Severity | Applicability and supported interpretation | Required evidence |
|---|---|---|---|
| RBA300 | Critical | Applicable when calendar-processing evidence is available. `AutomateProcessing` is not `AutoAccept`, so RBA will not process requests as expected. | `calendarProcessing.automateProcessing` |
| RBA301 | Critical | Applicable when calendar-processing evidence is available. No booking or referral route is configured for either policy class. | The six `BookInPolicy`, `RequestInPolicy`, and `RequestOutOfPolicy` list/all-user settings |
| RBA302 | Information | Always detected when calendar-processing evidence is available. `BookingWindowInDays` is the maximum advance-booking window; `0` means today and the supported maximum is 1,080 days. A request's dates are needed to determine whether this policy affected it. | `calendarProcessing.bookingWindowInDays`, `calendarProcessing.allowRecurringMeetings`, `calendarProcessing.enforceSchedulingHorizon` |
| RBA303 | Information | Detected when `MaximumDurationInMinutes` is greater than `0`, which limits each meeting or recurring instance to that duration. `0` means unlimited and is `NotDetected`. A request's duration is needed to determine whether this policy affected it. | `calendarProcessing.maximumDurationInMinutes` |
| RBA304 | Warning | Detected when `AllowRecurringMeetings` is false. Recurring requests aren't allowed; this setting says nothing about one specific request unless recurrence evidence is available. | `calendarProcessing.allowRecurringMeetings` |
| RBA305 | Information | Applicable to resources that allow recurring meetings. Detected when `EnforceSchedulingHorizon` is true: a series that starts within the booking window but extends beyond it is declined. | `calendarProcessing.enforceSchedulingHorizon`, `calendarProcessing.bookingWindowInDays`, `calendarProcessing.allowRecurringMeetings` |
| RBA306 | Information | Applicable to resources that allow recurring meetings. Detected when `EnforceSchedulingHorizon` is false: a series that starts within the booking window can be accepted, but its recurrence is truncated at the window and nothing beyond that boundary exists on the resource calendar. RBA705 provides log evidence when this actually occurred. | `calendarProcessing.enforceSchedulingHorizon`, `calendarProcessing.bookingWindowInDays`, `calendarProcessing.allowRecurringMeetings` |
| RBA307 | Warning | Detected when `ScheduleOnlyDuringWorkHours` is true. Requests outside the resource mailbox's configured work days, hours, or time zone are rejected. This report doesn't collect those work-hour values or prove that a request was outside them. | `calendarProcessing.scheduleOnlyDuringWorkHours` |
| RBA308 | Information | Detected when `AllowConflicts` is true. All conflicts are accepted regardless of the percentage/count settings, which are not evaluated. This is required behavior for Workspaces when combined with capacity enforcement, but it can permit overlapping reservations on other resources. This configuration does not prove a particular double booking. | `calendarProcessing.allowConflicts`, both recurring-conflict thresholds |
| RBA309 | Information | Applicable when recurring meetings are enabled and `AllowConflicts` is false. Detected when `ConflictPercentageAllowed` is greater than `0`; a new recurring series is declined if its conflicting-occurrence percentage is higher than this value. `0` permits no recurring conflicts. | `calendarProcessing.allowRecurringMeetings`, `calendarProcessing.allowConflicts`, `calendarProcessing.conflictPercentageAllowed` |
| RBA310 | Information | Applicable when recurring meetings are enabled and `AllowConflicts` is false. Detected when `MaximumConflictInstances` is greater than `0`; a new recurring series is declined if its conflicting-occurrence count is higher than this value. `0` permits no recurring conflicts. | `calendarProcessing.allowRecurringMeetings`, `calendarProcessing.allowConflicts`, `calendarProcessing.maximumConflictInstances` |
| RBA311 | Warning | Detected when `ProcessExternalMeetingMessages` is false. RBA doesn't process items that Transport classified as external. Classification is based on a property stamped during routing and delivery, not merely a comparison of sender and accepted domains. Unlike RBA700, this configuration finding does not prove that an external request was received or skipped. | `calendarProcessing.processExternalMeetingMessages` |

For `RBA309` and `RBA310`, the series is declined when either configured limit is exceeded. If neither limit is exceeded, the series can be accepted while conflicting occurrences are declined. Use meeting-level evidence and the RBA response/log before attributing a particular outcome to these limits.

Read-only verification for this section:

```powershell
Get-CalendarProcessing -Identity <ResourceMailbox> | Format-List AutomateProcessing,BookingWindowInDays,MaximumDurationInMinutes,AllowRecurringMeetings,EnforceSchedulingHorizon,ScheduleOnlyDuringWorkHours,AllowConflicts,ConflictPercentageAllowed,MaximumConflictInstances,ProcessExternalMeetingMessages
```

When `RBA307` is detected, also verify the resource's work-hour inputs:

```powershell
Get-MailboxCalendarConfiguration -Identity <ResourceMailbox> | Format-List WorkDays,WorkingHoursStartTime,WorkingHoursEndTime,WorkingHoursTimeZone
```

## Delegate and request routing (RBA400–RBA499)

| Rule ID | Severity | Applicability and supported interpretation | Required evidence |
|---|---|---|---|
| RBA400 | Information | Applicable only when no delegate route is needed: no delegates, all in-policy requests auto-book, and no out-of-policy requests can be referred. This is expected behavior, not a fault. | Delegate count, `allBookInPolicy`, `allRequestOutOfPolicy`, out-of-policy requester count |
| RBA401 | Warning | Applicable when no delegates exist. In-policy forwarding is enabled for requests that do not auto-book, so those requests have no delegate recipient. | Delegate count, `forwardRequestsToDelegates`, `allBookInPolicy` |
| RBA402 | Error | Applicable when no delegates exist. Listed users can submit out-of-policy requests, but no delegate can decide them; the script warns they may remain tentatively accepted. | Delegate and out-of-policy requester counts |
| RBA403 | Error | Applicable when no delegates exist. All users can submit out-of-policy requests, but no delegate can decide them; the script warns they may remain tentatively accepted. | Delegate count, `allRequestOutOfPolicy` |
| RBA410 | Warning | Applicable when delegates exist. `AddNewRequestsTentatively` is false, so the Calendar Attendant only updates existing calendar items instead of adding new requests tentatively for review. | Delegate count, `calendarProcessing.addNewRequestsTentatively` |
| RBA411 | Information | Applicable when delegates exist and forwarding is enabled. `AllBookInPolicy` auto-books every in-policy request, so delegates do not receive in-policy requests. This is expected routing behavior. | Delegate count, `forwardRequestsToDelegates`, `allBookInPolicy` |
| RBA412 | Information | Applicable when delegates exist, forwarding is enabled, and `AllBookInPolicy` is false. Listed `BookInPolicy` users bypass delegate review because their in-policy requests auto-book. | Delegate count, forwarding setting, all-book setting, `bookInPolicy` count |
| RBA420 | Warning | Applicable when delegates exist and forwarding is enabled. Neither all users nor listed users may submit out-of-policy requests, so delegates receive none; such requests are denied. | Delegate count, forwarding setting, `allRequestOutOfPolicy`, requester count |
| RBA421 | Information | Applicable when delegates exist, forwarding is enabled, and all-user out-of-policy referral is disabled. Only listed users can send out-of-policy requests to delegates. | Delegate count, forwarding setting, `allRequestOutOfPolicy`, requester count |
| RBA422 | Information | Applicable when delegates exist and forwarding is enabled. All users can submit out-of-policy requests for delegate review. | Delegate count, forwarding setting, `allRequestOutOfPolicy` |
| RBA423 | Warning | Applicable when `AllRequestOutOfPolicy` is true. A non-empty `RequestOutOfPolicy` list is overridden because all users are allowed to submit. | `allRequestOutOfPolicy`, requester count |

## Place, Workspace, and Room Finder (RBA500–RBA599)

| Rule ID | Severity | Applicability and supported interpretation | Required evidence |
|---|---|---|---|
| RBA500 | Error | Workspace only. Capacity is required but missing. Non-workspaces are `NotApplicable`. | `mailbox.resourceType`, `place.capacity` |
| RBA501 | Error | Workspace only. `EnforceCapacity` and `AllowConflicts` are not both enabled. Non-workspaces are `NotApplicable`. | `mailbox.resourceType`, `calendarProcessing.enforceCapacity`, `calendarProcessing.allowConflicts` |
| RBA510 | Warning | Adjacent Room Finder discovery check, not a core RBA blocker. The resource is not associated with a room list. | `place.roomListCount` |
| RBA511 | Warning | Adjacent Room Finder discovery check, not a core RBA blocker. City, Floor, or Capacity is missing. | Missing names derived from `place.city`, `place.floor`, and `place.capacity` |

## Meeting post-processing (RBA600–RBA699)

| Rule ID | Severity | Applicability and supported interpretation | Required evidence |
|---|---|---|---|
| RBA600 | Warning | Applicable when calendar-processing evidence is available. Deleting meeting comments can remove Teams join information from the body. | `calendarProcessing.deleteComments` |
| RBA601 | Warning | Detected when `RemovePrivateProperty` is true. RBA clears the private flag from incoming meetings; false preserves it. Calendar permissions still determine what viewers can see. | `calendarProcessing.removePrivateProperty` |
| RBA602 | Information | Detected when `DeleteSubject` is true. RBA removes the original subject during `AutoAccept` processing. Evaluate it with `AddOrganizerToSubject`; this does not explain subject visibility caused by Calendar folder permissions. | `calendarProcessing.deleteSubject`, `calendarProcessing.addOrganizerToSubject` |
| RBA603 | Information | Detected when `AddOrganizerToSubject` is true. RBA replaces the existing subject with the organizer's name during `AutoAccept` processing; false preserves the original subject unless another setting removes it. | `calendarProcessing.addOrganizerToSubject`, `calendarProcessing.deleteSubject` |
| RBA604 | Information | Detected when `RemoveCanceledMeetings` is false. Organizer-canceled meetings are retained on the resource calendar; true automatically deletes them. The setting is Exchange Online only. | `calendarProcessing.removeCanceledMeetings` |

The post-processing settings in this section describe configured behavior, not proof that RBA changed a particular calendar item. `RBA604` can explain why an organizer-canceled item is retained, but it cannot identify former organizers, establish that an item is stale, or prove that a cancellation reached the resource. Confirm `AutomateProcessing` is `AutoAccept`, then correlate item-level evidence before assigning causality. Default Calendar folder permissions commonly expose only availability; subject visibility requires at least `LimitedDetails` and must not be inferred from `DeleteSubject` alone.

Read-only verification for this section:

```powershell
Get-CalendarProcessing -Identity <ResourceMailbox> | Format-List AutomateProcessing,RemovePrivateProperty,DeleteSubject,AddOrganizerToSubject,RemoveCanceledMeetings
```

## RBA diagnostic logs (RBA700–RBA799)

| Rule ID | Severity | Applicability and supported interpretation | Required evidence |
|---|---|---|---|
| RBA700 | Warning | Applicable when RBA log evidence is available. One or more external requests were skipped because external processing was disabled. This is an observation, not proof of a transport problem. | `rbaLogSummary.skippedExternalCount` |
| RBA701 | Warning | Applicable when RBA log collection succeeds. No usable log history was returned; send a future test meeting before relying on log analysis. | `rbaLogSummary.entryCount` |
| RBA702 | Warning | Applicable only when usable RBA log history exists. No accept, decline, or tentative action was observed in that history. | RBA log entry and processed-action counts |
| RBA703 | Warning | Applicable only when usable RBA log history exists. No meeting update operation was observed in that history. | RBA log entry and update counts |
| RBA704 | Warning | Applicable when RBA log evidence is available. The log explicitly records one or more recurring requests whose recurrence end exceeded `BookingWindowInDays` and whose entire request was declined. Correlate by global object identifier, subject, and timestamp before applying this observation to a reported meeting. | `rbaLogSummary.horizonDeclineCount` |
| RBA705 | Warning | Applicable when RBA log evidence is available. The log explicitly records one or more recurring requests whose recurrence was truncated at the booking-window boundary. Correlate by global object identifier, subject, and timestamp before applying this observation to a reported meeting. | `rbaLogSummary.recurrenceTruncateCount` |
| RBA710 | Warning | Applicable only when `-MeetingSubject` was supplied and RBA log collection succeeded. The subject was not found in the retained log. This means only that no case-insensitive text match exists in the available bounded history; it does not prove that the meeting was never processed. | `meetingLogSearch.status`, `meetingLogSearch.subjectMatchCount` |
| RBA711 | Information | Applicable only when `-MeetingSubject` was supplied. The subject was found in one or more retained processing blocks. When a meeting ID was extracted, all retained blocks carrying that ID are included even if later update or cancellation blocks omit the subject. | `meetingLogSearch.status`, subject, meeting IDs, and event counts |
| RBA712 | Information | Applicable only to a successful targeted search. One or more correlated blocks contain the exact `Begin ProcessUpdateRequest` marker. This establishes that RBA logged update processing for the correlated meeting ID; it does not prove the final resource-calendar state. | `meetingLogSearch.updateCount`, targeted event markers and raw log |
| RBA713 | Information | Applicable only to a successful targeted search. One or more correlated blocks contain the exact `It's a meeting cancellation.` marker. This establishes that RBA recognized cancellation processing for the correlated meeting ID; interpret the resulting item state with `RemoveCanceledMeetings` and Calendar Diagnostic Logs. | `meetingLogSearch.cancellationCount`, targeted event markers and raw log |
| RBA714 | Warning | Applicable when the subject matched retained log text but no meeting ID could be extracted from the matching block. Only subject-matching blocks are included, and later blocks cannot be safely correlated. | `meetingLogSearch.status`, `meetingLogSearch.subjectMatchCount` |
| RBA715 | Information | Applicable only to a successful targeted search. One or more correlated blocks contain an explicit `Action:Decline` marker. This proves an RBA decline action was logged for a correlated block, but the reason remains unknown unless an approved reason marker occurs in that same block. | `meetingLogSearch.declineCount`, targeted event actions and raw log |

`RBA703` reports only whether the available RBA log contains any update operations. The report's aggregate `updatedCount` and `cancellationCount` cannot establish whether one reported update or cancellation reached or changed the resource item. Likewise, `RBA704` and `RBA705` explain recorded horizon outcomes but do not establish that a current recurring series is orphaned. Specific-item propagation, organizer state, calendar state, and recurrence exceptions require Calendar Diagnostic Log evidence correlated by meeting ID, subject, and timestamp.

## Targeted meeting log analysis

z`meetingLogSearch` has status `NotRequested`, zero counts, and empty meeting ID and event collections when the administrator does not supply `-MeetingSubject`. Findings `RBA710`–`RBA715` are then `NotApplicable`. When a subject is supplied, the search is a case-insensitive literal substring search of the retained RBA log. The exported source is newest-first, with the newest line at the top. RBA is single-threaded, so contiguous extraction is intentional: a processing block contains every line after the preceding newer exact boundary through and including its own row ending `START - HandleEventInternal Automatic Booking is enabled for resource.` at the bottom. Generic `START -` rows are not boundaries.

The `events` array preserves top-down source order, so sequence 1 is the newest retained processing unit. Each event's `rawLog` also preserves newest-first source text and must be read bottom-up for chronology. Across events, traverse highest sequence to lowest for chronological history. Printed timestamps corroborate the rows on which they occur but must not be used to reorder equal or ambiguous rows. `startMarker` is the complete exact START row, while `startTimeText` and compatibility field `eventTimeText` contain that row's timestamp—not an END or result timestamp. `startBoundaryFound` and `boundaryStatus` expose whether an exact lower boundary was retained; evidence with `MissingStartBoundary` is partial and must not be attached to a neighboring event.

Meeting IDs are extracted from recognized `CleanGlobalObjectId`, `GlobalObjectId`, `Global Object Id`, `MeetingId`, `Meeting ID`, and `UID` labels; the exact `Begin ProcessRequest Goid:` and `Begin ProcessUpdateRequest Goid:` formats are also recognized. A comma after the documented `040000008` prefix is removed for correlation, while the unchanged source remains in `rawLog`. The report includes every retained block containing an extracted normalized ID. A subject can resolve to multiple meeting IDs; never merge their timelines or assume that identical subjects identify one meeting.

Use the manual log-reference phases narrowly:

- **Entry and classification:** exact START, process-request or process-update GOID, received subject, and exact request/cancellation/non-meeting classification markers.
- **Policy evaluation:** evaluation start, conflict count, completed policy check, and explicit in-policy or not-in-policy text. These identify only the stated evaluation evidence.
- **Decision:** explicit evaluation result, `Action:*`, delegate-forwarding, and delegate-message-count markers.
- **Post-processing and end:** explicit begin/completed post-processing and documented acceptance or tentative END markers. No universal completion marker is assumed.
- **Recurrence, Workspace, and external handling:** only the exact horizon-decline, truncation, capacity, and external-skip markers support those observations.

Read one raw block chronologically as START at the bottom, then entry/classification, policy evaluation, decision, optional post-processing, and finally the newest result or documented END line toward the top. Preserve the raw text and cite it in exported order rather than rewriting it.

The targeted event fields are deterministic observations of exact markers:

| Event field | Required marker |
|---|---|
| `actions` | `Action:Accept`, `Action:Decline`, or `Action:Tentative` |
| `updateDetected` | `Begin ProcessUpdateRequest` |
| `cancellationDetected` | `It's a meeting cancellation.` |
| `delegateReferralDetected` | `Forwarding Request To Delegates` |
| `externalProcessingSkipped` | `Skipping processing because user settings for processing external items is false.` |
| `horizonDeclineDetected` | `Recurrence ends is past the booking window. Meeting will be declined.` |
| `recurrenceTruncateDetected` | `Truncating meeting recurrence end window` |

Treat the targeted raw blocks as sensitive meeting evidence even when the rest of the report is sanitized. `TargetedMeeting` privacy mode records this explicit scope. Cite the event sequence and exact raw marker when describing an observation. Do not infer delivery, final calendar state, rescheduling, conflict, policy route, or decline reason from the absence of a marker.

## Future decline evidence contract

A deterministic answer to "why did this meeting decline?" requires a per-processing-block decoder, not a comparison between a historical action and current configuration. Future schema revisions should expose the following bounded fields for each meeting ID and event. Each condition must use `Observed`, `NotObserved`, or `Unknown`, include the exact source marker and event sequence, and remain `Unknown` when no approved marker exists.

| Structured evidence | Required meaning |
|---|---|
| `policyRoute` | The route RBA explicitly selected, such as in-policy, out-of-policy, or delegate decision. |
| `conflict` | Whether RBA explicitly detected a conflict and, for recurrence, the observed instance or percentage result. |
| `bookingHorizon` | Whether meeting or recurrence dates exceeded the booking window and whether RBA declined or truncated the request. |
| `duration` | Whether RBA explicitly compared the meeting duration with the configured limit and found it exceeded. |
| `workingHours` | Whether RBA explicitly found the request outside the resource's work-hour policy. |
| `recurrence` | Whether recurrence was allowed and any explicit recurrence restriction, conflict, truncation, or rejection. |
| `externalMessage` | Whether RBA treated the message as external and processed or skipped it. |
| `delegateReferral` | Whether the request was explicitly referred to delegates. |
| `action` | The actual `Accept`, `Decline`, or `Tentative` action in that processing block. |
| `reason` | An approved reason classification backed by an exact marker in the same block as the action. |

Until that decoder exists, the skill may explain only approved exact markers already documented above. Current `CalendarProcessing` values can corroborate how a rule normally behaves, but cannot supply the historical reason for a targeted decline. If a block contains `Action:Decline` without an approved reason marker, report "decline observed; reason not established by the current decoder."

## Permissions and visibility (RBA800–RBA829)

This family intentionally does not collapse all access-related behavior into "room permissions." Calendar folder visibility, mailbox access, booking eligibility, booking-delegate routing, and RBA post-processing are separate control planes.

| Rule ID | Severity | Applicability and supported interpretation | Required evidence |
|---|---|---|---|
| RBA801 | Information | Always detected when Calendar folder permission evidence is available. Reports whether the `Default` principal is present and its access rights. This is a visibility observation, not a booking-eligibility decision. | `calendarPermissions.entries` filtered to `Default` |
| RBA802 | Warning | Detected when any Calendar folder entry has `Owner` access. Owner permits direct calendar management outside normal RBA ownership. It does not prove that the principal edited an item. | Count of Calendar folder entries with `Owner` |
| RBA803 | Warning | Applicable when `ResourceDelegates` are configured. A configured delegate has no matching **direct** Calendar `Editor` or `Owner` entry. Validate effective access separately before remediation because the user might receive rights through a group or another assignment path. This finding does not change booking eligibility or prove that delegate routing failed. | Configured delegate identities and direct Calendar `Editor`/`Owner` entries |
| RBA804 | Information | Always detected when Calendar permission and CalendarProcessing evidence are available. Calendar folder access controls who can view item details; `DeleteSubject` and `AddOrganizerToSubject` control what RBA stores as the subject during post-processing. Interpret with RBA602 and RBA603 rather than treating these as one permission. | `Default` access rights, `deleteSubject`, `addOrganizerToSubject` |
| RBA805 | Information | Always detected when Calendar permission and CalendarProcessing evidence are available. Calendar folder access and delegate flags control who can view item details; `RemovePrivateProperty` controls whether RBA clears the item's private flag. Interpret with RBA601 rather than treating these as one permission. | `Default` access rights, `removePrivateProperty` |
| RBA820 | Warning | Detected for explicit, non-inherited Full Access grants other than the mailbox's self entry. Full Access permits mailbox access that can bypass normal RBA ownership, but it does not prove that the grantee directly edited a calendar item. | `mailboxPermissions.explicitFullAccessCount` |

Booking eligibility remains in RBA300–RBA311 and delegate/request routing remains in RBA400–RBA423. `ResourceDelegates` identifies who receives requests for approval; it is not equivalent to Calendar folder visibility or Full Access. Subject and privacy transformations remain in RBA601–RBA603.

Read-only verification for this section:

```powershell
$calendarFolder = Get-MailboxFolderStatistics -Identity <ResourceMailbox> -FolderScope Calendar | Where-Object { $_.FolderType -eq "Calendar" } | Select-Object -First 1
Get-MailboxFolderPermission -Identity "<ResourceMailbox>:\$($calendarFolder.Name)"
Get-MailboxPermission -Identity <ResourceMailbox> | Where-Object { -not $_.IsInherited -and -not $_.Deny -and $_.AccessRights -contains "FullAccess" }
Get-CalendarProcessing -Identity <ResourceMailbox> | Format-List ResourceDelegates,BookInPolicy,AllBookInPolicy,RequestInPolicy,AllRequestInPolicy,RequestOutOfPolicy,AllRequestOutOfPolicy,DeleteSubject,AddOrganizerToSubject,RemovePrivateProperty
```

### Reserved direct-edit observation (RBA830)

`RBA830` is reserved and is not emitted by the current report. A direct-edit finding requires Calendar Diagnostic Log evidence showing a non-RBA client modifying the resource calendar. Calendar `Owner`, `Editor`, or mailbox Full Access grants only establish capability and must never be presented as proof that an edit occurred.

## Evidence rules

- Use collector errors only to describe missing evidence; they do not prove a configuration cause.
- A collector marked `Failed` may have retrieved evidence before immediate processing failed. Treat its collector-dependent evidence as unavailable; use the bounded structured error metadata for failure classification, not as configuration evidence.
- Use RBA log counts as observations, not proof of why a particular meeting succeeded or failed.
- `RBA704` and `RBA705` are stronger behavioral evidence than the corresponding configuration findings, but aggregated counts still don't identify the affected meeting. Use the full sensitive log only in an appropriately protected workflow, and correlate the request boundary by global object identifier, subject, and timestamp.
- Targeted event blocks correlated by an extracted meeting ID are stronger than aggregate log counts. Correlation does not make every free-form line authoritative: use only documented exact markers for deterministic classifications and preserve unknown states for future decoder fields.
- A targeted event's exact START boundary is at the bottom of its newest-first `rawLog`. Read the block bottom-up and event sequences from highest to lowest for chronology; do not reinterpret top-down source order as chronological execution.
- `RBA710` is bounded by retained log history. "Not found" must never be restated as "not processed," especially while the service retains only a limited number of recent processing events.
- If many requests believed to be internal appear under `RBA700`, investigate Transport classification and routing evidence before recommending `ProcessExternalMeetingMessages = $true`; changing the setting can also permit genuinely external requests.
- Information findings describe expected routing consequences and should not be remediated unless they conflict with the administrator's intent.
- `RBA400` explicitly describes a healthy no-delegate combination. Use `RBA401` through `RBA403` for faulty no-delegate routes.
- `RBA510` and `RBA511` affect discovery and workspace usability; do not claim they directly stop ordinary RBA processing.
- Calendar-processing configuration findings describe possible policy consequences. Do not claim that a setting caused a historical accept, decline, subject change, privacy change, or cancellation state without event-level evidence.
- Keep permission boundaries explicit: Calendar ACLs control folder access; `ResourceDelegates` controls approval routing; policy wells control booking eligibility; post-processing controls stored subject/private state; Full Access enables mailbox access; Calendar Diagnostic Logs are needed to establish direct editing.
- A missing direct permission match in `RBA803` does not prove missing effective access. Validate whether the delegate receives rights through a group or another supported assignment path before recommending a change.
- `RBA802` and `RBA820` establish the ability to edit or access the resource mailbox, not evidence that the permission was exercised. Do not claim direct editing unless future `RBA830` Calendar Diagnostic Log evidence is available.
- RBA reads the current `CalendarProcessing` configuration for each item it processes. The report is a snapshot at `metadata.collectedAtUtc` and does not prove which values were present when an older item was processed.
- Mailbox identity fields describe the one object resolved at collection time. A proxy-address match does not prove a rename, creation/change timestamps do not prove staleness, and the report does not inventory the tenant for duplicate objects.
- Validate coupled settings together: booking window with scheduling horizon; both conflict thresholds with `AllowConflicts` and recurring-meeting support; subject deletion with organizer substitution; work-hour restriction with mailbox calendar configuration.
- A `NotDetected` result applies only to the evidence captured at `metadata.collectedAtUtc`.
