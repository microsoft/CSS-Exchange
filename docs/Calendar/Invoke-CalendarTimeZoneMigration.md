<!-- cspell:ignore tzone -->
# Invoke-CalendarTimeZoneMigration

Download the latest release: [Invoke-CalendarTimeZoneMigration.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Invoke-CalendarTimeZoneMigration.ps1)

Moves organizer-owned calendar items in Exchange Server (on-premises) mailboxes from one Windows time zone to another while keeping their local date and time. Use it when a region changes its time zone rules and a new Windows time zone is introduced, for example British Columbia, or when users relocate and their meetings must follow a different time zone.

## What the script changes

For each selected single item or recurring series (the whole series, including past occurrences and exceptions):

- Start and end times are recalculated so that the local date and time stay the same in the new time zone, using the rules that apply on each date. All-day events stay all-day on the same dates.
- The time zone definitions that Outlook and Exchange use are replaced: start, end and recurrence definitions, the legacy recurrence time zone and the recurrence blob that stores exception times. A full definition stays full and a single-rule (partial) definition stays partial.
- Modified occurrences keep their bodies, attachments and other properties; deleted occurrences stay deleted. Active reminders move with the item.
- Meeting organizers send a normal meeting update to the attendees.

Only items in the owner's default Calendar where the owner is the organizer are changed. Attendee copies are updated by Exchange when the update arrives.

The script does not change mailbox regional settings, Windows settings, room or resource policies, or permissions. How attendees and resources respond to the updates, and how many updates are sent, is the responsibility of the organization running the script.

## Requirements

- Windows PowerShell 5.1 on a management or user computer. Run as administrator is not required. The Exchange Management Shell is not used. No additional modules or DLLs are needed.
- An HTTPS EWS URL with a certificate trusted by the computer, specified with `-EwsUrl` or found by Autodiscover. Extended Protection on EWS is supported.
- Permission to the calendar: the owner's own credentials, a delegate with Editor permission on the owner's Calendar and Send on Behalf or Send As for the owner, or an account with a scoped ApplicationImpersonation role (`-Impersonation`). See [Delegates](#delegates).
- The source and target time zones must exist, with identical rules, on the Exchange servers and on the computer running the script. Install the Windows time zone update on all Exchange servers (a restart may be required) and on the computer running the script first. The script compares the complete rules before it changes anything and stops if they differ.

## Before you start

- Back up the affected mailboxes and export their calendars to PST. Verify that you can restore them. The script's logs and snapshots are not a substitute for a backup.
- Coordinate the migration with the organizers. Applying changes sends normal meeting updates, including to external attendees and rooms. Restoring a calendar does not undo updates already delivered to attendees.
- Start with one or two pilot mailboxes. Review the report and preview the changes before using `-Apply`. Verify local times, recurring exceptions and attendee and room copies in the clients your organization uses before processing more mailboxes.

## Recommended procedure

1. Update Windows time zone data on all Exchange servers, the computer running the script and the client computers.
2. Confirm the time zone IDs: `-ListTimeZones`.
3. Create a report for the affected mailboxes with `-ReportPath`. The report is read-only.
4. Review the report. Delete the rows that must not be changed. Rows with `HasRoom` set to `True` include room or resource recipients.
5. Run the migration with `-CsvPath` and `-ToWindowsTimeZoneId` without `-Apply` to preview, then with `-Apply`.
6. Check `summary.txt` for each mailbox. Items listed under `CRITICAL OBJECTS` need manual attention.
7. Change the mailbox regional settings and the users' Windows time zone to the new time zone.

!!! warning "Avoid a double change"
    When the Windows time zone of a computer changes, Outlook can offer to move appointments. Decline this for items that were already migrated by this script. Items that users already corrected manually, for example by moving the time while keeping the old time zone, are moved again by the script. Remove such rows from the report.

## Syntax

`-EwsUrl` is optional in every parameter set. See [Finding the EWS URL](#finding-the-ews-url).

```powershell
Invoke-CalendarTimeZoneMigration.ps1 [-EwsUrl <Uri>] -ListTimeZones [-Mailbox <String[]>] [-Credential <PSCredential>]

Invoke-CalendarTimeZoneMigration.ps1 [-EwsUrl <Uri>] -Mailbox <String[]> -FromWindowsTimeZoneId <String> -ReportPath <String>
    [-QueryStartDate <String>] [-QueryWindowInDays <Int32>] [-Credential <PSCredential>] [-Impersonation] [-Force]

Invoke-CalendarTimeZoneMigration.ps1 [-EwsUrl <Uri>] -CsvPath <String> -ToWindowsTimeZoneId <String> -LogDirectory <String>
    [-Apply] [-Credential <PSCredential>] [-Impersonation] [-SkipSendPermissionCheck] [-MaxAttachmentHashSizeMB <Int32>]

Invoke-CalendarTimeZoneMigration.ps1 [-EwsUrl <Uri>] -Mailbox <String[]> -FromWindowsTimeZoneId <String> -ToWindowsTimeZoneId <String>
    -LogDirectory <String> [-QueryStartDate <String>] [-QueryWindowInDays <Int32>] [-Apply] [-Credential <PSCredential>] [-Impersonation]
    [-SkipSendPermissionCheck]

Invoke-CalendarTimeZoneMigration.ps1 [-EwsUrl <Uri>] -Reconcile -CsvPath <String> -SearchDirectory <String[]> -LogDirectory <String>
    [-Apply] [-ResendNotification] [-Credential <PSCredential>] [-Impersonation] [-SkipSendPermissionCheck]
```

## Finding the EWS URL

Without `-EwsUrl`, the script runs Autodiscover for the first mailbox: the first `Mailbox` in the CSV, the first `-Mailbox`, or, with `-ListTimeZones` and no `-Credential`, the current user's address from Active Directory. It tries:

1. The Autodiscover service connection points in Active Directory (domain-joined computers), the computer's site first. The internal EWS URL is used.
2. `https://<domain>/autodiscover/autodiscover.xml` and `https://autodiscover.<domain>/autodiscover/autodiscover.xml`. The external EWS URL is used.

Address redirects are followed (at most three addresses); after a redirect to another domain only the Active Directory service connection points are used. HTTP redirects, redirect URLs and DNS SRV records are not used, and certificates are validated normally. An EWS URL returned by the DNS endpoints is used only if its host is inside the mailbox domain. An explicit `-Credential` is sent to Autodiscover and to a discovered EWS URL only with Negotiate or NTLM, never with Basic authentication; with an explicit `-EwsUrl` the server's normal authentication methods are used. The URL found is displayed, included in the confirmation prompt and recorded in `run.json`. One URL serves all mailboxes in the run, because every request names its target mailbox and Exchange routes it to the right server.

If Autodiscover fails, the error lists every URL tried. Specify `-EwsUrl`, for example the `InternalUrl` from `Get-WebServicesVirtualDirectory` in the Exchange Management Shell. Also specify `-EwsUrl` if EWS accepts only Basic authentication and you use `-Credential`: a discovered URL never receives the password with Basic authentication.

## Parameters

| Parameter | Description |
|---|---|
| EwsUrl | HTTPS URL of Exchange Web Services, for example `https://mail.contoso.com/EWS/Exchange.asmx`. Optional; found by Autodiscover if omitted. |
| ListTimeZones | Lists the Windows time zone IDs supported by Exchange. |
| Mailbox | SMTP addresses of the calendar owners. A delegate specifies the owner's address. With `-ListTimeZones` only used for Autodiscover. |
| FromWindowsTimeZoneId | Current Windows time zone ID of the items, for example `Pacific Standard Time`. |
| ReportPath | CSV report to create. Existing files are replaced only with `-Force`. |
| QueryStartDate | Start of the search window. A date without an offset is UTC midnight. Default: now. A series is included completely if any occurrence is in the window. |
| QueryWindowInDays | Length of the search window, 1 to 1825 days. Default: 365. |
| CsvPath | Reviewed report. Only these items are processed. |
| ToWindowsTimeZoneId | Target Windows time zone ID, for example `British Columbia Standard Time`. |
| LogDirectory | Directory for logs. Every run creates a new subdirectory. |
| Apply | Changes items. Without it the script only previews. Confirmation is requested unless `-Confirm:$false` is used. |
| Reconcile | Resolves items left incomplete by an interrupted run. |
| SearchDirectory | Log directory of the interrupted run. Include the log directory of an interrupted earlier `-Reconcile` run as well; all journals below these directories are read. |
| ResendNotification | With `-Reconcile`: resend the meeting update when it is unknown whether the update was sent. |
| Credential | EWS account. Default: the current Windows account. |
| Impersonation | Use EWS impersonation of the owner. |
| SkipSendPermissionCheck | Allows a delegate without Send on Behalf or Send As to migrate items and send the meeting updates. See [Delegates](#delegates). |
| MaxAttachmentHashSizeMB | File attachments up to this size are verified by SHA256, larger ones by name, type and size. Default: 25. Reruns and Reconcile verify each item with the limit that its migration used. |
| SkipVersionCheck | Do not check for a newer version. |

## Delegates

A delegate runs the script with their own credentials and specifies the owner's address in `-Mailbox`. Exchange lets a delegate with Editor permission on the owner's Calendar send meeting updates on behalf of the organizer even without Send on Behalf. The script is stricter: before changing anything for a mailbox, it checks in Active Directory that the account running it has Send on Behalf (`GrantSendOnBehalfTo`) or Send As for the owner, directly or through a security group. Otherwise the items are reported as `NotAttempted` with the error code `SendPermissionMissing` (or `SendPermissionUnknown` if Active Directory could not be read) and are not changed. Grant Send on Behalf, run the script as the owner, use `-Impersonation`, or add `-SkipSendPermissionCheck` if your organization accepts updates sent by Editor delegates. The check does not apply to the owner or to `-Impersonation`. With `-Reconcile` it applies only to `-ResendNotification`.

## Examples

```powershell
# List time zones (EWS URL found by Autodiscover for the current user)
.\Invoke-CalendarTimeZoneMigration.ps1 -ListTimeZones

# Report for two mailboxes, using an impersonation account
$cred = Get-Credential
.\Invoke-CalendarTimeZoneMigration.ps1 -EwsUrl https://mail.contoso.com/EWS/Exchange.asmx -Credential $cred -Impersonation `
    -Mailbox user1@contoso.com, user2@contoso.com -FromWindowsTimeZoneId "Pacific Standard Time" `
    -QueryStartDate 2026-11-01 -ReportPath .\Report.csv

# Preview, then apply the reviewed report
.\Invoke-CalendarTimeZoneMigration.ps1 -EwsUrl https://mail.contoso.com/EWS/Exchange.asmx -Credential $cred -Impersonation `
    -CsvPath .\Report.csv -ToWindowsTimeZoneId "British Columbia Standard Time" -LogDirectory .\Logs
.\Invoke-CalendarTimeZoneMigration.ps1 -EwsUrl https://mail.contoso.com/EWS/Exchange.asmx -Credential $cred -Impersonation `
    -CsvPath .\Report.csv -ToWindowsTimeZoneId "British Columbia Standard Time" -LogDirectory .\Logs -Apply
```

## Results and logs

Each run creates `<LogDirectory>\<RunId>` with:

- `run.json` - script version, file hash, EWS URL and how it was found, target time zone and number of selected items.
- `selection.csv` - the processed input. Use it as `-CsvPath` for `-Reconcile`.
- `mailboxes.csv` - one result line per mailbox.
- One folder per mailbox with `summary.txt` (counts and unsuccessful items, critical items first), `results.csv`, `details.jsonl` (append-only journal of every planned and acknowledged change, including the Exchange server that processed it) and before/after snapshots.

The logs contain calendar data and must be protected. File attachment content is not stored, only its SHA256 hash.

The journal is flushed after every write event, and each completed item's result is appended to its mailbox's
`results.csv`. Summaries and `mailboxes.csv` are finalized when the run finishes. If the process is interrupted,
use the journal and result CSVs for progress; the summaries may still show their initial counts.

| Status | Meaning |
|---|---|
| Applied | Changed and verified. |
| AlreadyMigrated | Already migrated by this script and unchanged since. |
| RolledBack | Failed before any meeting update was sent; the original state was restored and verified. |
| Failed | Rejected before any change, for example because the item changed after the report or the time zone rules differ. |
| Critical | Needs manual attention. See the error and `details.jsonl`. |
| Preview, WhatIf | No change was made: without `-Apply`, with `-WhatIf`, or after the confirmation prompt was declined. |
| NotAttempted | Not processed, for example because a delegate has neither Send on Behalf nor Send As, or logging failed. |
| NoAction | With `-Reconcile`: nothing to resolve. |

Exit code 0 means all items succeeded or were previewed, 1 means some items were not migrated, and 2 means at least one item needs manual attention.

## Failures and interrupted runs

- A failure before the meeting update is sent is rolled back automatically and verified.
- After a meeting update may have been sent, the item is never moved back automatically and the update is not resent. The item is reported as critical when its state cannot be verified.
- Every change first stores a marker on the item. If the script is interrupted (window closed, computer restarted), the marker blocks a new migration of that item. Run the script with `-Reconcile -CsvPath <RunId>\selection.csv -SearchDirectory <LogDirectory>`: items whose meeting update was not sent are restored to their original state; items whose update may have been sent are finalized in their verified new state, and with `-ResendNotification` the update is sent again. Items that cannot be proven are reported as critical and left unchanged.
- Server busy (throttling) responses are retried after the delay requested by Exchange. Consider a dedicated throttling policy for the account that runs large migrations.

## Limitations

- Items whose time zone rules cannot be represented safely are rejected before any change, for example partial recurrence definitions that cannot express the future rules of the target time zone.
- Items whose stored time zone definition differs from the current Windows rules of the source time zone for the affected years (for example definitions saved before a Windows time zone update) are rejected before any change, because their local times are ambiguous.
- A recurring meeting whose local time falls into a daylight saving gap of the target time zone on some dates (for example a series at 02:30) is shown by Exchange at the next valid time on those dates, as for any recurring meeting at that local time.
- When the original definition uses a single-rule source time zone (for example GMT Standard Time or UTC), its full and partial forms cannot be distinguished. The full form of the target time zone is written, which is correct in every year, and `AssumedFull` is recorded in the `O12Modes` column of `results.csv`.
- Items without Outlook time zone definitions (EWS reports them in a pseudo time zone such as `tzone://Microsoft/Utc`) cannot be matched to a source time zone. They are listed as warnings during the search and are not migrated.
- Items with IANA time zone names (for example `Europe/Lisbon`, created by Exchange Online and moved on-premises) are listed as warnings during the search and are not migrated.
- All-day recurring meetings whose UTC times do not change are rejected, because Exchange cannot merge such an update into attendee calendars reliably.
- Recurring series whose start and end time zones differ from each other are rejected.
- Recurring series are not migrated within one day of New Year (in the target time zone) when the target time zone has different rules in the old and the new year, for example British Columbia Standard Time around January 1, 2027. Run the script again after January 2.
- Mailboxes in Exchange Online cannot be processed through on-premises EWS.
- The script cannot detect items that users already corrected manually.
