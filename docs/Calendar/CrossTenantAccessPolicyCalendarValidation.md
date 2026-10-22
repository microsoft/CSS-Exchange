# CrossTenantAccessPolicyCalendarValidation

Download the latest release: [CrossTenantAccessPolicyCalendarValidation.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/CrossTenantAccessPolicyCalendarValidation.ps1)

Assesses whether Organization Relationships, Availability Address Spaces, and Sharing Policies can migrate to
[Microsoft 365 Cross-Tenant Access Policy (XTAP)](https://learn.microsoft.com/exchange/sharing/migrate-to-m365-xtap).
It explains eligibility and can generate commands for migration, testing, rollback, and cleanup.

The script is read-only. Configuration changes occur only when you review and run the generated scripts.

## Prerequisites

For live collection, connect to Exchange Online PowerShell with the **Organization Management** role:

```PowerShell
Connect-ExchangeOnline
```

The generated Part 2 script requires the Microsoft Graph PowerShell SDK and Global Administrator.
Offline analysis requires only a JSON bundle saved by this script.

## Usage

Save the script in a writable folder, then change to that folder before running it. Replace the example path below
with the folder where you saved the `.ps1` file. By default, all output files are saved together in a timestamped
results subfolder beside the script, even if you launch it from another working directory.

```PowerShell
# Change to the folder containing the script
Set-Location -LiteralPath 'C:\Path\To\Script'

# Assessment only
.\CrossTenantAccessPolicyCalendarValidation.ps1 -RunName BeforeMigration

# Include migration commands and mailbox counts per Sharing Policy
.\CrossTenantAccessPolicyCalendarValidation.ps1 -RunName BeforeMigration -GenerateCommandScripts -ProcessUsers

# Copy this script and the JSON bundle into one folder, then run:
.\CrossTenantAccessPolicyCalendarValidation.ps1 -ImportData '.\BeforeMigration_CrossTenantAccessPolicyCalendarValidation_Data.json'

# Generate commands from previously collected data
.\CrossTenantAccessPolicyCalendarValidation.ps1 -ImportData '.\BeforeMigration_CrossTenantAccessPolicyCalendarValidation_Data.json' -GenerateCommandScripts
```

## Parameters

| Parameter | Description |
| --- | --- |
| OutputPath | Parent folder for the timestamped results folder. Defaults to the folder containing the `.ps1` file. Specify another writable folder only when needed. |
| RunName | Optional label such as BeforeMigration or MonthlyValidation, used in folder/file names, JSON metadata, and report headers. Defaults to the saved run name when importing. Each run also has an automatic timestamp. |
| ImportData | Path to a previously saved JSON bundle. Replaces the separate CLIXML import parameters. Cannot be combined with ProcessUsers or Organization. |
| SkipTenantResolution | Skips public OpenID Connect tenant lookups. Only domain names are sent. Import mode defaults to the saved setting and never makes network requests. |
| EntraLoginHost | DNS host name for tenant lookup in sovereign clouds, without a scheme, port, path, or IP address. Defaults to login.microsoftonline.com in live mode; imports retain the saved host. |
| Organization | Live mode only. Targets the specified tenant using cmdlets supporting Organization. The saved organization is also used in generated commands during replay. Unsupported collection cmdlets cause an error; an unsupported mailbox cmdlet skips mailbox counts with a warning. |
| GenerateCommandScripts | Writes the optional XTAP Part 2, Part 3, rollback, and cleanup scripts for eligible items. |
| ProcessUsers | Live mode only. Counts user and shared mailboxes per Sharing Policy using Get-EXOMailbox, or Get-Mailbox if unavailable. Off by default because it queries every mailbox. Counts are included in the JSON bundle for replay. |
Live runs check for script updates automatically. ImportData automatically skips the update check, as well as live
collection and tenant lookups, so replay can run without network access.

Results are displayed in the console and saved to files; the script does not return a PowerShell results object.
Normal output uses the console's default text color so it follows your accessibility and contrast settings.
Warnings and errors retain their diagnostic colors.
For automation, read the saved JSON bundle:

```PowerShell
$data = Get-Content -LiteralPath .\BeforeMigration_CrossTenantAccessPolicyCalendarValidation_Data.json -Raw | ConvertFrom-Json
$data.Analysis.OrganizationRelationship
```

## Output and JSON replay

A new `<RunName>_XTAP_Calendar_<yyyyMMdd_HH.mm.ss>` folder contains the output. For example,
`-RunName Microsoft` produces `Microsoft_XTAP_Calendar_20261021_14.27.42`. Without a run name, the folder is
`XTAP_Calendar_20261021_14.27.42`. The timestamp uses local time, with dots separating hours, minutes, and seconds;
milliseconds are omitted. If the folder name already exists, a numeric suffix such as `_1` or `_2` keeps each run
separate without overwriting earlier output. Filenames inside the folder are unchanged:

| File | Contents |
| --- | --- |
| `*_CrossTenantAccessPolicyCalendarValidation_Data.json` | Versioned bundle with the summary near the top, invocation metadata, run errors, all collected configuration properties, optional mailbox counts, tenant resolution results (including failed lookups), analysis arrays, generated command text, and output file names. |
| `*_CrossTenantAccessPolicyCalendarValidation_Summary.txt` | Readable results, warnings, next steps, and the ImportData replay command. |
| `XTAP_Part2_CreatePolicies.ps1` | Optional commands to create XTAP partner policies and capabilities. |
| `XTAP_Part3_DisableForTesting.ps1`, `XTAP_Part3_Rollback.ps1` | Optional commands to disable the old configuration and restore it. Availability Address Space backups use JSON. |
| `XTAP_Part4_Cleanup.ps1` | Review-only cleanup commands. All configuration-changing commands are commented out, so running the file unchanged makes no changes. Deliberately uncomment commands or copy and run them individually after successful testing. |

Empty configuration and analysis collections remain JSON arrays. SharingPolicyAssignment is null when counts were not
collected, and an empty array when collection succeeded with no mailboxes. Exchange-specific values such as domains,
sharing rules, enums, directory identities, and URIs are stored as plain strings; booleans and numbers retain their types.
No XML or CSV data files are created. Existing CLIXML collections are not accepted by ImportData.

`Summary` immediately follows `SchemaVersion`. `Metadata.CommandLine` records the script path and resolved bound
parameter values, including explicit switch values; `Metadata.InvocationLine` preserves the original invocation text
when PowerShell provides it. `Metadata.User` identifies the local account executing PowerShell, not necessarily the
Exchange Online account. `Errors` contains structured errors raised during this run, including recoverable lookup
and mailbox-count failures, but excludes errors already present in the PowerShell session. It is an empty array when
no errors were recorded. Existing warnings and fatal-stop behavior are unchanged; a fatal failure can stop before JSON
is written. Replay records its own invocation, user, and errors rather than copying these fields from the input bundle.

Each `TenantResolution` entry also saves an `Error` string. Organization Relationship analysis includes a
`DomainTenantResolution` array containing each domain, tenant ID, status, and error. Availability Address Space and
Sharing Policy analysis expose `TenantResolutionStatus` or `TenantResolution`, plus `TenantResolutionError`.
These diagnostics distinguish failed lookups, invalid configured tenant IDs, and missing saved lookup data.
Offline replay retains the original lookup diagnostics without adding them to the replay run's `Errors` array.
Older version 1 bundles without per-domain errors remain supported; their failed lookups report that no detailed
error was saved.

Import mode recalculates analysis from saved configuration using saved tenant lookups, without querying Exchange or
Microsoft Entra. RunName can be overridden. Older bundles using CustomerName are still imported as a run label; new bundles
write RunName only. The folder timestamp, summary generation time, and JSON Metadata.GeneratedUtc identify when each run
was performed, even when the same run label is reused. GenerateCommandScripts controls whether scripts are written on each run,
regardless of whether the original collection included them. Missing or incompatible bundles cause an error.

These files contain organization configuration, external domains, command lines and paths, the executing user, and
error details. Review them before sharing outside your organization.

## Statuses

| Status | Meaning |
| --- | --- |
| Eligible | Can migrate now. Commands can be generated. |
| Review | Needs manual confirmation, such as an unresolved tenant ID. |
| NotEligible | Cannot migrate now; notes explain why. Keep the existing configuration. |
| Disabled | Not currently sharing. Potential capabilities if enabled are assessed separately; no migration commands are generated. |
| NothingToMigrate | No supported Free/Busy or MailTips sharing enabled. |
| MailboxMoveOnly | Used only for mailbox moves. Keep it. |

## Migration safeguards

- On-premises, hybrid, non-Microsoft 365, and Google Workspace targets cannot migrate to XTAP.
- An explicit `FYDIBOHF25SPDLT` on-premises indicator in an Availability Address Space takes precedence over a
  configured tenant ID. Invalid configured tenant IDs require review rather than being replaced by a lookup.
- Only OrgWideFBToken Availability Address Spaces qualify.
- ContactsSharing rules and Sharing Policy domains belonging to hybrid relationships remain in place.
- Organization Relationships are checked for MailboxMove, IdentityMove, PeopleSearch, ArchiveAccess, DeliveryReport,
  and Photos functionality. MailboxMove and IdentityMove are detected from either their enabled flag or capability.
  Relationships with additional functionality are never disabled or removed by generated commands; only their
  Free/Busy and MailTips settings change, with rollback restoring those settings. Verify current XTAP support and
  preserve or split any functionality that is not covered before manually retiring a relationship.
- With tenant resolution enabled, **every** Organization Relationship domain must resolve before the relationship
  is eligible. Partially resolved relationships require review and are excluded from migration, testing, and cleanup
  scripts. Missing domain names also require review, even when lookup is skipped. Skipping lookup retains guarded
  tenant-ID placeholders for otherwise eligible relationships.
- Scoped sharing requires security groups in XTAP. Validate scope behavior to avoid over-sharing.
- Domains resolving to multiple tenants require separate partner policies.
- XTAP is inbound; bidirectional sharing requires complementary external policies.
- Existing relationships, address spaces, and sharing policies take precedence and must be disabled to test XTAP.
- Generated scripts contain guarded placeholders for unknown tenant IDs or security groups. Replace them before running.
- All Step 4 changes, including deletion and sharing-setting changes, are commented out until you deliberately enable them.
  Deletion is permanent. Retain the collected JSON bundle, Part 3 rollback script, and backups; Part 3 rollback does not
  recreate Organization Relationships or Sharing Policies deleted during Step 4.
- Microsoft Graph cmdlet names can change; confirm them against the linked migration documentation.

## Additional assessment details

Organization Relationship analysis includes `AdditionalEnabledFunctionalities`,
`AdditionalFunctionalitiesRecommendation`, and `SharingCapabilityWouldBeEligibleIfEnabled`. Disabled relationships
retain potential capabilities in `FreeBusyCapabilityIfEnabled` and `MailTipsCapabilityIfEnabled`, while their active
capability fields remain empty. Disabled Sharing Policy rows similarly expose
`CalendarCapabilityWouldBeEligibleIfEnabled` and `RecommendedCapabilityIfEnabled`. These are assessments of current
settings, not instructions to enable legacy configuration, and do not make disabled items eligible for command generation.

Sharing Policy analysis retains one row per action, including ContactsSharing. `HasContactsSharing` and
`ContactsSharingAssessment` describe the entire original rule, even on its calendar action rows.
`LegacyRuleCanBeRetired` is false when the policy is disabled, the calendar action is not eligible, or the original
rule contains ContactsSharing or another unsupported action. Generated commands continue to preserve any policy
containing an ineligible rule.

Availability Address Space analysis includes the original `ConfiguredTargetTenantId`, `TargetTenantIdValid`,
`ResolvedEntraTenantId`, and a migration recommendation. Migration is optional and is not required because of
EWS deprecation.

## Acknowledgments

<!-- cspell:ignore Mirela Buruiana -->

Credit to Mirela Buruiana for the idea and first draft of this script.
