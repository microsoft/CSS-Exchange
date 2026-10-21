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

```PowerShell
# Assessment only
.\CrossTenantAccessPolicyCalendarValidation.ps1 -RunName BeforeMigration -OutputPath C:\Temp

# Include migration commands and mailbox counts per Sharing Policy
.\CrossTenantAccessPolicyCalendarValidation.ps1 -RunName BeforeMigration -GenerateCommandScripts -ProcessUsers

# Replay a collected JSON bundle without Exchange Online or network lookups
.\CrossTenantAccessPolicyCalendarValidation.ps1 -ImportData .\BeforeMigration_CrossTenantAccessPolicyCalendarValidation_Data.json

# Generate commands from previously collected data
.\CrossTenantAccessPolicyCalendarValidation.ps1 -ImportData .\BeforeMigration_CrossTenantAccessPolicyCalendarValidation_Data.json -GenerateCommandScripts
```

## Parameters

| Parameter | Description |
| --- | --- |
| OutputPath | Parent folder for the timestamped results folder. Defaults to the current directory. |
| RunName | Optional label such as BeforeMigration or MonthlyValidation, used in folder/file names, JSON metadata, and report headers. Defaults to the saved run name when importing. Each run also has an automatic timestamp. |
| ImportData | Path to a previously saved JSON bundle. Replaces the separate CLIXML import parameters. Cannot be combined with ProcessUsers or Organization. |
| SkipTenantResolution | Skips public OpenID Connect tenant lookups. Only domain names are sent. Import mode defaults to the saved setting and never makes network requests. |
| EntraLoginHost | Tenant lookup host for sovereign clouds. Defaults to login.microsoftonline.com in live mode; imports retain the saved host. |
| Organization | Live mode only. Targets the specified tenant using cmdlets supporting Organization. The saved organization is also used in generated commands during replay. Unsupported collection cmdlets cause an error; an unsupported mailbox cmdlet skips mailbox counts with a warning. |
| GenerateCommandScripts | Writes the optional XTAP Part 2, Part 3, rollback, and cleanup scripts for eligible items. |
| ProcessUsers | Live mode only. Counts user and shared mailboxes per Sharing Policy using Get-EXOMailbox, or Get-Mailbox if unavailable. Off by default because it queries every mailbox. Counts are included in the JSON bundle for replay. |
Live runs check for script updates automatically. ImportData automatically skips the update check, as well as live
collection and tenant lookups, so replay can run without network access.

Results are displayed in the console and saved to files; the script does not return a PowerShell results object.
For automation, read the saved JSON bundle:

```PowerShell
$data = Get-Content -LiteralPath .\BeforeMigration_CrossTenantAccessPolicyCalendarValidation_Data.json -Raw | ConvertFrom-Json
$data.Analysis.OrganizationRelationship
```

## Output and JSON replay

A new `CrossTenantAccessPolicyCalendarValidation_<RunName>_<timestamp>` folder contains:

| File | Contents |
| --- | --- |
| `*_CrossTenantAccessPolicyCalendarValidation_Data.json` | Versioned bundle with metadata, all collected configuration properties, optional mailbox counts, tenant resolution results (including failed lookups), analysis arrays, summary lines, generated command text, and output file names. |
| `*_CrossTenantAccessPolicyCalendarValidation_Summary.txt` | Readable results, warnings, next steps, and the ImportData replay command. |
| `XTAP_Part2_CreatePolicies.ps1` | Optional commands to create XTAP partner policies and capabilities. |
| `XTAP_Part3_DisableForTesting.ps1`, `XTAP_Part3_Rollback.ps1` | Optional commands to disable the old configuration and restore it. Availability Address Space backups use JSON. |
| `XTAP_Part4_Cleanup.ps1` | Review-only cleanup commands. All configuration-changing commands are commented out, so running the file unchanged makes no changes. Deliberately uncomment commands or copy and run them individually after successful testing. |

Empty configuration and analysis collections remain JSON arrays. SharingPolicyAssignment is null when counts were not
collected, and an empty array when collection succeeded with no mailboxes. Exchange-specific values such as domains,
sharing rules, enums, directory identities, and URIs are stored as plain strings; booleans and numbers retain their types.
No XML or CSV data files are created. Existing CLIXML collections are not accepted by ImportData.

Import mode recalculates analysis from saved configuration using saved tenant lookups, without querying Exchange or
Microsoft Entra. RunName can be overridden. Older bundles using CustomerName are still imported as a run label; new bundles
write RunName only. The folder timestamp, summary generation time, and JSON Metadata.GeneratedUtc identify when each run
was performed, even when the same run label is reused. GenerateCommandScripts controls whether scripts are written on each run,
regardless of whether the original collection included them. Missing or incompatible bundles cause an error.

These files contain organization configuration and external domains. Review them before sharing outside your organization.

## Statuses

| Status | Meaning |
| --- | --- |
| Eligible | Can migrate now. Commands can be generated. |
| Review | Needs manual confirmation, such as an unresolved tenant ID. |
| NotEligible | Cannot migrate now; notes explain why. Keep the existing configuration. |
| Disabled | Not currently sharing. |
| NothingToMigrate | No supported Free/Busy or MailTips sharing enabled. |
| MailboxMoveOnly | Used only for mailbox moves. Keep it. |

## Migration safeguards

- On-premises, hybrid, non-Microsoft 365, and Google Workspace targets cannot migrate to XTAP.
- Only OrgWideFBToken Availability Address Spaces qualify.
- ContactsSharing rules and Sharing Policy domains belonging to hybrid relationships remain in place.
- Relationships used for mailbox moves are never disabled or removed; only their sharing settings change.
- Scoped sharing requires security groups in XTAP. Validate scope behavior to avoid over-sharing.
- Domains resolving to multiple tenants require separate partner policies.
- XTAP is inbound; bidirectional sharing requires complementary external policies.
- Existing relationships, address spaces, and sharing policies take precedence and must be disabled to test XTAP.
- Generated scripts contain guarded placeholders for unknown tenant IDs or security groups. Replace them before running.
- All Step 4 changes, including deletion and sharing-setting changes, are commented out until you deliberately enable them.
  Deletion is permanent. Retain the collected JSON bundle, Part 3 rollback script, and backups; Part 3 rollback does not
  recreate Organization Relationships or Sharing Policies deleted during Step 4.
- Microsoft Graph cmdlet names can change; confirm them against the linked migration documentation.

## Acknowledgments

<!-- cspell:ignore Mirela Buruiana -->

Credit to Mirela Buruiana for the idea and first draft of this script.
