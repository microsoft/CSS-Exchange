# Test-XtapMigrationReadiness

Download the latest release: [Test-XtapMigrationReadiness.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-XtapMigrationReadiness.ps1)

This script helps you move to Microsoft 365 Cross-Tenant Access Policy (XTAP) as described in
[Migrate to Microsoft 365 Cross-Tenant Access Policy for sharing Free/Busy, Calendars, and MailTips](https://learn.microsoft.com/exchange/sharing/migrate-to-m365-xtap).

It collects your Organization Relationships, Availability Address Spaces and Sharing Policies, tells you which ones can be upgraded to XTAP now (and why the others can't), and, when you ask for it, generates the cmdlets to do the upgrade.

By default the script is an assessment only. Use `-GenerateCommandScripts` to also create the cmdlet scripts, and `-ProcessUsers` to count the mailboxes assigned to each Sharing Policy.

The script itself is read-only. It never changes your configuration. The generated scripts change configuration only when you review and run them.

## Prerequisites

- Connect to Exchange Online PowerShell first with an account assigned the **Organization Management** role. The script doesn't connect for you.

```PowerShell
Connect-ExchangeOnline
```

- To run the generated Part 2 script you need the Microsoft Graph PowerShell SDK and the Global Administrator role.

## Usage

```PowerShell
# Assessment only
.\Test-XtapMigrationReadiness.ps1 -CustomerName Contoso -OutputPath C:\Temp

# Assessment plus the cmdlet scripts, counting mailboxes per Sharing Policy
.\Test-XtapMigrationReadiness.ps1 -CustomerName Contoso -GenerateCommandScripts -ProcessUsers

# Analyze files that were collected earlier (no Exchange Online connection needed)
.\Test-XtapMigrationReadiness.ps1 `
    -OrganizationRelationshipXml .\OrgRel.xml `
    -AvailabilityAddressSpaceXml .\AAS.xml `
    -SharingPolicyXml .\SharingPolicy.xml
```

## Parameters

| Parameter | Description |
| --- | --- |
| OutputPath | Folder where the results folder is created. Defaults to the current directory. |
| CustomerName | Optional name used in the folder and file names. |
| OrganizationRelationshipXml, AvailabilityAddressSpaceXml, SharingPolicyXml | Offline analysis. CLIXML files from `Get-OrganizationRelationship`, `Get-AvailabilityAddressSpace` and `Get-SharingPolicy`. All three are required together. |
| SharingPolicyAssignmentXml | Offline analysis. Optional mailbox count per Sharing Policy. |
| SkipTenantResolution | Skips the tenant ID lookup. By default each external domain is looked up at `login.microsoftonline.com` (only domain names are sent). Without the lookup, the generated scripts contain `<placeholders>` for tenant IDs. |
| EntraLoginHost | Host for the tenant ID lookup, for sovereign clouds. |
| Organization | Runs against a specific tenant (a domain or tenant ID). Passes `-Organization` to `Get-OrganizationRelationship`, `Get-AvailabilityAddressSpace`, `Get-SharingPolicy` and `Get-EXOMailbox` (or `Get-Mailbox`), and adds it to the Exchange cmdlets and `Connect-MgGraph -TenantId` in the generated scripts. The script stops if your session's cmdlets don't support the parameter, and skips the mailbox count if the mailbox cmdlet doesn't. Live mode only. |
| GenerateCommandScripts | Also creates the `XTAP_Part*.ps1` cmdlet scripts for the eligible items. Without it only the assessment files are created. |
| ProcessUsers | Counts the mailboxes assigned to each Sharing Policy with `Get-EXOMailbox -ResultSize Unlimited`, or `Get-Mailbox` when `Get-EXOMailbox` isn't available (for example in support sessions). It queries every mailbox, so it is off by default and can be slow in large organizations. It only matters when more than one Sharing Policy is in use, because the generated sharing commands then need security groups. Live mode only. Offline analysis can use `SharingPolicyAssignmentXml`. |
| PassThru | Returns the results folder path and analysis rows. |
| SkipVersionCheck | Skips the automatic update check. |

## Output

A new `XtapReadiness_<CustomerName>_<date>` folder contains:

| File | Contents |
| --- | --- |
| `*_OrganizationRelationships.xml`, `*_AvailabilityAddressSpaces.xml`, `*_SharingPolicies.xml`, `*_SharingPolicyAssignment.xml` | Raw collected data. Send these to support to replay the analysis offline. |
| `*_Analysis.csv` | One wide row per item with the raw properties, status, recommended capability and notes. |
| `*_XtapReadiness_Summary.txt` | Key results, warnings and next steps. |
| `XTAP_Part2_CreatePolicies.ps1` (with `-GenerateCommandScripts`) | Creates the XTAP partner policies and capabilities. |
| `XTAP_Part3_DisableForTesting.ps1` and `XTAP_Part3_Rollback.ps1` | Disable the old configuration so XTAP can be tested, and undo that. |
| `XTAP_Part4_Cleanup.ps1` | Removes the old configuration after testing succeeds. |

The files contain your external domain names. Review them before sharing them outside your organization.

## Statuses

| Status | Meaning |
| --- | --- |
| Eligible | Can be upgraded now. Commands are generated. |
| Review | Needs a manual check first (for example, the tenant ID couldn't be determined). |
| NotEligible | Can't be upgraded at this time. The Notes column says why. Keep the existing configuration. |
| Disabled | Not sharing anything today. |
| NothingToMigrate | No Free/Busy or MailTips sharing is enabled. |
| MailboxMoveOnly | Only used for mailbox moves. Keep it. |

## What can't be upgraded

- Relationships to on-premises Exchange or hybrid organizations (including `O365 to On-premises - <GUID>` created by the Hybrid Configuration Wizard), and to non-Microsoft 365 organizations. XTAP only applies between Microsoft 365 organizations.
- Availability Address Spaces that don't use `OrgWideFBToken`, and those that target Google Workspace.
- Sharing Policy `ContactsSharing` rules.
- Sharing Policy rules for domains that belong to on-premises or hybrid relationships.

## Things the script warns about

- A relationship that also has mailbox move settings is never disabled or removed, because that would break mailbox moves. The Part 3 and Part 4 scripts only turn off its Free/Busy and MailTips settings, and the Part 3 rollback restores them with their original level and scope.
- A Free/Busy or MailTips scope group needs a security group in XTAP. XTAP doesn't yet honor `FreeBusyAccessScope`, which risks over-sharing, so confirm before disabling the relationship.
- Domains in one relationship that resolve to different tenants get one XTAP partner policy for each tenant.
- XTAP is inbound. For two-way sharing, the external organization must create complementary policies.
- Existing Organization Relationships, Availability Address Spaces and Sharing Policies take precedence over XTAP, so they must be disabled to test XTAP.

## Notes

- The Microsoft Graph cross-tenant access policy cmdlet names used in the generated Part 2 script can change. Confirm them against the documentation if a cmdlet isn't found.
- The generated scripts contain `<placeholders>` (for tenant IDs and security groups) that must be replaced. The scripts stop with an error if a placeholder remains.
