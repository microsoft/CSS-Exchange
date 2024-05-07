# MDOThreatPolicyChecker.ps1

Download the latest release: [MDOThreatPolicyChecker.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/MDOThreatPolicyChecker.ps1)

 This script checks which Microsoft Defender for Office 365 and Exchange Online Protection threat policies cover a particular user, including anti-malware, anti-phishing, inbound and outbound anti-spam, as well as Safe Attachments and Safe Links policies in case these are licensed for your tenant.

[Order and Precedence of Email Protection](https://learn.microsoft.com/en-us/defender-office-365/how-policies-and-protections-are-combined?view=o365-worldwide)

[Policy Setting in Preset Security Policies](https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies#appendix)

In addition, the script can check for threat policies that have inclusion and/or exclusion settings that may be redundant and confusing and lead to coverage of users by an unexpected threat policy.

## Which policy applies to a user?
1. The script ignores disabled policies, invalid inclusions, and accounts for exclusions to find which policy applies to a user or users.
2. Threat policies use AND logic between different types of **inclusion** conditions (Users, Groups, Domains). Different types of **exceptions** use OR logic (Users, Groups, Domains). This script takes this logic into account to indicate which policy of each type actually applies to a user.
3. Checks group membership of a user or users in Microsoft 365 Groups for inclusion or exclusion in a policy.

## Are your threat policies ambiguous or potentially confusing?
- When run without parameters, the script checks all threat policies for potentially confusing user inclusion and/or exclusion conditions and prints them out for your review.

## Additional Notes
Just read-only permissions are needed as the script only reads policies.

Preset rules, if applied to a user, have no configurable or visible properties. Their set values are documented in link above.

## How To Run
This script requires permissions in Microsoft Defender XDR RBAC, Exchange Online, or Microsoft Entra ID, as explained here:

[Permissions to Configure EOP](https://learn.microsoft.com/en-us/defender-office-365/anti-malware-policies-configure#what-do-you-need-to-know-before-you-begin)

## Parameters

Parameter | Description |
----------|-------------|
CsvFilePath | Path and file name with list of email addresses.
EmailAddresses | Email address or multiple addresses separated by commas.
OutputFilePath | File with users and policies applied.
SkipVersionCheck | Skip script version verification.
ScriptUpdateOnly | Just update script version to latest one.
SkipConnectionCheck | Skip connection check for AzureAD and ExchangeOnline

#### Examples:

This will take 2 recipient mailboxes and print the anti-malware, anti-phishing, inbound anti-spam, and outbound anti-spam policies that apply to them on screen:

```
.\AllEOP-AppliedTo-User.ps1 -EmailAddresses john@domain1.com,sue@domain2.com
```
This will take a CSV input file with email addresses and print them to a file:

```
.\AllEOP-AppliedTo-User.ps1 -CsvFilePath C:\Scripts\Input\Addresses.txt -OutputFilePath C:\Scripts\Output\PoliciesApplied.txt
```


# MDO-EOP-Rule-Logic-Check.ps1

This script retrieves various types of Security/Threat policies from an Exchange Online environment and checks for logical inconsistencies in their configuration.

## DESCRIPTION
The script first defines a hashtable of cmdlets that are used to retrieve different types of policies from Exchange Online, including Presets, anti-phishing/spam/malware, and built-in. Each cmdlet is associated with a specific policy type.

It then loops through each cmdlet, invoking it to retrieve the corresponding policies. For each policy, it checks the inclusion and exclusion properties for logical inconsistencies. These properties define which users, groups, or domains the policy applies to or excludes.

The checks performed are as follows:
1. If individual users are included and excluded, it prints a message indicating that the policy could only apply to users listed in the inclusions.
2. If email domains are included and excluded, it prints a message indicating that the policy could only apply to domains listed in the inclusions.
3. If users are included along with groups, it prints a message indicating that the policy will only apply to users who are also members of any groups specified, making the group inclusion redundant and confusing.
4. If users are included along with domains, it prints a message indicating that the policy will only apply to users whose email domains also match any domains specified, making the domain inclusion redundant and confusing.
5. If no logical inconsistencies found, prints that out.
6. This script is backed by documentation about script priorities and behavior at the time of writing.

## NOTES
The script checks for connection to AzureAD and Exchange Online, and, if not connected, connects you before running this script.
Only read-only permissions are needed as the script only reads from policies.

# SA-SL-Policies-AppliedTo-User.ps1

Download the latest release: [SA-SL-Policies-AppliedTo-User.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/SA-SL-Policies-AppliedTo-User.ps1)

 This script checks which Defender for Office 365 threat policies cover a particular user according to our documentation, including Safe Links and Safe Attachments:

 [Order and Precedence of Email Protection](https://learn.microsoft.com/en-us/defender-office-365/how-policies-and-protections-are-combined?view=o365-worldwide)

[Policy Setting in Preset Security Policies](https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies#appendix)

## Which policy applies to USER?
1. Ignores disabled policies, invalid inclusions, and accounts for exclusions to find which policy applies to USER.
2. As documented, the script uses AND logic between different types of **inclusion** conditions (Users, Groups, Domains).
3. Different types of **exceptions** use OR logic (Users, Groups, Domains).
4. Checks group membership of USER in Microsoft 365 Groups for inclusion or exclusion in a policy.

## Additional Notes
Just read-only permissions are needed as the script only reads policies.

Preset rules, if applied to USER, have no configurable or visible properties. Their set values documented in link above.

## How To Run
This script requires permissions in Microsoft Defender XDR RBAC, Exchange Online, or Microsoft Entra ID, as explained here:

[Permissions to Configure MDO](https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure?view=o365-worldwide#what-do-you-need-to-know-before-you-begin)
