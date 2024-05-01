# AllEOP-AppliedTo-User.ps1

Download the latest release: [AllEOP-AppliedTo-User.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/AllEOP-AppliedTo-User.ps1)

 This script checks which Exchange Online threat policies cover a particular user according to our documentation, including anti-malware, anti-phishing, inbound anti-spam and outbound anti-spam:

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

