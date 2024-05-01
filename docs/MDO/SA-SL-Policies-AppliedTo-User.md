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
