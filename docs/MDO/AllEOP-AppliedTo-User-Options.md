# AllEOP-AppliedTo-User-Options.ps1

## Checks which MDO/EOP threat policies cover a particular user.

## Which policy applies to USER?
1. Ignores disabled policies and accounts for inclusions/exclusions within enabled policies.
2. Input can be an individual's email address or a CSV file.
3. Prints rule priority and policy/rule that applies. If none, prints Default policy. Priority property 0 is highest.
4. Option to print to screen or to an output file.
5. Checks any existing groups in AAD to get groups and members.
6. This script is backed by documentation about script priorities and behavior at the time of writing.
- CONSIDERATIONS: Preset rules have no configurable or visible properties. Their set values documented here:
       https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide#policy-settings-in-preset-security-policies

## Notes
The script checks for connection to AzureAD and Exchange Online, and, if not connected, connects you before running this script.
Only read-only permissions needed as the script only reads from the policies.
