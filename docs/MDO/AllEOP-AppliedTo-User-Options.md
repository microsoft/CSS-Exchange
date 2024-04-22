# AllEOP-AppliedTo-User-Options.ps1

## Checks which MDO/EOP threat policies cover a particular user.

## Which policy applies to USER?
1. Checks only for enabled policies and accounts for inclusions/exclusions within enabled policies.
2. Input can be an individual's email address or a CSV file.
3. Prints rule priority and policy/rule that applies. If none, prints Default policy. Priority property 0 is highest.
4. Option to print to screen or to an output file.
5. Checks any existing groups in AAD to get members.
6. This script is backed by documentation about script priorities and behavior at the time of writing.
- CONSIDERATIONS: Preset rules have no configurable or visible properties. Their set values documented here:
       https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide#policy-settings-in-preset-security-policies


## Notes
Make sure to connect to both AzureAD and Exchange Online before running this script.
