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
Make sure to connect to Exchange Online before running this script.
