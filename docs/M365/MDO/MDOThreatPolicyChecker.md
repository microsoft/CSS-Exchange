# MDOThreatPolicyChecker
 This script checks which Microsoft Defender for Office 365 and Exchange Online Protection threat policies cover a particular user, including anti-malware, anti-phishing, inbound and outbound anti-spam, as well as Safe Attachments and Safe Links policies in case these are licensed for your tenant. In addition, the script can check for threat policies that have inclusion and/or exclusion settings that may be redundant or confusing and lead to missed coverage of users or coverage by an unexpected threat policy.

## Download
Download the latest release: [MDOThreatPolicyChecker.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/MDOThreatPolicyChecker.ps1)

## Parameters

Parameter | Description |
----------|-------------|
CsvFilePath | Allows you to specify a CSV file with a list of email addresses to check.
EmailAddresses | Allows you to specify email address or multiple addresses separated by commas.
IncludeMDOPolicies | Checks both EOP and MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddresses parameter.
OnlyMDOPolicies | Checks only MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddresses parameter.
SkipConnectionCheck | Skips connection check for Graph and Exchange Online.
ScriptUpdateOnly | Just updates script version to latest one.

## Common Usage
After downloading the script, you must be connected to both Exchange Online and Microsoft Graph PowerShell to run it.

To check all threat policies for potentially confusing user inclusion and/or exclusion conditions and print them out for review, run the following: `.\MDOThreatPolicyChecker.ps1`

To provide a CSV input file with email addresses and see only EOP policies, run the following: `.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv]`

To provide multiple email addresses by command line and see only EOP policies, run the following: `.\MDOThreatPolicyChecker.ps1 -EmailAddresses user1@domainX.com,user2@domainY.com`

To provide a CSV input file with email addresses and see both EOP and MDO policies, run the following: `.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv] -IncludeMDOPolicies`

To provide an email address and see only MDO (Safe Attachment and Safe Links) policies, run the following: `.\MDOThreatPolicyChecker.ps1 -EmailAddresses user1@domainX.com -OnlyMDOPolicies`
