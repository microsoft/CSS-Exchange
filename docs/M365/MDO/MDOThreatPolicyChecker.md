# MDOThreatPolicyChecker
This script checks which Microsoft Defender for Office 365 and Exchange Online Protection threat policies cover a particular user, including anti-malware, anti-phishing, inbound and outbound anti-spam, as well as Safe Attachments and Safe Links policies in case these are licensed for your tenant. In addition, the script can check for threat policies that have inclusion and/or exclusion settings that may be redundant or confusing and lead to missed coverage of users or coverage by an unexpected threat policy.

## Download
Download the latest release: [MDOThreatPolicyChecker.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/MDOThreatPolicyChecker.ps1)

## Parameters

Parameter | Description |
----------|-------------|
CsvFilePath | Allows you to specify a CSV file with a list of email addresses to check. Csv file must include a first line with header Email.
EmailAddresses | Allows you to specify email address or multiple addresses separated by commas.
IncludeMDOPolicies | Checks both EOP and MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddresses parameter.
OnlyMDOPolicies | Checks only MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddresses parameter.
ShowDetailedPolicies | In addition to the policy applied, show any policy details that are set to True, On, or not blank.
SkipConnectionCheck | Skips connection check for Graph and Exchange Online.
ScriptUpdateOnly | Just updates script version to latest one.

## Common Usage
The script uses Exchange Online cmdlets from Exchange Online module and Microsoft.Graph cmdLets from Microsoft.Graph.Authentication, Microsoft.Graph.Groups and Microsoft.Graph.Users modules.

After downloading the script, you need an Exchange Online session.<br>
&nbsp;&nbsp;&nbsp;&nbsp;`Connect-ExchangeOnline`

You can find the Exchange module and information in the following links:<br>
&nbsp;&nbsp;&nbsp;&nbsp;https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps<br>
&nbsp;&nbsp;&nbsp;&nbsp;https://www.powershellgallery.com/packages/ExchangeOnlineManagement

To run the PowerShell Graph cmdlets used in this script, you need only the following modules from the Microsoft.Graph PowerShell SDK:
- Microsoft.Graph.Groups: Contains cmdlets for managing groups, including Get-MgGroup and Get-MgGroupMember.
- Microsoft.Graph.Users: Includes cmdlets for managing users, such as Get-MgUser.
- Microsoft.Graph.Authentication: Required for authentication purposes and to run any cmdlet that interacts with Microsoft Graph.

You can find the Microsoft Graph modules in the following link:<br>
&nbsp;&nbsp;&nbsp;&nbsp;https://www.powershellgallery.com/packages/Microsoft.Graph/<br>
&nbsp;&nbsp;&nbsp;&nbsp;https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0#installation

Here's how you can install the required submodules for the PowerShell Graph SDK cmdlets:

&nbsp;&nbsp;&nbsp;&nbsp;`Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser`<br>
&nbsp;&nbsp;&nbsp;&nbsp;`Install-Module -Name Microsoft.Graph.Groups -Scope CurrentUser`<br>
&nbsp;&nbsp;&nbsp;&nbsp;`Install-Module -Name Microsoft.Graph.Users -Scope CurrentUser`<br>

Remember to run these commands in a PowerShell session with the appropriate permissions. The -Scope CurrentUser parameter installs the modules for the current user only, which doesn't require administrative privileges.

In the Graph connection you will need the following scopes 'Group.Read.All','User.Read.All'<br>
&nbsp;&nbsp;&nbsp;&nbsp;`Connect-MgGraph -Scopes 'Group.Read.All','User.Read.All'`

## Examples:
To check all threat policies for potentially confusing user inclusion and/or exclusion conditions and print them out for review, run the following:<br>
&nbsp;&nbsp;&nbsp;&nbsp;`.\MDOThreatPolicyChecker.ps1`

To provide a CSV input file with email addresses and see only EOP policies, run the following:<br>
&nbsp;&nbsp;&nbsp;&nbsp;`.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv]`

To provide multiple email addresses by command line and see only EOP policies, run the following:<br>
&nbsp;&nbsp;&nbsp;&nbsp;`.\MDOThreatPolicyChecker.ps1 -EmailAddresses user1@contoso.com,user2@fabrikam.com`

To provide a CSV input file with email addresses and see both EOP and MDO policies, run the following:<br>
&nbsp;&nbsp;&nbsp;&nbsp;`.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv] -IncludeMDOPolicies`

To provide an email address and see only MDO (Safe Attachment and Safe Links) policies, run the following:<br>
&nbsp;&nbsp;&nbsp;&nbsp;`.\MDOThreatPolicyChecker.ps1 -EmailAddresses user1@contoso.com -OnlyMDOPolicies`

To see the details of the policies applied to mailbox in a CSV file for both EOP and MDO, run the following:<br>
&nbsp;&nbsp;&nbsp;&nbsp;`.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv] -IncludeMDOPolicies -ShowDetailedPolicies`

To get all mailboxes in your tenant and print out their EOP and MDO policies, run the following:<br>
&nbsp;&nbsp;&nbsp;&nbsp;`.\MDOThreatPolicyChecker.ps1 -IncludeMDOPolicies -EmailAddresses @(Get-ExOMailbox -ResultSize unlimited | Select-Object -ExpandProperty PrimarySmtpAddress)`