# Get-RBASummary

Download the latest release: [Get-RBASummary.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-RBASummary.ps1)


This script runs the Get-CalendarProcessing cmdlet and returns the output with more details in clear English, highlighting the key settings that affect RBA and some of the common errors in configuration.

The script will also validate the mailbox is the correct type for RBA to interact with (via the Get-Mailbox cmdlet) as well as check for any Delegate rules that would interfere with RBA functionality (via the Get-InboxRules cmdlet).


#### Syntax:

Example to display the setting of room mailbox.
```PowerShell
.\Get-RBASummary.ps1 -Identity Room1@Contoso.com

.\Get-RBASummary.ps1 -Identity Room1 -Verbose
```

##### High-level steps for RBA processing: <br>

1. Determine if the Meeting Request is in policy or out of policy.<br>
2. If the meeting request is Out of Policy, see if the user has rights to create an Out of Policy request and if so, forward it to the Delegates.<br>
3. If it is In Policy, then either book it or forward it to the delegate based on the settings.<br>
4. Lastly the RBA does the configured Post Processing steps to format the meeting (delete attachments, rename meeting, etc.)<br>


When the RBA receives a Meeting Request, the first thing that it will do is to determine if the meeting is in or out of policy.  How does the RBA do this? The RBA compares the Meeting properties to the Policy Configuration. If all the checks 'pass', then the meeting request is In Policy, otherwise it is Out of Policy.

Whether the meeting is in or out of policy, the RBA will look up the configuration that will tell it what to do with the meeting. By default, all out of policy meetings are rejected, and all in policy meetings are accepted, but there is a larger range of customization that you can do to get the RBA to treat this resource the way you want it to.

If the meeting is accepted, the RBA will Post Process it based on the Post Processing configuration. 

