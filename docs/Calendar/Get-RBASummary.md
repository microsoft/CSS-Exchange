# Get-RBASummary

Download the latest release: [Get-RBASummary.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-RBASummary.ps1)


This script runs the Get-CalendarProcessing cmdlet and returns the output with more details in clear English, highlighting the key settings that affect RBA and some of the common errors in configuration.

The script will validate the mailbox is the correct type for RBA to interact with via the Get-Mailbox cmdlet.


Syntax:

Example to display the setting of room mailbox.
```PowerShell
.\Get-RBASummary.ps1 -Identity Room1@Contoso.com

.\Get-RBASummary.ps1 -Identity Room1@Contoso.com -VerbosePreference
```

Here are the high-level steps for RBA processing:
1. Determine in the Meeting Request is in policy or out of policy.
2. If the meeting request is Out of Policy, see if the user has rights to create out of policy request and if so, forward it to the Delegates.
3. If it is In Policy, then either book it or forward it to the delegate based on the settings.
4. Lastly the RBA does the configured Post Processes the meeting format (delete attachments, rename meeting, etc.)

So the first thing that RBA does is to look if the meeting is in or out of policy.  How does it do this? It looks at the first group of rules that are setup. If they all 'pass' then the meeting request is in Policy, otherwise it is out of policy.

wheather the meeting is in or out of policy, the RBA will look up the configuration that will tell it what to do with the meeting. By default all out of policy meetings are rejected, and all in policy meetings are accepted, but there is a larger range of customization that you can do to get the RBA to treat this resource the way you want it to.

If the meeting is accepted, the RBA will do some Post Processing on it based on the rules setup. 
