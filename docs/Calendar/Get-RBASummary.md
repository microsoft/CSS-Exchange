# Get-RBASummary

Download the latest release: [Get-RBASummary.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-RBASummary.ps1)


This script runs the Get-CalendarProcessing cmdlet and returns the output with more details in clear english, highlighting the key settings that affect RBA and some of the common errors in configuration.

The script will validate the mailbox is the correct type for RBA to interact with via the Get-Mailbox cmdlet.


Syntax:

Example to display the setting of room mailbox.
```PowerShell
.\Get-RBASummary.ps1 -Identity Room1@Contoso.com
```
