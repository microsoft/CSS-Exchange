# Set-ExchAVExclusions

Download the latest release: [Set-ExchAVExclusions.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Set-ExchAVExclusions.ps1)

The Script will assist on setting Microsoft Defender Exclusions according to our documentation for Microsoft Exchange Server.

[AV Exclusions Exchange 2016/2019](https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019)

[AV Exclusions Exchange 2013](https://docs.microsoft.com/en-us/exchange/anti-virus-software-in-the-operating-system-on-exchange-servers-exchange-2013-help)

## Requirements
#### Supported Exchange Server Versions:
The script can be used to validate the configuration of the following Microsoft Exchange Server versions:
- Microsoft Exchange Server 2013
- Microsoft Exchange Server 2016
- Microsoft Exchange Server 2019

The server must have Microsoft Defender enabled.

#### Required Permissions:
Please make sure that the account used is a member of the `Local Administrator` group. This should be fulfilled on Exchange servers by being a member of the  `Organization Management` group.

## How To Run
This script **must** be run as Administrator in Exchange Management Shell on an Exchange Server. You do not need to provide any parameters and the script will set the Windows Defender exclusions for the local Exchange server.

#### Examples:

This will run Set-ExchAVExclusions Script against the local server.
It will show the exclusions on screen and write them on the log file.

```
.\Set-ExchAVExclusions.ps1
```

## Outputs

Log file:
$env:LOCALAPPDATA\SetExchAvExclusions.log
