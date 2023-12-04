# Set-ExchAVExclusions

Download the latest release: [Set-ExchAVExclusions.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Set-ExchAVExclusions.ps1)

The Script will assist in setting the Antivirus Exclusions according to our documentation for Microsoft Exchange Server.

[AV Exclusions Exchange 2016/2019](https://docs.microsoft.com/en-us/Exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019)

[AV Exclusions Exchange 2013](https://docs.microsoft.com/en-us/exchange/anti-virus-software-in-the-operating-system-on-exchange-servers-exchange-2013-help)

If you use Windows Defender you can Set the exclusions executing the script without parameters but if you have any other Antivirus solution you can get the full list of Expected Exclusions.

## Requirements
#### Supported Exchange Server Versions:
The script can be used to validate the configuration of the following Microsoft Exchange Server versions:
- Microsoft Exchange Server 2013
- Microsoft Exchange Server 2016
- Microsoft Exchange Server 2019

The server must have Microsoft Defender to set it and enable it to be effective.

#### Required Permissions:
Please make sure that the account used is a member of the `Local Administrator` group. This should be fulfilled on Exchange servers by being a member of the  `Organization Management` group.

## How To Run
This script **must** be run as Administrator in Exchange Management Shell on an Exchange Server. You do not need to provide any parameters and the script will set the Windows Defender exclusions for the local Exchange server.

If you want to get the full list of expected exclusions you should use the parameter `ListRecommendedExclusions`

You can export the Exclusion List with the parameter `FileName`

## Parameters

Parameter | Description |
----------|-------------|
ListRecommendedExclusions | Get the full list of expected exclusions without set.
FileName | Export the Exclusion List.
SkipVersionCheck | Skip script version verification.
ScriptUpdateOnly | Just update script version to latest one.


#### Examples:

This will run Set-ExchAVExclusions Script against the local server.

```
.\Set-ExchAVExclusions.ps1
```

This will run Set-ExchAVExclusions Script against the local server and show in screen the expected exclusions on screen without setting them.

```
.\Set-ExchAVExclusions.ps1 -ListRecommendedExclusions
```

This will run Set-ExchAVExclusions Script against the local server and show in screen the expected exclusions on screen without setting them and write them in the defined `FileName`.

```
.\Set-ExchAVExclusions.ps1 -ListRecommendedExclusions -FileName .\Exclusions.txt
```

This will run Set-ExchAVExclusions Script against the local server and write them in the defined `FileName`.

```
.\Set-ExchAVExclusions.ps1 -FileName .\Exclusions.txt
```

## Outputs

Exclusions List File:
`FileName`

Log file:
$PSScriptRoot\SetExchAvExclusions.log
