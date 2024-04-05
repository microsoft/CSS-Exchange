# HealthChecker

Download the latest release: [HealthChecker.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/HealthChecker.ps1)

The Exchange Server Health Checker script helps detect common configuration issues that are known to cause performance issues and other long running issues that are caused by a simple configuration change within an Exchange Environment. It also helps collect useful information of your server to help speed up the process of common information gathering of your server.


## Requirements
#### Supported Exchange Server Versions:
The script can be used to validate the configuration of the following Exchange Server versions:
- Exchange Server 2016
- Exchange Server 2019

#### Required Permissions:
Please make sure that the account used is a member of the `Local Administrator` group. This should be fulfilled on Exchange servers by being a member of the  `Organization Management` group. However, if the group membership was adjusted or in case the script is executed on a non-Exchange system like a management server, you need to add your account to the `Local Administrator` group. You also need to be a member of the following groups:

- Organization Management
- Domain Admins (only necessary for the `DCCoreRatio` parameter)

# Syntax

```powershell
HealthChecker.ps1
  [-Server <string[]>]
  [-OutputFilePath <string>]
  [-SkipVersionCheck]
  [-SaveDebugLog]
HealthChecker.ps1
  [-Server <string[]>]
  [-MailboxReport]
  [-OutputFilePath <string>]
  [-SkipVersionCheck]
  [-SaveDebugLog]
HealthChecker.ps1
  [-LoadBalancingReport]
  [-ServerList <string[]>]
  [-SiteName <string>]
  [-OutputFilePath <string>]
  [-SkipVersionCheck]
  [-SaveDebugLog]
HealthChecker.ps1
  [-BuildHtmlServersReport]
  [-XMLDirectoryPath <string>]
  [-HtmlReportFile <string>]
  [-OutputFilePath <string>]
  [-SkipVersionCheck]
  [-SaveDebugLog]
HealthChecker.ps1
  [-AnalyzeDataOnly]
  [-XMLDirectoryPath <string>]
  [-HtmlReportFile <string>]
  [-OutputFilePath <string>]
  [-SkipVersionCheck]
  [-SaveDebugLog]
HealthChecker.ps1
  [-DCCoreRatio]
  [-OutputFilePath <string>]
  [-SkipVersionCheck]
  [-SaveDebugLog]
HealthChecker.ps1
  [-ScriptUpdateOnly]
  [-OutputFilePath <string>]
  [-SaveDebugLog]
HealthChecker.ps1
  [-VulnerabilityReport]
  [-OutputFilePath <string>]
  [-SkipVersionCheck]
  [-SaveDebugLog]
```

## How To Run
This script **must** be run as Administrator in Exchange Management Shell on an Exchange Server. You can provide no parameters and the script will just run against the local server and provide the detail output of the configuration of the server.

#### Examples:

This cmdlet with run Health Checker Script by default and run against the local server.

```powershell
PS C:\> .\HealthChecker.ps1
```

This cmdlet will run the Health Checker Script against the specified server.

```powershell
PS C:\> .\HealthChecker.ps1 -Server EXCH1
```

This cmdlet will run the Health Checker Script against a list of servers.

```powershell
PS C:\> .\HealthChecker.ps1 -Server EXCH1,EXCH2,EXCH3
```

This cmdlet will build the HTML report for all the XML files located in the same location as the Health Checker Script.

```powershell
PS C:\> .\HealthChecker.ps1 -BuildHtmlServersReport
```

This cmdlet will build the HTML report for all the XML files located in the directory specified in the XMLDirectoryPath Parameter.

```powershell
PS C:\> .\HealthChecker.ps1 -BuildHtmlServersReport -XMLDirectoryPath C:\Location
```

This cmdlet will run the Health Checker Load Balancing Report for all the Exchange CAS (Front End connections only) and MBX servers (BackEnd connections) in the Organization.

```powershell
PS C:\> .\HealthChecker.ps1 -LoadBalancingReport
```

This cmdlet will run the Health Checker Load Balancing Report for these Servers EXCH1, EXCH2, and EXCH3 CAS (Front End connections) and MBX  (BackEnd Connections)

```powershell
PS C:\> .\HealthChecker.ps1 -LoadBalancingReport -ServerList EXCH1,EXCH2,EXCH3
```

This cmdlet will run the Health Checker Load Balancing Report for the Exchange servers in the site SiteA.

```powershell
PS C:\> .\HealthChecker.ps1 -LoadBalancingReport -SiteName SiteA
```

This cmdlet will run the Health Checker Mailbox Report against the Server EXCH1

```powershell
PS C:\> .\HealthChecker.ps1 -MailboxReport -Server EXCH1
```

This cmdlet will run the Health Checker against all your Exchange Servers, then run the HTML report and open it.

```powershell
PS C:\> Get-ExchangeServer | ?{$_.AdminDisplayVersion -Match "^Version 15"} | .\HealthChecker.ps1; .\HealthChecker.ps1 -BuildHtmlServersReport -HtmlReportFile "ExchangeAllServersReport.html"; .\ExchangeAllServersReport.html
```

This cmdlet will run Health Checker Vulnerability Report feature against all your Exchange Servers. Then Export out the data to a json file.

```powershell
PS C:\> .\HealthChecker.ps1 -VulnerabilityReport
```

## Parameters

Parameter | Description
----------|------------
Server | The server that you would like to run the Health Checker Script against. Parameter not valid with -BuildHTMLServersReport or LoadBalancingReport. Default is the localhost.
OutputFilePath | The output location for the log files that the script produces. Default is the current directory.
MailboxReport | Produces the Mailbox Report for the server provided.
LoadBalancingReport | Runs the Load Balancing Report for the Script
ServerList | Used in combination with the LoadBalancingReport switch for letting the script to know which servers to run against.
SiteName | Used in combination with the LoadBalancingReport switch for letting the script to know which servers to run against in the site.
XMLDirectoryPath | Used in combination with BuildHtmlServersReport switch for the location of the HealthChecker XML files for servers which you want to be included in the report. Default location is the current directory.
BuildHtmlServersReport | Switch to enable the script to build the HTML report for all the servers XML results in the XMLDirectoryPath location.
HtmlReportFile | Name of the HTML output file from the BuildHtmlServersReport. Default is ExchangeAllServersReport-yyyyMMddHHmmss.html
DCCoreRatio | Gathers the Exchange to DC/GC Core ratio and displays the results in the current site that the script is running in.
AnalyzeDataOnly | Switch to analyze the existing HealthChecker XML files. The results are displayed on the screen and an HTML report is generated.
VulnerabilityReport | Switch to collect the Vulnerability Information for all the servers in the environment and export it out to json file.
SkipVersionCheck | No version check is performed when this switch is used.
SaveDebugLog | The debug log is kept even if the script is executed successfully.
ScriptUpdateOnly | Switch to check for the latest version of the script and perform an auto update if a newer version was found. Can be run on any machine with internet connectivity. No elevated permissions or EMS are required.

