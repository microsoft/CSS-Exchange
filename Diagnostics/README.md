# HealthChecker

[![Build Status](https://dev.azure.com/CSS-Exchange-Tools/Exchange%20Health%20Checker/_apis/build/status/dpaulson45.HealthChecker?branchName=master)](https://dev.azure.com/CSS-Exchange-Tools/Exchange%20Health%20Checker/_build/latest?definitionId=5&branchName=master)
[![Downloads](https://img.shields.io/github/downloads/dpaulson45/HealthChecker/total.svg?label=Downloads&maxAge=9999)](https://github.com/dpaulson45/HealthChecker/releases)

The Exchange Server Health Checker script helps detect common configuration issues that are known to cause performance issues and other long running issues that are caused by a simple configuration change within an Exchange Environment. It also helps collect useful information of your server to help speed up the process of common information gathering of your server.

# Download
To download this script, download the latest version [here](https://aka.ms/ExHCDownload)

Or go to the [Releases](https://github.com/dpaulson45/HealthChecker/releases) page and select `HealthChecker.ps1` asset to download.

# Requirements
### Supported Exchange Server Versions:
The script can be used to validate the configuration of the following Exchange Server versions:
- Exchange Server 2013
- Exchange Server 2016
- Exchange Server 2019

You can use the latest v2 release to validate the configuration of `Exchange Server 2010`. Please note that this version is no longer maintained and some checks are not available.

You can download the latest v2 release [here](https://aka.ms/ExHCDownloadv2)

### Required Permissions:
Please make sure that the account used is a member of the `Local Administrator` group. This should be fulfilled on Exchange servers by being a member of the  `Organization Management` group. However, if the group membership was adjusted or in case the script is executed on a non-Exchange system like a management server, you need to add your account to the `Local Administrator` group. You also need to be a member of the following groups:

- Organization Management
- Domain Admins (only necessary for the `DCCoreRatio` parameter)

# How To Run
This script **must** be run as Administrator in Exchange Management Shell on an Exchange Server. You can provide no parameters and the script will just run against the local server and provide the detail output of the configuration of the server.

### Examples:

This cmdlet with run Health Checker Script by default and run against the local server.

```
.\HealthChecker.ps1
```

This cmdlet will run the Health Checker Script against the specified server.

```
.\HealthChecker.ps1 -Server EXCH1
```
This cmdlet will build the HTML report for all the XML files located in the same location as the Health Checker Script.

```
.\HealthChecker.ps1 -BuildHtmlServersReport
```

This cmdlet will build the HTML report for all the XML files located in the directory specified in the XMLDirectoryPath Parameter.

```
.\HealthChecker.ps1 -BuildHtmlServersReport -XMLDirectoryPath C:\Location
```

This cmdlet will run the Health Checker Load Balancing Report for all the Exchange 2013/2016 CAS (Front End connections only) in the Organization.

```
.\HealthChecker.ps1 -LoadBalancingReport
```

This cmdlet will run the Health Checker Load Balancing Report for these Servers EXCH1, EXCH2, and EXCH3

```
.\HealthChecker.ps1 -LoadBalancingReport -CasServerList EXCH1,EXCH2,EXCH3
```

This cmdlet will run the Health Checker Load Balancing Report for the Exchange 2013/2016 CAS (Front End connections only) in the site SiteA.

```
.\HealthChecker.ps1 -LoadBalancingReport -SiteName SiteA
```

This cmdlet will run the Health Checker Mailbox Report against the Server EXCH1

```
.\HealthChecker.ps1 -MailboxReport -Server EXCH1
```

This cmdlet will run the Health Checker against all your Exchange Servers, then run the HTML report and open it.

```
Get-ExchangeServer | ?{$_.AdminDisplayVersion -Match "^Version 15"} | %{.\HealthChecker.ps1 -Server $_.Name}; .\HealthChecker.ps1 -BuildHtmlServersReport; .\ExchangeAllServersReport.html
```

# Parameters

Parameter | Description
----------|------------
Server | The server that you would like to run the Health Checker Script against. Parameter not valid with -BuildHTMLServersReport or LoadBalancingReport. Default is the localhost.
OutputFilePath | The output location for the log files that the script produces. Default is the current directory.
MailboxReport | Produces the Mailbox Report for the server provided.
LoadBalancingReport | Runs the Load Balancing Report for the Script
CasServerList | Used in combination with the LoadBalancingReport switch for letting the script to know which servers to run against.
SiteName | Used in combination with the LoadBalancingReport switch for letting the script to know which servers to run against in the site.
XMLDirectoryPath | Used in combination with BuildHtmlServersReport switch for the location of the HealthChecker XML files for servers which you want to be included in the report. Default location is the current directory.
BuildHtmlServersReport | Switch to enable the script to build the HTML report for all the servers XML results in the XMLDirectoryPath location.
HtmlReportFile | Name of the HTML output file from the BuildHtmlServersReport. Default is ExchangeAllServersReport.html
DCCoreRatio | Gathers the Exchange to DC/GC Core ratio and displays the results in the current site that the script is running in.

# Exchange Log Collector

[![Build Status](https://dev.azure.com/CSS-Exchange-Tools/Exchange%20Log%20Collector/_apis/build/status/dpaulson45.ExchangeLogCollector?branchName=master)](https://dev.azure.com/CSS-Exchange-Tools/Exchange%20Log%20Collector/_build/latest?definitionId=8&branchName=master)

This script is intended to collect the Exchange default logging data from the server in a consistent manner to make it easier to troubleshoot an issue when large amounts of data is needed to be collected. You can specify what logs you want to collect by the switches that are available, then the script has logic built in to determine how to collect the data.

# Download
To download this script, download the latest version [here](https://github.com/dpaulson45/ExchangeLogCollector/releases)

# How to Run
The script **must** be run as Administrator in PowerShell session on an Exchange Server or Tools box. Supported to run and collected logs against Exchange 2013 and greater. The intent of the script is to collect logs only that you need from X servers quickly without needing to have to manually collect it yourself and label zip them all up for you. If you don't know what logs to collect, it is recommended to use `-AllPossibleLogs`.

This script no longer supports collecting logs from Exchange 2010. However, the last release of v2 should still work just fine. You can download that [here](https://github.com/dpaulson45/ExchangeLogCollector/releases/tag/v2.17.1).

The script is able to collect from the large set of servers while using the Invoke-Command. Prior to executing the main script, we check to make sure the server is up and that we are able to use Invoke-Command against the server. If Invoke-Command works remotely, then we will allow you to attempt to collect the data. You can still utilize the script to collect locally as it used to be able to, if the target OS doesn't allow this.

Prior to collecting the data, we check to make sure that there is at least 10GB of free space at the location of where we are trying to save the data of the target server. The script will continue to keep track of all the logs and data that is being copied over and will stop if we have less than 10GB of free space.

You are able to use a config file to load up all the parameters you wish to choose and the servers you wish to run the script against. Just create a file called `ExchangeLogCollector.ps1.json` and place at the same location as the script. Then provide the switches you would like to use in the file like so:

```
{
  "Servers": [
    "ADT-E16A",
    "ADT-E16B",
    "ADT-E16C"
  ],
  "FilePath": "C:\\MS_Logs",
  "IISLogs": true,
  "AcceptEULA": true,
  "AppSysLogsToXml": false,
  "ScriptDebug": true
}
```

**NOTE:** It is import that you use `\\` for the file path otherwise the settings will fail to load.

Examples:

This cmdlet will collect all default logs of the local Exchange Server and store them in the default location of "C:\MS_Logs_Collection"

```
.\ExchangeLogCollector.ps1 -AllPossibleLogs
```

This cmdlet will collect all relevant data regarding database failovers from server EXCH1 and EXCH2 and store them at Z:\Data\Logs. Note: at the end of the collection, the script will copy over the data to the local host execution server to make data collection even easier.

```
.\ExchangeLogCollector.ps1 -DatabaseFailoverIssue -Servers EXCH1,EXCH2 -FilePath Z:\Data\Logs
```

This cmdlet will collect all relevant data regarding IIS Logs (within the last 3 days by default) and all RPC type logs from the servers EXCH1 and EXCH2 and store them at the default location of "C:\MS_Logs_Collection"

```
.\ExchangeLogCollector.ps1 -Servers EXCH1,EXCH2 -IISLogs -RPCLogs
```

# Parameters

Parameter | Description |
----------|-------------|
FilePath | The Location of where you would like the data to be copied over to. This location **must** be the same and accessible on all servers if you use the Servers parameter. Default value: C:\MS_Logs_Collection |
Servers | An array of servers that you would like to collect data from.
ADDriverLogs | Enable to collect AD Driver Logs. Location: `V15\Logging\ADDriver`
AppSysLogs | Collects the Windows Event Application, System, and MSExchange Management Logs. Default value `$true`
AppSysLogsToXml | Collects the Windows Event Application and System and saves them out to XML. The date range only is from the time the script run and the value set on `DaysWorth`. Default value: `$true`
AutoDLogs | Enable to collect AutoDiscover Logs. Location: `V15\Logging\Autodiscover` and `V15\Logging\HttpProxy\Autodiscover`
CollectFailoverMetrics | Enable to run the `CollectOverMetrics.ps1` script against the DAG. Only able to be run on an Exchange tools box or an Exchange Server.
DAGInformation | Enable to collect the DAG Information from all different DAGs that are in the list of servers.
DailyPerformanceLogs | Enable to collect Daily Performance Logs. Default Location: `V15\Logging\Diagnostics\DailyPerformanceLogs`
DefaultTransportLogging | Enables the following switches and their logs to be collected. `FrontEndConnectivityLogs`, `FrontEndProtocolLogs`, `HubConnectivityLogs`, `MailboxConnectivityLogs`, `MailboxDeliveryThrottlingLogs`, `MessageTrackingLogs`, `QueueInformation`, `ReceiveConnectors`, `SendConnectors`, and `TransportConfig`
EASLogs | Enable to collect Exchange Active Sync Logging. Location: `V15\Logging\HttpProxy\Eas`
ECPLogs | Enable to collect ECP Logs. Location: `V15\Logging\ECP` and `V15\Logging\HttpProxy\Ecp`
EWSLogs | Enable to collect EWS Logs. Location: `V15\Logging\HttpProxy\Ews` and `V15\Logging\Ews`
ExchangeServerInformation | Enable to collect Exchange Information like Get-ExchangeServer, Get-MailboxServer, etc... This is also collected when `-ServerInformation` is also enabled.
Exmon | Enable to collect exmon data from the server.
Experfwiz | Enable to collect Experfwiz data if found.
FrontEndConnectivityLogs | Enable to collect the connectivity logging on the FE. Location: `(Get-FrontendTransportService $server).ConnectivityLogPath`
FrontEndProtocolLogs | Enable to collect the protocol logging on the FE. Location: `(Get-FrontendTransportService $server).ReceiveProtocolLogPath` and `(Get-FrontendTransportService $server).SendProtocolLogPath`
GetVdirs | Enable to collect the Virtual Directories of the environment.
HighAvailabilityLogs | Enable to collect High Availability Logs. Windows Event Logs like: `Microsoft-Exchange-HighAvailability`, `Microsoft-Exchange-MailboxDatabaseFailureItems`, and `Microsoft-Windows-FailoverClustering`
HubConnectivityLogs | Enable to collect the Hub connectivity logging. Location: `(Get-TransportService $server).ConnectivityLogPath`
HubProtocolLogs | Enable to collect the protocol logging. Location: `(Get-TransportService $server).ReceiveProtocolLogPath` and `(Get-TransportService $server).SendProtocolLogPath`
IISLogs | Enable to collect IIS Logs and HTTPErr Logs from the Exchange Server. Default Location: `C:\inetpub\logs\LogFiles\W3SVC1`, `C:\inetpub\logs\LogFiles\W3SVC1`, and `C:\Windows\System32\LogFiles\HTTPERR`. Only able to collect on DaysWorth.
ImapLogs | Enable to collect IMAP logging. Location: `(Get-ImapSettings -Server $server).LogFileLocation`
MailboxConnectivityLogs | Enable to collect the connectivity logging on the mailbox server. Location: `(Get-MailboxTransportService $server).ConnectivityLogPath`
MailboxDeliveryThrottlingLogs | Enable to collect the mailbox delivery throttling logs on the server. Location: `(Get-MailboxTransportService $server).MailboxDeliveryThrottlingLogPath`
MailboxProtocolLogs | Enable to collect protocol logging on the mailbox server. Location: `(Get-MailboxTransportService $server).ReceiveProtocolLogPath` and `(Get-MailboxTransportService $server).SendProtocolLogPath`
ManagedAvailabilityLogs | Enable to collect the Managed Availability Logs. Location: `V15\Logging\Monitoring` and Windows Event logs like `Microsoft-Exchange-ManagedAvailability`
MapiLogs | Enable to collect MAPI Logs. Location: `V15\Logging\MAPI Client Access`, `V15\Logging\MapiHttp\Mailbox`, and `V15\Logging\HttpProxy\Mapi`
MessageTrackingLogs | Enable to collect the Message Tracking Logs. Location: `(Get-TransportService $server).MessageTrackingLogPath`
OABLogs | Enable to collect OAB Logs. Location: `V15\Logging\HttpProxy\OAB`, `V15\Logging\OABGeneratorLog`, `V15\Logging\OABGeneratorSimpleLog`, and `V15\Logging\MAPI AddressBook Service`
OrganizationConfig | Enable to collect the Organization Configuration from the environment.
OWALogs | Enable to collect OWA Logs. Location: `V15\Logging\OWA`, `Logging\HttpProxy\OwaCalendar`, and `V15\Logging\HttpProxy\Owa`
PopLogs | Enable to collect POP logging. Location: `(Get-PopSettings -Server $server).LogFileLocation`
PowerShellLogs | Enable to collect the PowerShell Logs. Location: `V15\Logging\HttpProxy\PowerShell`
QueueInformation | Enable to collect the historical queue information. Location: `(Get-TransportService $server).QueueLogPath`
ReceiveConnectors | Enable to collect the Receive Connector information from the server.
RPCLogs | Enable to collect RPC Logs. Location: `V15\Logging\RPC Client Access`, `V15\Logging\HttpProxy\RpcHttp`, and `V15\Logging\RpcHttp`
SearchLogs | Enable to collect Search Logs. Location: `V15\Bin\Search\Ceres\Diagnostics\Logs`, `V15\Bin\Search\Ceres\Diagnostics\ETLTraces`, `V15\Logging\Search`. On 2019 only we also include `V15\Logging\BigFunnelMetricsCollectionAssistant`, `V15\Logging\BigFunnelQueryParityAssistant`, and `V15\Logging\BigFunnelRetryFeederTimeBasedAssistant`
SendConnectors | Enable to collect the send connector information from the environment.
ServerInformation | Enable to collect general server information.
TransportConfig | Enable to collect the Transport Configuration from the Server. Files: `EdgeTransport.exe.config`, `MSExchangeFrontEndTransport.exe.config`, `MSExchangeDelivery.exe.config`, and `MSExchangeSubmission.exe.config`
WindowsSecurityLogs | Enable to collect the Windows Security Logs. Default Location: `'C:\Windows\System32\Winevt\Logs\Security.evtx'`
AcceptEULA | Enable to accept the conditions of the script and not get prompted.
AllPossibleLogs | Enables the collection of all default logging collection on the Server.
CollectAllLogsBasedOnDaysWorth | Boolean to determine if you collect all the logs based off day's worth or all the logs in that directory. Default value `$true`
DatabaseFailoverIssue | Enables the following switches and their logs to be collected. `DAGInformation`, `DailyPerformanceLogs`, `ExchangeServerInformation`, `Experfwiz`, `HighAvailabilityLogs`, `ManagedAvailabilityLogs`, and `ServerInformation`.
DaysWorth | The number of days to go back from today for log collection. Default value: 3
DisableConfigImport | Enable to not import the `ExchangeLogCollector.ps1.json` file if it exists.
ExmonLogmanName | A list of names that we want to collect for Exmon data. The default name is `Exmon_Trace`.
ExperfwizLogmanName | A list of names that we want to collect performance data logs from. The default names are `Exchange_Perfwiz` and `ExPerfwiz`. (For both styles of Experfwiz)
ConnectivityLogs | Enables the following switches and their logs to be collected: `FrontEndConnectivityLogs`, `HubConnectivityLogs`, and `MailboxConnectivityLogs`
OutlookConnectivityIssues | Enables the following switches and their logs to be collected: `AutoDLogs`, `DailyPerformanceLogs`, `EWSLogs`, `Experfwiz`, `IISLogs`, `MAPILogs`, `RPCLogs`, and `ServerInformation`
PerformanceIssues | Enables the following switches and their logs to be collected: `DailyPerformanceLogs`, `Experfwiz`, and `ManagedAvailabilityLogs`
PerformanceMailflowIssues | Enables the following switches and their logs to be collected: `DailyPerformanceLogs`, `Experfwiz`, `MessageTrackingLogs`, `QueueInformation`, and `TransportConfig`
ProtocolLogs | Enables the following switches and their logs to be collected: `FrontEndProtocolLogs`, `HubProtocolLogs`, and `MailboxProtocolLogs`
ScriptDebug | Enable to display all the verbose lines in the script.
SkipEndCopyOver | If the Servers parameter is used, by default we will attempt to collect all the data back over to the local server after all the data was collected on each server.
