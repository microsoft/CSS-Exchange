# Exchange Log Collector

Download the latest release: [ExchangeLogCollector.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ExchangeLogCollector.ps1)

This script is intended to collect the Exchange default logging data from the server in a consistent manner to make it easier to troubleshoot an issue when large amounts of data is needed to be collected. You can specify what logs you want to collect by the switches that are available, then the script has logic built in to determine how to collect the data.

## How to Run

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
  "AppSysLogsToXml": false,
  "ScriptDebug": true
}
```

**NOTE:** It is import that you use `\\` for the file path otherwise the settings will fail to load.

### Examples:

This cmdlet will collect all default logs of the local Exchange Server and store them in the default location of "C:\MS_Logs_Collection"

```
.\ExchangeLogCollector.ps1 -AllPossibleLogs
```

This cmdlet will collect all relevant data regarding database fail overs from server EXCH1 and EXCH2 and store them at Z:\Data\Logs. Note: at the end of the collection, the script will copy over the data to the local host execution server to make data collection even easier.

```
.\ExchangeLogCollector.ps1 -DatabaseFailoverIssue -Servers EXCH1,EXCH2 -FilePath Z:\Data\Logs
```

This cmdlet will collect all relevant data regarding IIS Logs (within the last 3 days by default) and all RPC type logs from the servers EXCH1 and EXCH2 and store them at the default location of "C:\MS_Logs_Collection"

```
.\ExchangeLogCollector.ps1 -Servers EXCH1,EXCH2 -IISLogs -RPCLogs
```

This cmdlet will collect all relevant data regarding Message Tracking Logs and Protocol Logs for the past 3 hours from the servers EXCH1 and EXCH2 and store them at the default location of "C:\MS_Logs_Collection"

```
.\ExchangeLogCollector.ps1 -Servers EXCH1,EXCH2 -MessageTrackingLogs -ProtocolLogs -LogAge "03:00:00"
```

## Parameters

Parameter | Description |
----------|-------------|
FilePath | The Location of where you would like the data to be copied over to. This location **must** be the same and accessible on all servers if you use the Servers parameter. Default value: C:\MS_Logs_Collection |
Servers | An array of servers that you would like to collect data from.
AcceptedRemoteDomain | Enable to collect `Get-AcceptedDomain` and `Get-RemoteDomain`.
ADDriverLogs | Enable to collect AD Driver Logs. Location: `V15\Logging\ADDriver`
AppSysLogs | Collects the Windows Event Application, System, and MSExchange Management Logs. Default value `$true`
AppSysLogsToXml | Collects the Windows Event Application and System and saves them out to XML. The time range only is from the time the script run and the value set on `LogAge`. Default value: `$true`
AutoDLogs | Enable to collect AutoDiscover Logs. Location: `V15\Logging\Autodiscover` and `V15\Logging\HttpProxy\Autodiscover`
CollectFailoverMetrics | Enable to run the `CollectOverMetrics.ps1` script against the DAG. Only able to be run on an Exchange tools box or an Exchange Server.
DAGInformation | Enable to collect the DAG Information from all different DAGs that are in the list of servers.
DailyPerformanceLogs | Enable to collect Daily Performance Logs. Default Location: `V15\Logging\Diagnostics\DailyPerformanceLogs`
DefaultTransportLogging | Enables the following switches and their logs to be collected. `AcceptedRemoteDomain`, `FrontEndConnectivityLogs`, `FrontEndProtocolLogs`, `HubConnectivityLogs`, `MailboxConnectivityLogs`, `MailboxDeliveryThrottlingLogs`, `MessageTrackingLogs`, `PipelineTracingLogs`, `QueueInformation`, `ReceiveConnectors`, `SendConnectors`, `TransportConfig`, `TransportRoutingTableLogs`, and `TransportRules`
EASLogs | Enable to collect Exchange Active Sync Logging. Location: `V15\Logging\HttpProxy\Eas`
ECPLogs | Enable to collect ECP Logs. Location: `V15\Logging\ECP` and `V15\Logging\HttpProxy\Ecp`
EWSLogs | Enable to collect EWS Logs. Location: `V15\Logging\HttpProxy\Ews` and `V15\Logging\Ews`
ExchangeServerInformation | Enable to collect Exchange Information like Get-ExchangeServer, Get-MailboxServer, etc... This is also collected when `-ServerInformation` is also enabled.
ExMon | Enable to collect ExMon data from the server.
ExPerfWiz | Enable to collect ExPerfWiz data if found.
FrontEndConnectivityLogs | Enable to collect the connectivity logging on the FE. Location: `(Get-FrontendTransportService $server).ConnectivityLogPath`
FrontEndProtocolLogs | Enable to collect the protocol logging on the FE. Location: `(Get-FrontendTransportService $server).ReceiveProtocolLogPath` and `(Get-FrontendTransportService $server).SendProtocolLogPath`
GetVDirs | Enable to collect the Virtual Directories of the environment.
HighAvailabilityLogs | Enable to collect High Availability Logs. Windows Event Logs like: `Microsoft-Exchange-HighAvailability`, `Microsoft-Exchange-MailboxDatabaseFailureItems`, and `Microsoft-Windows-FailoverClustering`
HubConnectivityLogs | Enable to collect the Hub connectivity logging. Location: `(Get-TransportService $server).ConnectivityLogPath`
HubProtocolLogs | Enable to collect the protocol logging. Location: `(Get-TransportService $server).ReceiveProtocolLogPath` and `(Get-TransportService $server).SendProtocolLogPath`
IISLogs | Enable to collect IIS Logs and HTTPErr Logs from the Exchange Server. Default Location: `C:\InetPub\logs\LogFiles\W3SVC1`, `C:\InetPub\logs\LogFiles\W3SVC2`, and `C:\Windows\System32\LogFiles\HTTPERR`. IISlogs do not collect all logs on CollectAllLogsBasedOnLogAge:$false, just works based on log age.
ImapLogs | Enable to collect IMAP logging. Location: `(Get-ImapSettings -Server $server).LogFileLocation`
MailboxAssistantsLogs | Enable to collect Mailbox Assistants logging. Location: `V15\Logging\MailboxAssistantsLog`, `V15\Logging\MailboxAssistantsSlaReportLog`, and `V15\Logging\MailboxAssistantsDatabaseSlaLog`
MailboxConnectivityLogs | Enable to collect the connectivity logging on the mailbox server. Location: `(Get-MailboxTransportService $server).ConnectivityLogPath`
MailboxDeliveryThrottlingLogs | Enable to collect the mailbox delivery throttling logs on the server. Location: `(Get-MailboxTransportService $server).MailboxDeliveryThrottlingLogPath`
MailboxProtocolLogs | Enable to collect protocol logging on the mailbox server. Location: `(Get-MailboxTransportService $server).ReceiveProtocolLogPath` and `(Get-MailboxTransportService $server).SendProtocolLogPath`
ManagedAvailabilityLogs | Enable to collect the Managed Availability Logs. Location: `V15\Logging\Monitoring` and Windows Event logs like `Microsoft-Exchange-ManagedAvailability`
MapiLogs | Enable to collect MAPI Logs. Location: `V15\Logging\MAPI Client Access`, `V15\Logging\MapiHttp\Mailbox`, and `V15\Logging\HttpProxy\Mapi`
MessageTrackingLogs | Enable to collect the Message Tracking Logs. Location: `(Get-TransportService $server).MessageTrackingLogPath`
MitigationService | Enable to collect the Mitigation Service logs. Location: `V15\Logging\MitigationService`
OABLogs | Enable to collect OAB Logs. Location: `V15\Logging\HttpProxy\OAB`, `V15\Logging\OABGeneratorLog`, `V15\Logging\OABGeneratorSimpleLog`, and `V15\Logging\MAPI AddressBook Service`
OrganizationConfig | Enable to collect the Organization Configuration from the environment.
OWALogs | Enable to collect OWA Logs. Location: `V15\Logging\OWA`, `Logging\HttpProxy\OwaCalendar`, and `V15\Logging\HttpProxy\Owa`
PipelineTracingLogs | Enable to collect the Pipeline Tracing Logs. Location `(Get-TransportService $server).PipelineTracingPath`, and `(Get-MailboxTransportService $server).PipelineTracingPath`
PopLogs | Enable to collect POP logging. Location: `(Get-PopSettings -Server $server).LogFileLocation`
PowerShellLogs | Enable to collect the PowerShell Logs. Location: `V15\Logging\HttpProxy\PowerShell`
QueueInformation | Enable to collect the historical queue information. Location: `(Get-TransportService $server).QueueLogPath`
ReceiveConnectors | Enable to collect the Receive Connector information from the server.
RPCLogs | Enable to collect RPC Logs. Location: `V15\Logging\RPC Client Access`, `V15\Logging\HttpProxy\RpcHttp`, and `V15\Logging\RpcHttp`
SearchLogs | Enable to collect Search Logs. Location: `V15\Bin\Search\Ceres\Diagnostics\Logs`, `V15\Bin\Search\Ceres\Diagnostics\ETLTraces`, `V15\Logging\Search`. On 2019 only we also include `V15\Logging\BigFunnelMetricsCollectionAssistant`, `V15\Logging\BigFunnelQueryParityAssistant`, and `V15\Logging\BigFunnelRetryFeederTimeBasedAssistant`
SendConnectors | Enable to collect the send connector information from the environment.
ServerInformation | Enable to collect general server information.
TransportAgentLogs | Enable to collect the Agent Logs. Location: `(Get-TransportService $server).AgentLogPath`, `(Get-FrontendTransportService $server).AgentLogPath`, `(Get-MailboxTransportService $server).MailboxSubmissionAgentLogPath`, and `(Get-MailboxTransportService $server).MailboxDeliveryAgentLogPath`
TransportConfig | Enable to collect the Transport Configuration files from the Server and `Get-TransportConfig` from the org. Files: `EdgeTransport.exe.config`, `MSExchangeFrontEndTransport.exe.config`, `MSExchangeDelivery.exe.config`, and `MSExchangeSubmission.exe.config`
TransportRoutingTableLogs | Enable to collect the Routing Table Logs. Location: `(Get-TransportService $server).RoutingTableLogPath`, `(Get-FrontendTransportService $server).RoutingTableLogPath`, and `(Get-MailboxTransportService $server).RoutingTableLogPath`
TransportRules | Enable to collect `Get-TransportRule`.
WindowsSecurityLogs | Enable to collect the Windows Security Logs. Default Location: `'C:\Windows\System32\WinEvt\Logs\Security.evtx'`
AllPossibleLogs | Enables the collection of all default logging collection on the Server.
CollectAllLogsBasedOnLogAge | Boolean to determine if you collect all the logs based off the log's age or all the logs in that directory. Default value `$true`
ConnectivityLogs | Enables the following switches and their logs to be collected: `FrontEndConnectivityLogs`, `HubConnectivityLogs`, and `MailboxConnectivityLogs`
DatabaseFailoverIssue | Enables the following switches and their logs to be collected. `DAGInformation`, `DailyPerformanceLogs`, `ExchangeServerInformation`, `ExPerfWiz`, `HighAvailabilityLogs`, `ManagedAvailabilityLogs`, and `ServerInformation`.
DaysWorth | The number of days to go back to be included int the time span for log collection. Default value: 3
HoursWorth | The number of hours to go back to be included in the time span for the log collection. Default Value 0.
LogStartDate | Set the starting time for the log collection (DateTime).
LogEndDate | Set the ending time for the log collection (DateTime).
DisableConfigImport | Enable to not import the `ExchangeLogCollector.ps1.json` file if it exists.
ExMonLogmanName | A list of names that we want to collect for ExMon data. The default name is `ExMon_Trace`.
ExPerfWizLogmanName | A list of names that we want to collect performance data logs from. The default names are `Exchange_PerfWiz`, `ExPerfWiz`, and `SimplePerf`. (For both styles of ExPerfWiz)
LogAge | A Time Span value to use instead of the DaysWorth and HoursWorth parameters. Default Value: 3.00:00:00
OutlookConnectivityIssues | Enables the following switches and their logs to be collected: `AutoDLogs`, `DailyPerformanceLogs`, `EWSLogs`, `ExPerfWiz`, `IISLogs`, `MAPILogs`, `RPCLogs`, and `ServerInformation`
PerformanceIssues | Enables the following switches and their logs to be collected: `DailyPerformanceLogs`, `ExPerfWiz`, and `ManagedAvailabilityLogs`
PerformanceMailFlowIssues | Enables the following switches and their logs to be collected: `DailyPerformanceLogs`, `ExPerfWiz`, `MessageTrackingLogs`, `QueueInformation`, and `TransportConfig`
ProtocolLogs | Enables the following switches and their logs to be collected: `FrontEndProtocolLogs`, `HubProtocolLogs`, and `MailboxProtocolLogs`
ScriptDebug | Enable to display all the verbose lines in the script.
SkipEndCopyOver | If the Servers parameter is used, by default we will attempt to collect all the data back over to the local server after all the data was collected on each server.
