<#
.NOTES
    Name: ExchangeLogCollector.ps1
    Author: David Paulson
    Requires: Powershell on an Exchange 2010+ Server with Administrator rights

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
	BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
	DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
.SYNOPSIS
    Collects the requested logs off the Exchange server based off the switches that are used.
.DESCRIPTION
    Collects the requested logs off the Exchange server based off the switches that are used.
.PARAMETER FilePath
    The Location of where you would like the data to be copied over to
.PARAMETER Servers
    An array of servers that you would like to collect data from.
.PARAMETER EWSLogs
    Will collect the EWS logs from the Exchange Server
.PARAMETER IISLogs
    Will Collect the IIS Logs from the Exchange Server
.PARAMETER DailyPerformanceLogs
    Used to collect Exchange 2013+ Daily Performance Logs
.PARAMETER ManagedAvailability
    Used to collect managed Availability Logs from the Exchange 2013+ Server
.PARAMETER Experfwiz
    Used to collect Experfwiz data from the server
.PARAMETER RPCLogs
    Used to collect the PRC Logs from the server
.PARAMETER EASLogs
    Used to collect the Exchange Active Sync Proxy Logs
.PARAMETER ECPLogs
    Used to collect the ECP Logs from the Exchange server
.PARAMETER AutoDLogs
    Used to Collect the AutoD Logs from the server
.PARAMETER OWALogs
    Used to collect the OWA Logs from the server
.PARAMETER ADDriverLogs
    Used to collect the AD Driver Logs from the server
.PARAMETER SearchLogs
    Used to collect the Search Logs from the server
.PARAMETER HighAvailabilityLogs
    Used to collect the High Availability Information from the server
.PARAMETER MapiLogs
    Used to collect the Mapi Logs from the server
.PARAMETER MessageTrackingLogs
    Used to collect the Message Tracking Logs from the server
.PARAMETER HubProtocolLogs
    Used to collect the Hub Protocol Logs from the server
.PARAMETER HubConnectivityLogs
    Used to collect the Hub Connectivity Logs from the server
.PARAMETER FrontEndConnectivityLogs
    Used to collect the Front End Connectivity Logs from the server
.PARAMETER FrontEndProtocolLogs
    Used to collect the Front End Protocol Logs from the server
.PARAMETER MailboxConnectivityLogs
    Used to collect the Mailbox Connectivity Logs from the server
.PARAMETER MailboxProtocolLogs
    Used to collect the Mailbox Protocol Logs from the server
.PARAMETER QueueInformationThisServer
    Used to collect the Queue Information from this server
.PARAMETER ReceiveConnectors
    Used to collect the Receive Connector information from this server
.PARAMETER SendConnectors
    Used to collect the Send connector information from the Org
.PARAMETER DAGInformation
    Used to collect the DAG Information for this DAG
.PARAMETER GetVdirs
    Used to collect the Virtual Directories of the environment
.PARAMETER OrganizationConfig
    Used to collect the Organization Configuration from the environment.
.PARAMETER TransportConfig
    Used to collect the Transport Configuration from this Exchange Server
.PARAMETER DefaultTransportLogging
    Used to Get all the default logging that is enabled on the Exchange Server for Transport Information
.PARAMETER Exmon
    Used to Collect the Exmon Information
.PARAMETER ServerInfo
    Used to collect the general Server information from the server
.PARAMETER ExchangeServerInfo
    Used to collect Exchange Server data (Get-ExchangeServer, Get-MailboxServer...). Enabled whenever ServerInfo is used as well.
.PARAMETER PopLogs
    Used to collect the POP protocol logs
.PARAMETER ImapLogs
    Used to collect the IMAP protocol logs
.PARAMETER OABLogs
    Used to collect the OAB logs
.PARAMETER PowerShellLogs
    Used to collect the Exchange PowerShell Logs
.PARAMETER MSInfo
    Old switch that was used for collecting the general Server information
.PARAMETER CollectAllLogsBasedOnDaysWorth
    Used to collect some of the default logging based off Days Worth vs the whole directory
.PARAMETER AppSysLogs
    Used to collect the Application and System Logs. Default is set to true
.PARAMETER AllPossibleLogs
    Switch to enable all default logging enabled on the Exchange server.
.PARAMETER SkipEndCopyOver
    Boolean to prevent the copy over after a remote collection.
.PARAMETER DaysWorth
    To determine how far back we would like to collect data from
.PARAMETER ScriptDebug
    To enable Debug Logging for the script to determine what might be wrong with the script
.PARAMETER DatabaseFailoverIssue
    To enable the common switches to assist with determine the cause of database failover issues
.PARAMETER PerformanceIssues
    To enable the common switches for data collection to assist with determining the cause of a Performance issue.
.PARAMETER PerformanceMailFlowIssues
    To enable the common switches for data collection to assist with determine the cause of a MailFlow Performance Type issue.
.PARAMETER OutlookConnectivityIssues
    To enable the command switches for the data collection to assist with determining outlook connectivity issues that are on the Exchange server.
.PARAMETER ExperfwizLogmanName
    To be able to set the Experfwiz Logman Name that we would be looking for. By Default "Exchange_Perfwiz"
.PARAMETER ExmonLogmanName
    To be able to set the Exmon Logman Name that we would be looking for. By Default "Exmon_Trace"
.PARAMETER AcceptEULA
    Switch used to bypass the disclaimer confirmation
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'All Parameters are used in other functions of the script')]
[CmdletBinding()]
Param (
    [string]$FilePath = "C:\MS_Logs_Collection",
    [Array]$Servers,
    [switch]$EWSLogs,
    [switch]$IISLogs,
    [switch]$DailyPerformanceLogs,
    [switch]$ManagedAvailability,
    [switch]$Experfwiz,
    [switch]$RPCLogs,
    [switch]$EASLogs,
    [switch]$ECPLogs,
    [switch]$AutoDLogs,
    [switch]$OWALogs,
    [switch]$ADDriverLogs,
    [switch]$SearchLogs,
    [switch]$HighAvailabilityLogs,
    [switch]$MapiLogs,
    [switch]$MessageTrackingLogs,
    [switch]$HubProtocolLogs,
    [switch]$HubConnectivityLogs,
    [switch]$FrontEndConnectivityLogs,
    [switch]$FrontEndProtocolLogs,
    [switch]$MailboxConnectivityLogs,
    [switch]$MailboxProtocolLogs,
    [switch]$QueueInformationThisServer,
    [switch]$ReceiveConnectors,
    [switch]$SendConnectors,
    [switch]$DAGInformation,
    [switch]$GetVdirs,
    [switch]$OrganizationConfig,
    [switch]$TransportConfig,
    [switch]$DefaultTransportLogging,
    [switch]$Exmon,
    [switch]$ServerInfo,
    [switch]$ExchangeServerInfo,
    [switch]$PopLogs,
    [switch]$ImapLogs,
    [switch]$OABLogs,
    [switch]$PowerShellLogs,
    [switch]$WindowsSecurityLogs,
    [bool]$CollectAllLogsBasedOnDaysWorth = $true,
    [Bool]$AppSysLogs = $true,
    [switch]$AllPossibleLogs,
    [bool]$SkipEndCopyOver,
    [int]$DaysWorth = 3,
    [switch]$DatabaseFailoverIssue,
    [switch]$PerformanceIssues,
    [switch]$PerformanceMailflowIssues,
    [switch]$OutlookConnectivityIssues,
    [string]$ExperfwizLogmanName = "Exchange_Perfwiz",
    [string]$ExmonLogmanName = "Exmon_Trace",
    [switch]$AcceptEULA,
    [switch]$ScriptDebug
)
