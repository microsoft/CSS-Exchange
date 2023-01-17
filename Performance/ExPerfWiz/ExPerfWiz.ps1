# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
Testing Notes

.SYNOPSIS
Testing synopsis

.DESCRIPTION
Testing Description

.OUTPUTS
Testing Outputs

.EXAMPLE
Testing Example

#>

. $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\Get-ExPerfWiz.ps1
. $PSScriptRoot\New-ExPerfWiz.ps1
. $PSScriptRoot\Remove-ExPerfWiz.ps1
. $PSScriptRoot\Set-ExPerfWiz.ps1
. $PSScriptRoot\Start-ExPerfWiz.ps1
. $PSScriptRoot\Step-ExPerfWizSize.ps1
. $PSScriptRoot\Stop-ExPerfWiz.ps1
. $PSScriptRoot\Write-SimpleLogFile.ps1

## Main ##

$xml131619 = @"
<?xml version="1.0" encoding="UTF-8"?>
<DataCollectorSet>
<Status>0</Status>
<Duration>0</Duration>
<Description>ExPerfWiz Exchange 2013/16/19 Full</Description>
<DescriptionUnresolved>
</DescriptionUnresolved>
<DisplayName>ExPerfWiz</DisplayName>
<DisplayNameUnresolved>ExPerfWiz</DisplayNameUnresolved>
<SchedulesEnabled>-1</SchedulesEnabled>
<LatestOutputLocation>
</LatestOutputLocation>
<Name>ExPerfWiz Test</Name>
<OutputLocation>C:\Temp\ExPerfWiz</OutputLocation>
<RootPath>C:\Temp\ExPerfWiz</RootPath>
<Segment>0</Segment>
<SegmentMaxDuration>28800</SegmentMaxDuration>
<SegmentMaxSize>100</SegmentMaxSize>
<SerialNumber>1</SerialNumber>
<Server>
</Server>
<Subdirectory>
</Subdirectory>
<SubdirectoryFormat>3</SubdirectoryFormat>
<SubdirectoryFormatPattern></SubdirectoryFormatPattern>
<Task>
</Task>
<TaskRunAsSelf>0</TaskRunAsSelf>
<TaskArguments>
</TaskArguments>
<TaskUserTextArguments>
</TaskUserTextArguments>
<UserAccount>SYSTEM</UserAccount>
<Security></Security>
<StopOnCompletion>0</StopOnCompletion>
<PerformanceCounterDataCollector>
<DataCollectorType>0</DataCollectorType>
<Name>ExPerfWiz</Name>
<FileName>ExPerfWiz</FileName>
<FileNameFormat>3</FileNameFormat>
<FileNameFormatPattern>\_ddMMyy\_HHmm\_z\Z\_NNN</FileNameFormatPattern>
<LogAppend>-1</LogAppend>
<LogCircular>0</LogCircular>
<LogOverwrite>0</LogOverwrite>
<LatestOutputLocation>
</LatestOutputLocation>
<DataSourceName>
</DataSourceName>
<SampleInterval>15</SampleInterval>
<SegmentMaxRecords>0</SegmentMaxRecords>
<LogFileFormat>3</LogFileFormat>
<Counter>\.NET CLR Exceptions( * )\*</Counter>
<Counter>\.NET CLR Memory( * )\*</Counter>
<Counter>\.NET CLR Loading( * )\*</Counter>
<Counter>\.NET CLR LocksAndThreads( * )\Contention Rate / sec</Counter>
<Counter>\APP_POOL_WAS( * )\*</Counter>
<Counter>\ASP.NET\*</Counter>
<Counter>\ASP.NET Applications( * )\*</Counter>
<Counter>\ASP.NET Apps v4.0.30319( * )\*</Counter>
<Counter>\ASP.NET v4.0.30319\*</Counter>
<Counter>\HTTP Service Request Queues( * )\*</Counter>
<Counter>\LogicalDisk( * )\*</Counter>
<Counter>\Memory\*</Counter>
<Counter>\MSExchangeTransport SmtpSend( * )\*</Counter>
<Counter>\MSExchangeUMAutoAttendant( * )\*</Counter>
<Counter>\MSExchangeUMAvailability\*</Counter>
<Counter>\MSExchangeUMCallAnswer\*</Counter>
<Counter>\MSExchangeUMCallRouterAvailability\*</Counter>
<Counter>\MSExchangeUMClientAccess( * )\*</Counter>
<Counter>\MSExchangeUMFax\*</Counter>
<Counter>\MSExchangeUMGeneral\*</Counter>
<Counter>\MSExchangeUMMessageWaitingIndicator( * )\*</Counter>
<Counter>\MSExchangeUMPerformance\*</Counter>
<Counter>\MSExchangeUMSubscriberAccess\*</Counter>
<Counter>\MSExchange Active Manager Client( * )\*</Counter>
<Counter>\MSExchange Active Manager Dag Name Instance( * )\*</Counter>
<Counter>\MSExchange Active Manager Server\*</Counter>
<Counter>\MSExchange Active Manager( * )\*</Counter>
<Counter>\MSExchange ActiveSync\*</Counter>
<Counter>\MSExchange Activity Context Resources( * )\*</Counter>
<Counter>\MSExchange ADAccess Caches( * )\*</Counter>
<Counter>\MSExchange ADAccess Domain Controllers( * )\*</Counter>
<Counter>\MSExchange ADAccess Forest Discovery( * )\*</Counter>
<Counter>\MSExchange ADAccess Global Counters\*</Counter>
<Counter>\MSExchange ADAccess Local Site Domain Controllers( * )\*</Counter>
<Counter>\MSExchange ADAccess Processes( * )\*</Counter>
<Counter>\MSExchange ADAccess Topology Service\*</Counter>
<Counter>\MSExchange Admin Audit Log( * )\*</Counter>
<Counter>\MSExchange Anti-Malware Agent\*</Counter>
<Counter>\MSExchange Approval Assistant\*</Counter>
<Counter>\MSExchange Approval Framework( * )\*</Counter>
<Counter>\MSExchange Assistants - Per Assistant( * )\*</Counter>
<Counter>\MSExchange Assistants - Per Database( * )\*</Counter>
<Counter>\MSExchange Authentication( * )\*</Counter>
<Counter>\MSExchange Availability Service\*</Counter>
<Counter>\MSExchange Bulk User Provisioning\*</Counter>
<Counter>\MSExchange Calendar Attendant\*</Counter>
<Counter>\MSExchange Calendar Repair Assistant\*</Counter>
<Counter>\MSExchange Calendar Sync Assistant( * )\*</Counter>
<Counter>\MSExchange Connection Filtering Agent\*</Counter>
<Counter>\MSExchange Content Filter Agent\*</Counter>
<Counter>\MSExchange Control Panel\*</Counter>
<Counter>\MSExchange Conversations Transport Agent\*</Counter>
<Counter>\MSExchange Database Pinger( * )\*</Counter>
<Counter>\MSExchange Database( * )\*</Counter>
<Counter>\MSExchange Delivery Certificate Validation Cache( * )\*</Counter>
<Counter>\MSExchange Delivery Component Latency( * )\*</Counter>
<Counter>\MSExchange Delivery Configuration Cache( * )\*</Counter>
<Counter>\MSExchange Delivery DSN( * )\*</Counter>
<Counter>\MSExchange Delivery End To End Latency( * )\*</Counter>
<Counter>\MSExchange Delivery Extensibility Agents( * )\*</Counter>
<Counter>\MSExchange Delivery ProxyHubSelector( * )\*</Counter>
<Counter>\MSExchange Delivery Routing( * )\*</Counter>
<Counter>\MSExchange Delivery SmtpAvailability( * )\*</Counter>
<Counter>\MSExchange Delivery SmtpReceive( * )\*</Counter>
<Counter>\MSExchange Delivery SmtpSend( * )\*</Counter>
<Counter>\MSExchange Delivery Store Driver Agents( * )\*</Counter>
<Counter>\MSExchange Delivery Store Driver Database( * )\*</Counter>
<Counter>\MSExchange Delivery Store Driver\*</Counter>
<Counter>\MSExchange Delivery Store Driver\Inbound\*</Counter>
<Counter>\MSExchange Diagnostics Service\*</Counter>
<Counter>\MSExchange Encryption Agent\*</Counter>
<Counter>\MSExchange HttpProxy Cache( * )\*</Counter>
<Counter>\MSExchange HttpProxy Per Array( * )\*</Counter>
<Counter>\MSExchange HttpProxy Per Site( * )\*</Counter>
<Counter>\MSExchange HttpProxy( * )\*</Counter>
<Counter>\MSExchange Hygiene AntiMalware( * )\*</Counter>
<Counter>\MSExchange Hygiene Cache( * )\*</Counter>
<Counter>\MSExchange Hygiene Classification\*</Counter>
<Counter>\MSExchange Hygiene Text Extraction\*</Counter>
<Counter>\MSExchange Hygiene Updates Connectivity( * )\*</Counter>
<Counter>\MSExchange Hygiene Updates Engine( * )\*</Counter>
<Counter>\MSExchange Hygiene Updates Pipeline( * )\*</Counter>
<Counter>\MSExchange Hygiene\*</Counter>
<Counter>\MSExchange Inbound SMS Delivery Agent\*</Counter>
<Counter>\MSExchange Journal Report Decryption Agent\*</Counter>
<Counter>\MSExchange Journaling Agent\*</Counter>
<Counter>\MSExchange Junk E-mail Options Assistant\*</Counter>
<Counter>\MSExchange Log Search Service\*</Counter>
<Counter>\MSExchange Mailbox Replication Service Per Mdb( * )\*</Counter>
<Counter>\MSExchange Mailbox Replication Service\*</Counter>
<Counter>\MSExchange MailTips\*</Counter>
<Counter>\MSExchange Managed Folder Assistant\*</Counter>
<Counter>\MSExchange MapiHttp Emsmdb\*</Counter>
<Counter>\MSExchange MapiHttp Nspi\*</Counter>
<Counter>\MSExchange Message Tracking\*</Counter>
<Counter>\MSExchange Middle-Tier Storage( * )\*</Counter>
<Counter>\MSExchange Network Manager( * )\*</Counter>
<Counter>\MSExchange NSPI RPC Client Connections( * )\*</Counter>
<Counter>\MSExchange OAB Generator Assistant\*</Counter>
<Counter>\MSExchange OAuth( * )\*</Counter>
<Counter>\MSExchange OWA\*</Counter>
<Counter>\MSExchange Prelicensing Agent\*</Counter>
<Counter>\MSExchange Protocol Analysis Agent\*</Counter>
<Counter>\MSExchange Protocol Analysis Background Agent\*</Counter>
<Counter>\MSExchange Provisioning Cache( * )\*</Counter>
<Counter>\MSExchange Provisioning\*</Counter>
<Counter>\MSExchange Push Notifications Apns Channel( * )\*</Counter>
<Counter>\MSExchange Push Notifications Assistant\*</Counter>
<Counter>\MSExchange Push Notifications Pending Get\*</Counter>
<Counter>\MSExchange Push Notifications Publisher Manager\*</Counter>
<Counter>\MSExchange Push Notifications Publishers( * )\*</Counter>
<Counter>\MSExchange Recipient Cache( * )\*</Counter>
<Counter>\MSExchange Recipient DL Expansion Assistant\*</Counter>
<Counter>\MSExchange Recipient Filter Agent\*</Counter>
<Counter>\MSExchange Replica Seeder( * )\*</Counter>
<Counter>\MSExchange Replication Server\*</Counter>
<Counter>\MSExchange Replication( * )\*</Counter>
<Counter>\MSExchange ReportingWebService\*</Counter>
<Counter>\MSExchange Resource Booking\*</Counter>
<Counter>\MSExchange Resource Load( * )\*</Counter>
<Counter>\MSExchange Rights Management\*</Counter>
<Counter>\MSExchange RMS Agents\*</Counter>
<Counter>\MSExchange RMS Decryption Agent\*</Counter>
<Counter>\MSExchange RpcClientAccess\*</Counter>
<Counter>\MSExchange Search Indexes( * )\*</Counter>
<Counter>\MSExchange Secure Mail Transport( * )\*</Counter>
<Counter>\MSExchange Sender Filter Agent\*</Counter>
<Counter>\MSExchange Sender Id Agent\*</Counter>
<Counter>\MSExchange ServiceProxyPool( * )\*</Counter>
<Counter>\MSExchange Sharing Engine\*</Counter>
<Counter>\MSExchange Store Interface( * )\*</Counter>
<Counter>\MSExchange Submission Certificate Validation Cache( * )\*</Counter>
<Counter>\MSExchange Submission Component Latency( * )\*</Counter>
<Counter>\MSExchange Submission Configuration Cache( * )\*</Counter>
<Counter>\MSExchange Submission DSN( * )\*</Counter>
<Counter>\MSExchange Submission Extensibility Agents( * )\*</Counter>
<Counter>\MSExchange Submission ProxyHubSelector( * )\*</Counter>
<Counter>\MSExchange Submission Routing( * )\*</Counter>
<Counter>\MSExchange Submission SmtpSend( * )\*</Counter>
<Counter>\MSExchange Submission Store Driver Agents( * )\*</Counter>
<Counter>\MSExchange Submission Store Driver Database( * )\*</Counter>
<Counter>\MSExchange Submission Store Driver\*</Counter>
<Counter>\MSExchange Submission\*</Counter>
<Counter>\MSExchange Text Messaging\*</Counter>
<Counter>\MSExchange Throttling Service Client( * )\*</Counter>
<Counter>\MSExchange Throttling( * )\*</Counter>
<Counter>\MSExchange TopN Words Assistant\*</Counter>
<Counter>\MSExchange Topology( * )\*</Counter>
<Counter>\MSExchange Transport Rules( * )\*</Counter>
<Counter>\MSExchange UnJournaling Agent\*</Counter>
<Counter>\MSExchange Update Agent\*</Counter>
<Counter>\MSExchange User Throttling( * )\*</Counter>
<Counter>\MSExchange User WorkloadManager( * )\*</Counter>
<Counter>\MSExchange UserPhotos\*</Counter>
<Counter>\MSExchange WorkloadManagement Classification( * )\*</Counter>
<Counter>\MSExchange WorkloadManagement Workloads( * )\*</Counter>
<Counter>\MSExchange WorkloadManagement( * )\*</Counter>
<Counter>\MSExchangeAB\*</Counter>
<Counter>\MSExchangeAutodiscover\*</Counter>
<Counter>\MSExchangeEdgeSync Synchronizer( * )\*</Counter>
<Counter>\MSExchangeEdgeSync Topology\*</Counter>
<Counter>\MSExchangeFrontEndTransport Certificate Validation Cache( * )\*</Counter>
<Counter>\MSExchangeFrontEndTransport Component Latency( * )\*</Counter>
<Counter>\MSExchangeFrontEndTransport Configuration Cache( * )\*</Counter>
<Counter>\MSExchangeFrontEndTransport Extensibility Agents( * )\*</Counter>
<Counter>\MSExchangeFrontendTransport Proxy Routing Agent\*</Counter>
<Counter>\MSExchangeFrontEndTransport ProxyHubSelector( * )\*</Counter>
<Counter>\MSExchangeFrontEndTransport Routing( * )\*</Counter>
<Counter>\MSExchangeFrontEndTransport Smtp Blind Proxy( * )\*</Counter>
<Counter>\MSExchangeFrontEndTransport SmtpAvailability( * )\*</Counter>
<Counter>\MSExchangeFrontEndTransport SmtpReceive( * )\*</Counter>
<Counter>\MSExchangeFrontEndTransport SmtpSend( * )\*</Counter>
<Counter>\MSExchangeImap4( * )\*</Counter>
<Counter>\MSExchangeInference Classification Latency( * )\*</Counter>
<Counter>\MSExchangeInference Model( * )\*</Counter>
<Counter>\MSExchangeInference Pipeline( * )\*</Counter>
<Counter>\MSExchangeInference StatefulComponent( * )\*</Counter>
<Counter>\MSExchangeIS Client Type( * )\*</Counter>
<Counter>\MSExchangeIS HA Active Database Sender( * )\*</Counter>
<Counter>\MSExchangeIS HA Active Database( * )\*</Counter>
<Counter>\MSExchangeIS Physical Access( * )\*</Counter>
<Counter>\MSExchangeIS Store( * )\*</Counter>
<Counter>\MSExchangeOABRequestHandler\*</Counter>
<Counter>\MSExchangePop3( * )\*</Counter>
<Counter>\MSExchangeRepl Source Database( * )\*</Counter>
<Counter>\MSExchangeSearch Mailbox Operators( * )\*</Counter>
<Counter>\MSExchangeSearch MailboxSession Cache( * )\*</Counter>
<Counter>\MSExchangeSearch Transport CTS Flow( * )\*</Counter>
<Counter>\MSExchangeTransport Certificate Validation Cache( * )\*</Counter>
<Counter>\MSExchangeTransport Component Latency( * )\*</Counter>
<Counter>\MSExchangeTransport Configuration Cache( * )\*</Counter>
<Counter>\MSExchangeTransport Database( * )\*</Counter>
<Counter>\MSExchangeTransport Delivery Failures\*</Counter>
<Counter>\MSExchangeTransport DeliveryAgent( * )\*</Counter>
<Counter>\MSExchangeTransport DSN( * )\*</Counter>
<Counter>\MSExchangeTransport E2E Latency Buckets( * )\*</Counter>
<Counter>\MSExchangeTransport End To End Latency( * )\*</Counter>
<Counter>\MSExchangeTransport Extensibility Agents( * )\*</Counter>
<Counter>\MSExchangeTransport Pickup( * )\*</Counter>
<Counter>\MSExchangeTransport Queued Recipients By Age( * )\*</Counter>
<Counter>\MSExchangeTransport Queues( * )\*</Counter>
<Counter>\MSExchangeTransport Resolver( * )\*</Counter>
<Counter>\MSExchangeTransport Routing( * )\*</Counter>
<Counter>\MSExchangeTransport Safety Net( * )\*</Counter>
<Counter>\MSExchangeTransport ServerAlive( * )\*</Counter>
<Counter>\MSExchangeTransport Shadow Redundancy Host Info( * )\*</Counter>
<Counter>\MSExchangeTransport Shadow Redundancy( * )\*</Counter>
<Counter>\MSExchangeTransport SMTPAvailability( * )\*</Counter>
<Counter>\MSExchangeTransport SMTPReceive( * )\*</Counter>
<Counter>\MSExchangeUMVoiceMailSpeechRecognition( * )\*</Counter>
<Counter>\MSExchangeWorkerTaskFramework( * )\*</Counter>
<Counter>\MSExchangeWorkerTaskFrameworkLocalDataAccess\*</Counter>
<Counter>\MSExchangeWS\*</Counter>
<Counter>\Netlogon( * )\*</Counter>
<Counter>\Network Interface( * )\*</Counter>
<Counter>\Paging File( * )\*</Counter>
<Counter>\PhysicalDisk( * )\*</Counter>
<Counter>\Process( * )\*</Counter>
<Counter>\Processor Information( * )\*</Counter>
<Counter>\Processor( * )\*</Counter>
<Counter>\RPC/HTTP Proxy Per Server( * )\*</Counter>
<Counter>\RPC/HTTP Proxy\*</Counter>
<Counter>\Server\*</Counter>
<Counter>\System\Context Switches/sec</Counter>
<Counter>\System\Processor Queue Length</Counter>
<Counter>\TCPv4\*</Counter>
<Counter>\TCPv6\*</Counter>
<Counter>\W3SVC_W3WP( * )\*</Counter>
<Counter>\WAS_W3WP( * )\*</Counter>
<Counter>\Web Service( * )\*</Counter>
<Counter>\VM Memory\*</Counter>
<Counter>\VM Processor( * )\*</Counter>
<Counter>\Expanded Groups Cache( * )\*</Counter>
<Counter>\MSExchange Database ==> Instances( * )\*</Counter>
<Counter>\MSExchange Database ==> TableClasses( * )\*</Counter>
</PerformanceCounterDataCollector>
<Schedule>
<StartDate>9/14/2020</StartDate>
<EndDate>9/15/2020</EndDate>
<StartTime>4:00:00 AM</StartTime>
<Days>127</Days>
</Schedule>
<DataManager>
<Enabled>0</Enabled>
<CheckBeforeRunning>0</CheckBeforeRunning>
<MinFreeDisk>0</MinFreeDisk>
<MaxSize>0</MaxSize>
<MaxFolderCount>0</MaxFolderCount>
<ResourcePolicy>0</ResourcePolicy>
<ReportFileName>report.html</ReportFileName>
<RuleTargetFileName>report.xml</RuleTargetFileName>
<EventsFileName>
</EventsFileName>
</DataManager>
</DataCollectorSet>
"@

# Confirm that we are an administrator
if (Confirm-Administrator) {}
else { Write-Error "Please run as Administrator" -ErrorAction Stop }

function global:Convert-OnOffBool {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$toCompare
    )

    switch ($toCompare) {
        On { return $true }
        default { return $false }
    }
}

# Create the template file
$xml131619 | Out-File -FilePath (Join-Path $env:LOCALAPPDATA "Exch_13_16_19_Full.xml") -Encoding utf8

# Create prompt body
$title = "Default ExPerfWiz"
$message = "Create the default ExPerfWiz on this server?"

# Create answers
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Creates the default PerfWiz: 5s Interval; 8 Hour Run time; C:\ExPerfWiz Path"
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Returns to a prompt."

# Create ChoiceDescription with answers
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

# Show prompt and save user's answer to variable
$response = $host.UI.PromptForChoice($title, $message, $options, 0)

# Perform action based on answer
switch ($response) {
    0 { New-ExPerfWiz -FolderPath C:\ExPerfWiz } # Yes
    1 { break } # No
}
