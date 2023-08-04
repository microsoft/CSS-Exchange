# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ExchAVExclusionsPaths {
    [CmdletBinding()]
    [OutputType([Collections.Generic.List[string]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
                if (Test-Path $_ -PathType Container ) { $true }
                else { throw "Path $_ is not valid" }
            })]
        [string]
        $ExchangePath,
        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1, 2)]
        [byte]
        $MsiProductMinor
    )
    # Create the Array List
    $BaseFolders = New-Object Collections.Generic.List[string]

    # List of base Folders
    if ((Get-ExchangeServer $env:COMPUTERNAME).IsMailboxServer) {
        if (Get-DatabaseAvailabilityGroup ) {
            if (Get-DatabaseAvailabilityGroup | Where-Object { $_.Servers.Name -contains ($env:COMPUTERNAME) } ) {
                $BaseFolders.Add((Join-Path $($env:SystemRoot) '\Cluster').ToLower())
                $dag = $null
                $dag = Get-DatabaseAvailabilityGroup | Where-Object { $_.Servers.Name -contains ($env:COMPUTERNAME) }
                if ( $null -ne $dag ) {
                    Write-Warning "Remember to add the witness directory $($dag.WitnessDirectory.PathName) on the server $($dag.WitnessServer.Fqdn)"
                }
            }
        }
        $BaseFolders.Add((Join-Path $ExchangePath '\ClientAccess\OAB').ToLower())
        $BaseFolders.Add((Join-Path $ExchangePath '\FIP-FS').ToLower())
        $BaseFolders.Add((Join-Path $ExchangePath '\GroupMetrics').ToLower())
        $BaseFolders.Add((Join-Path $ExchangePath '\Logging').ToLower())
        if ($MsiProductMinor -eq 0 ) {
            $BaseFolders.Add((Join-Path $ExchangePath '\Mailbox\MdbTemp').ToLower())
        }

        $mbxS = Get-MailboxServer -Identity $($env:COMPUTERNAME) | Select-Object CalendarRepairLogPath, LogPathForManagedFolders, `
            DataPath, MigrationLogFilePath, TransportSyncLogFilePath, TransportSyncMailboxHealthLogFilePath
        $mbxS.PSObject.Properties.Value.PathName | ForEach-Object {
            if ( $_ ) {
                $BaseFolders.Add($_.ToLower())
            }
        }

        # Add all database folder paths
        foreach ($Entry in (Get-MailboxDatabase -Server $Env:COMPUTERNAME)) {
            $BaseFolders.Add((Split-Path $Entry.EdbFilePath -Parent).ToLower())
            $mbDbLogs = $Entry | Select-Object TemporaryDataFolderPath, LogFolderPath

            $mbDbLogs.PSObject.Properties.Value.PathName | ForEach-Object {
                if ( $_ ) {
                    $BaseFolders.Add($_.ToLower())
                }
            }
        }

        $mtsLogs = Get-MailboxTransportService $($env:COMPUTERNAME) | Select-Object ConnectivityLogPath, `
            ReceiveProtocolLogPath, SendProtocolLogPath, MailboxSubmissionAgentLogPath, MailboxDeliveryAgentLogPath, `
            DnsLogPath, RoutingTableLogPath, SyncDeliveryLogPath, MailboxDeliveryHttpDeliveryLogPath, `
            MailboxDeliveryThrottlingLogPath, AgentGrayExceptionLogPath, PipelineTracingPath
        $mtsLogs.PSObject.Properties.Value.PathName | ForEach-Object {
            if ( $_ ) {
                $BaseFolders.Add($_.ToLower())
            }
        }

        $BaseFolders.Add("$($env:SystemRoot)\Temp\OICE_????????-????-????-????-????????????")
        $BaseFolders.Add("$($env:SystemRoot)\Temp\OICE_????????-????-????-????-????????????.?")
    }

    if ((Get-ExchangeServer $env:COMPUTERNAME).IsUnifiedMessagingServer) {
        $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Grammars'))
        $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Prompts'))
        $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Temp'))
        $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Voicemail'))
    }

    if ((Get-ExchangeServer $env:COMPUTERNAME).IsClientAccessServer) {

        $feTsLogs = Get-FrontEndTransportService $($env:COMPUTERNAME) | Select-Object ConnectivityLogPath, `
            ReceiveProtocolLogPath, SendProtocolLogPath, AgentLogPath, DnsLogPath, ResourceLogPath, `
            AttributionLogPath, `
            RoutingTableLogPath, ProxyDestinationsLogPath, TopInboundIpSourcesLogPath
        $feTsLogs.PSObject.Properties.Value.PathName | ForEach-Object {
            if ( $_) {
                $BaseFolders.Add($_.ToLower())
            }
        }

        $BaseFolders.Add((Join-Path $env:SystemDrive '\inetPub\temp\IIS Temporary Compressed Files').ToLower())
        $BaseFolders.Add(($((Get-PopSettings).LogFileLocation)).ToLower())
        $BaseFolders.Add(($((Get-ImapSettings).LogFileLocation)).ToLower())
    }

    if ((Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer) {
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\Adam').ToLower())
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\IpFilter').ToLower())
    }

    if ((Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer -or (Get-ExchangeServer $env:COMPUTERNAME).IsHubTransportServer) {
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\Queue').ToLower())
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\SenderReputation').ToLower())
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\Temp').ToLower())
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Logs').ToLower())

        $tsLogs = Get-TransportService $($env:COMPUTERNAME) | Select-Object ConnectivityLogPath, MessageTrackingLogPath, `
            IrmLogPath, ActiveUserStatisticsLogPath, ServerStatisticsLogPath, ReceiveProtocolLogPath, RoutingTableLogPath, `
            SendProtocolLogPath, QueueLogPath, LatencyLogPath, GeneralLogPath, WlmLogPath, AgentLogPath, FlowControlLogPath, `
            ProcessingSchedulerLogPath, ResourceLogPath, DnsLogPath, JournalLogPath, TransportMaintenanceLogPath, `
            RequestBrokerLogPath, StorageRESTLogPath, AgentGrayExceptionLogPath, TransportHttpLogPath, PipelineTracingPath, `
            PickupDirectoryPath, ReplayDirectoryPath, `
            RootDropDirectoryPath
        $tsLogs.PSObject.Properties.Value.PathName | ForEach-Object {
            if ( $_ ) {
                $BaseFolders.Add($_.ToLower())
            }
        }

        $BaseFolders.Add((Join-Path $ExchangePath '\Working\OleConverter').ToLower())

        # Get transport database path
        [xml]$TransportConfig = Get-Content (Join-Path $ExchangePath "Bin\EdgeTransport.exe.config")
        $BaseFolders.Add(($TransportConfig.configuration.AppSettings.Add | Where-Object { $_.key -eq "QueueDatabasePath" }).value.ToLower())
        $BaseFolders.Add(($TransportConfig.configuration.AppSettings.Add | Where-Object { $_.key -eq "QueueDatabaseLoggingPath" }).value.ToLower())

        if ($MsiProductMinor -eq 0 ) {
            #E13MBX  By default, content conversions are performed in the Exchange server's %TMP% folder.
            $BaseFolders.Add((Join-Path $env:SystemRoot '\Temp').ToLower())
        }
    }

    if ($MsiProductMinor -eq 0 ) {
        #E13 Exchange Server setup temporary files.
        $BaseFolders.Add((Join-Path $env:SystemRoot '\Temp\ExchangeSetup').ToLower())

        # it is only in client Access E13 doc--- inetPub\logs\LogFiles\w3svc
        Get-Website | Where-Object { $_.name -eq 'Default Web Site' -or $_.name -eq 'Exchange Back End' } | ForEach-Object {
            if ($_.LogFile.directory.StartsWith('%')) {
                $BaseFolders.Add(("$(Get-Content -Path Env:"$($_.logFile.directory.Split('%')[1])")$($_.logFile.directory.Split('%')[2])\W3SVC$($_.id)").ToLower())
            } else {
                $BaseFolders.Add(("$($_.LogFile.directory)\W3SVC$($_.id)").ToLower())
            }
        }
    }

    # Remove any Duplicates
    $BaseFolders = $BaseFolders | Select-Object -Unique

    $BaseFolders
}

function Get-ExchAVExclusionsExtensions {
    [CmdletBinding()]
    [OutputType([Collections.Generic.List[string]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1, 2)]
        [byte]
        $MsiProductMinor
    )
    # Create the Array List
    $ExtensionsList = New-Object Collections.Generic.List[string]

    if ($MsiProductMinor -eq 0 ) {
        #Application-related extensions:
        $ExtensionsList.Add("config")
        $ExtensionsList.Add("dia")
        $ExtensionsList.Add("wsb")
        #Database-related extensions:
        $ExtensionsList.Add("chk")
        $ExtensionsList.Add("edb")
        $ExtensionsList.Add("jrs")
        $ExtensionsList.Add("jsl")
        $ExtensionsList.Add("log")
        $ExtensionsList.Add("que")
        #Offline address book-related extensions:
        $ExtensionsList.Add("lzx")
        #Content Index-related extensions:
        $ExtensionsList.Add("ci")
        $ExtensionsList.Add("dir")
        $ExtensionsList.Add("wid")
        $ExtensionsList.Add("000")
        $ExtensionsList.Add("001")
        $ExtensionsList.Add("002")
        #Unified Messaging-related extensions:
        $ExtensionsList.Add("cfg")
        $ExtensionsList.Add("grXml")
        #Group Metrics-related extensions:
        $ExtensionsList.Add("dsc")
        $ExtensionsList.Add("txt")
    }

    if ($MsiProductMinor -eq 1 -or $MsiProductMinor -eq 2 ) {
        if ((Get-ExchangeServer $env:COMPUTERNAME).IsMailboxServer -or (Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer) {
            #Application-related extensions
            $ExtensionsList.Add("config")
            #Database-related extensions
            $ExtensionsList.Add("chk")
            $ExtensionsList.Add("edb")
            $ExtensionsList.Add("jfm")
            $ExtensionsList.Add("jrs")
            $ExtensionsList.Add("log")
            $ExtensionsList.Add("que")
        }
        if ((Get-ExchangeServer $env:COMPUTERNAME).IsMailboxServer) {
            #Group Metrics-related extensions
            $ExtensionsList.Add("dsc")
            $ExtensionsList.Add("txt")
            #Offline address book-related extensions
            $ExtensionsList.Add("lzx")
        }
        if ((Get-ExchangeServer $env:COMPUTERNAME).IsUnifiedMessagingServer) {
            #Unified Messaging-related extensions
            $ExtensionsList.Add("cfg")
            $ExtensionsList.Add("grXml")
        }
    }
    $ExtensionsList.ToLower()
}

function Get-ExchAVExclusionsProcess {
    [CmdletBinding()]
    [OutputType([Collections.Generic.List[string]])]
    param (
        [ValidateScript({
                if (Test-Path $_ -PathType Container ) { $true }
                else { throw "Path $_ is not valid" }
            })]
        [string]
        $ExchangePath,
        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1, 2)]
        [byte]
        $MsiProductMinor
    )
    # Create the Array List
    $ProcessList = New-Object Collections.Generic.List[string]

    if ( $MsiProductMinor -eq 0) {
        if ((Get-ExchangeServer $env:COMPUTERNAME).IsMailboxServer) {
            $ProcessList.Add((Join-Path $ExchangePath 'FIP-FS\Bin\fms.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.EdgeSyncSvc.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'ClientAccess\PopImap\Microsoft.Exchange.Imap4service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'ClientAccess\PopImap\Microsoft.Exchange.Pop3service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.RPCClientAccess.Service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Search.Service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Store.Service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Store.Worker.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeDagMgmt.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeDelivery.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeMailboxAssistants.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeMailboxReplication.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeMigrationWorkflow.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeRepl.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeSubmission.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeThrottling.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Search\Ceres\Runtime\1.0\Noderunner.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\OleConverter.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Search\Ceres\ParserServer\ParserServer.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'FIP-FS\Bin\ScanEngineTest.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'FIP-FS\Bin\ScanningProcess.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'ClientAccess\Owa\Bin\DocumentViewing\TranscodingService.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\UmService.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\UmWorkerProcess.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'FIP-FS\Bin\UpdateService.exe'))
        }

        if ((Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer) {
            $ProcessList.Add((Join-Path $env:SystemRoot '\System32\Dsamain.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.EdgeCredentialSvc.exe'))
        }

        if ((Get-ExchangeServer $env:COMPUTERNAME).IsClientAccessServer) {
            $ProcessList.Add((Join-Path $ExchangePath 'FrontEnd\PopImap\Microsoft.Exchange.Imap4.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'FrontEnd\PopImap\Microsoft.Exchange.Pop3.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'FrontEnd\CallRouter\Microsoft.Exchange.UM.CallRouter.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeFrontendTransport.exe'))
        }

        if ((Get-ExchangeServer $env:COMPUTERNAME).IsClientAccessServer -or (Get-ExchangeServer $env:COMPUTERNAME).IsMailboxServer) {
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Search\Ceres\HostController\hostcontrollerservice.exe'))
            $ProcessList.Add((Join-Path $env:SystemRoot '\System32\inetSrv\inetInfo.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Directory.TopologyService.exe'))
        }

        if ((Get-ExchangeServer $env:COMPUTERNAME).IsClientAccessServer -or (Get-ExchangeServer $env:COMPUTERNAME).IsMailboxServer -or (Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer) {
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Diagnostics.Service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.ProtectedServiceHost.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Servicehost.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeHMHost.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeHMWorker.exe'))
        }

        if ((Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer -or (Get-ExchangeServer $env:COMPUTERNAME).IsMailboxServer) {
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\EdgeTransport.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.AntispamUpdateSvc.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'TransportRoles\agents\Hygiene\Microsoft.Exchange.ContentFilter.Wrapper.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeTransport.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeTransportLogSearch.exe'))
        }
    } else {
        if ((Get-ExchangeServer $env:COMPUTERNAME).IsMailboxServer) {
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\ComplianceAuditService.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'FIP-FS\Bin\fms.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Search\Ceres\HostController\hostcontrollerservice.exe'))
            $ProcessList.Add((Join-Path $env:SystemRoot '\System32\inetSrv\inetInfo.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Directory.TopologyService.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.EdgeSyncSvc.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'FrontEnd\PopImap\Microsoft.Exchange.Imap4.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'ClientAccess\PopImap\Microsoft.Exchange.Imap4service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Notifications.Broker.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'FrontEnd\PopImap\Microsoft.Exchange.Pop3.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'ClientAccess\PopImap\Microsoft.Exchange.Pop3service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.RPCClientAccess.Service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Search.Service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Store.Service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Store.Worker.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeCompliance.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeDagMgmt.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeDelivery.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeFrontendTransport.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeMailboxAssistants.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeMailboxReplication.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeRepl.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeSubmission.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeThrottling.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Search\Ceres\Runtime\1.0\Noderunner.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\OleConverter.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Search\Ceres\ParserServer\ParserServer.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'FIP-FS\Bin\ScanEngineTest.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'FIP-FS\Bin\ScanningProcess.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'FIP-FS\Bin\UpdateService.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\wsbExchange.exe'))
        }

        if ((Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer) {
            $ProcessList.Add((Join-Path $env:SystemRoot '\System32\Dsamain.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.EdgeCredentialSvc.exe'))
        }

        if ((Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer -or (Get-ExchangeServer $env:COMPUTERNAME).IsMailboxServer) {

            $ProcessList.Add((Join-Path $ExchangePath 'Bin\EdgeTransport.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.AntispamUpdateSvc.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'TransportRoles\agents\Hygiene\Microsoft.Exchange.ContentFilter.Wrapper.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Diagnostics.Service.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.ProtectedServiceHost.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\Microsoft.Exchange.Servicehost.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeHMHost.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeHMWorker.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeTransport.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\MSExchangeTransportLogSearch.exe'))
        }

        if ((Get-ExchangeServer $env:COMPUTERNAME).IsUnifiedMessagingServer) {
            $ProcessList.Add((Join-Path $ExchangePath 'FrontEnd\CallRouter\Microsoft.Exchange.UM.CallRouter.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\UmService.exe'))
            $ProcessList.Add((Join-Path $ExchangePath 'Bin\UmWorkerProcess.exe'))
        }
    }
    $ProcessList
}
