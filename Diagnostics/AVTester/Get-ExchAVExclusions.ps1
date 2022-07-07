# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ExchAVExclusions {
    [CmdletBinding()]
    [OutputType([Collections.Generic.List[string]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
                if (Test-Path $_) { $true }
                else { throw "Path $_ is not valid" }
            })]
        [string]
        $ExchangePath
    )
    # Create the Array List
    $BaseFolders = New-Object Collections.Generic.List[string]

    # List of base Folders
    if ((Get-ExchangeServer $env:COMPUTERNAME).IsMailboxServer) {
        if (Get-DatabaseAvailabilityGroup ) {
            if ((Get-DatabaseAvailabilityGroup).Servers.name.Contains($env:COMPUTERNAME) ) {
                $BaseFolders.Add((Join-Path $($env:SystemRoot) '\Cluster').tolower())
                $dag = $null
                $dag = Get-DatabaseAvailabilityGroup | Where-Object { $_.Servers.Name.Contains($env:COMPUTERNAME) }
                #needs local system rigths
                if ( $null -ne $dag ) {
                    $BaseFolders.Add($("\\" + $($dag.WitnessServer.Fqdn) + "\" + $($dag.WitnessDirectory.PathName.Split("\")[-1])).ToLower())
                }
            }
        }
        $BaseFolders.Add((Join-Path $ExchangePath '\ClientAccess\OAB').tolower())
        $BaseFolders.Add((Join-Path $ExchangePath '\FIP-FS').tolower())
        $BaseFolders.Add((Join-Path $ExchangePath '\GroupMetrics').tolower())
        $BaseFolders.Add((Join-Path $ExchangePath '\Logging').tolower())
        if ($($serverExchangeInstallDirectory.MsiProductMinor) -eq 0 ) {
            $BaseFolders.Add((Join-Path $ExchangePath '\Mailbox\MDBTEMP').tolower())
        }

        $mbxS = Get-MailboxServer -Identity $($env:COMPUTERNAME) | Select-Object CalendarRepairLogPath, LogPathForManagedFolders, `
            DataPath, MigrationLogFilePath, TransportSyncLogFilePath, TransportSyncMailboxHealthLogFilePath
        $mbxS.psobject.Properties.Value.PathName | ForEach-Object {
            if ( $_ ) {
                if ( Test-Path $_ -PathType Container ) {
                    $BaseFolders.Add($_.tolower())
                }
            }
        }

        # Add all database folder paths
        foreach ($Entry in (Get-MailboxDatabase -Server $Env:COMPUTERNAME)) {
            $BaseFolders.Add((Split-Path $Entry.EdbFilePath -Parent).tolower())
            $mbdblogs = $Entry | Select-Object TemporaryDataFolderPath, LogFolderPath

            $mbdblogs.psobject.Properties.Value.PathName | ForEach-Object {
                if ( $_ ) {
                    if ( Test-Path $_ -PathType Container ) {
                        $BaseFolders.Add($_.tolower())
                    }
                }
            }
        }

        $mtsLogs = Get-MailboxTransportService $($env:COMPUTERNAME) | Select-Object ConnectivityLogPath, `
            ReceiveProtocolLogPath, SendProtocolLogPath, MailboxSubmissionAgentLogPath, MailboxDeliveryAgentLogPath, `
            DnsLogPath, RoutingTableLogPath, SyncDeliveryLogPath, MailboxDeliveryHttpDeliveryLogPath, `
            MailboxDeliveryThrottlingLogPath, AgentGrayExceptionLogPath, PipelineTracingPath
        $mtsLogs.psobject.Properties.Value.PathName | ForEach-Object {
            if ( $_ ) {
                if ( Test-Path $_ -PathType Container ) {
                    $BaseFolders.Add($_.tolower())
                }
            }
        }

        #'$env:SystemRoot\Temp\OICE_<GUID>'
        $possibleOICEFolders = Get-ChildItem $env:SystemRoot\temp -Directory -Filter OICE_*.0
        $possibleOICEFolders | ForEach-Object {
            if ( $_.Name.Length -gt 41) {
                $possibleGUID = $_.Name.Substring(5, 36)
                $result = [System.Guid]::Empty
                if ( [System.Guid]::TryParse($possibleGUID, [System.Management.Automation.PSReference]$result) ) {
                    $BaseFolders.Add($_.FullName.tolower())
                }
            }
        }
    }

    if ((Get-ExchangeServer $env:COMPUTERNAME).IsUnifiedMessagingServer) {
        $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Grammars'))
        $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Prompts'))
        $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Temp'))
        $BaseFolders.Add((Join-Path $ExchangePath '\UnifiedMessaging\Voicemail'))
    }

    if ((Get-ExchangeServer $env:COMPUTERNAME).IsClientAccessServer) {

        $fetsLogs = Get-FrontEndTransportService $($env:COMPUTERNAME) | Select-Object ConnectivityLogPath, `
            ReceiveProtocolLogPath, SendProtocolLogPath, AgentLogPath, DnsLogPath, ResourceLogPath, `
            AttributionLogPath, `
            RoutingTableLogPath, ProxyDestinationsLogPath, TopInboundIpSourcesLogPath
        $fetsLogs.psobject.Properties.Value.PathName | ForEach-Object {
            if ( $_) {
                if ( Test-Path $_ -PathType Container ) {
                    $BaseFolders.Add($_.tolower())
                }
            }
        }

        $BaseFolders.Add((Join-Path $env:SystemDrive '\inetpub\temp\IIS Temporary Compressed Files').tolower())
        $BaseFolders.Add((Join-Path $env:SystemRoot '\System32\Inetsrv').tolower())
        $BaseFolders.Add((Join-Path $env:SystemRoot '\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files').tolower())
        $BaseFolders.Add(($((Get-PopSettings).LogFileLocation)).tolower())
        $BaseFolders.Add(($((Get-ImapSettings).LogFileLocation)).tolower())
    }

    if ((Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer) {
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\Adam').tolower())
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\IpFilter').tolower())
    }

    if ((Get-ExchangeServer $env:COMPUTERNAME).IsEdgeServer -or (Get-ExchangeServer $env:COMPUTERNAME).IsHubTransportServer) {
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\Queue').tolower())
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\SenderReputation').tolower())
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Data\Temp').tolower())
        $BaseFolders.Add((Join-Path $ExchangePath '\TransportRoles\Logs').tolower())

        $tsLogs = Get-TransportService $($env:COMPUTERNAME) | Select-Object ConnectivityLogPath, MessageTrackingLogPath, `
            IrmLogPath, ActiveUserStatisticsLogPath, ServerStatisticsLogPath, ReceiveProtocolLogPath, RoutingTableLogPath, `
            SendProtocolLogPath, QueueLogPath, LatencyLogPath, GeneralLogPath, WlmLogPath, AgentLogPath, FlowControlLogPath, `
            ProcessingSchedulerLogPath, ResourceLogPath, DnsLogPath, JournalLogPath, TransportMaintenanceLogPath, `
            RequestBrokerLogPath, StorageRESTLogPath, AgentGrayExceptionLogPath, TransportHttpLogPath, PipelineTracingPath, `
            PickupDirectoryPath, ReplayDirectoryPath, `
            RootDropDirectoryPath
        $tsLogs.psobject.Properties.Value.PathName | ForEach-Object {
            if ( $_ ) {
                if ( Test-Path $_ -PathType Container ) {
                    $BaseFolders.Add($_.tolower())
                }
            }
        }

        $BaseFolders.Add((Join-Path $ExchangePath '\Working\OleConverter').tolower())

        # Get transport database path
        [xml]$TransportConfig = Get-Content (Join-Path $ExchangePath "Bin\EdgeTransport.exe.config")
        $BaseFolders.Add(($TransportConfig.configuration.appsettings.Add | Where-Object { $_.key -eq "QueueDatabasePath" }).value.tolower())
        $BaseFolders.Add(($TransportConfig.configuration.appsettings.Add | Where-Object { $_.key -eq "QueueDatabaseLoggingPath" }).value.tolower())

        if ($($serverExchangeInstallDirectory.MsiProductMinor) -eq 0 ) {
            #E13MBX  By default, content conversions are performed in the Exchange server's %TMP% folder.
            $BaseFolders.Add((Join-Path $env:SystemRoot '\Temp').tolower())
        }
    }

    if ($($serverExchangeInstallDirectory.MsiProductMinor) -eq 0 ) {
        #E13 Exchange Server setup temporary files.
        $BaseFolders.Add((Join-Path $env:SystemRoot '\Temp\ExchangeSetup').tolower())

        # it is only in client Access E13 doc--- Inetpub\logs\logfiles\w3svc
        Get-Website | Where-Object { $_.name -eq 'Default Web Site' -or $_.name -eq 'Exchange Back End' } | ForEach-Object {
            if ($_.logfile.directory.StartsWith('%')) {
                $BaseFolders.Add(("$(Get-Content -Path Env:"$($_.logFile.directory.Split('%')[1])")$($_.logFile.directory.Split('%')[2])\W3SVC$($_.id)").ToLower())
            } else {
                $BaseFolders.Add(("$($_.logfile.directory)\W3SVC$($_.id)").ToLower())
            }
        }
    }

    # Remove any Duplicates
    $BaseFolders = $BaseFolders | Select-Object -Unique

    #'$env:SystemRoot\Temp\OICE_<GUID>'
    #'$env:SystemDrive\DAGFileShareWitnesses\<DAGFQDN>'
    $BaseFolders
}
