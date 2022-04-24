# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeInstallDirectory.ps1
. $PSScriptRoot\Get-FreeSpace.ps1
. $PSScriptRoot\Get-IISLogDirectory.ps1
. $PSScriptRoot\LogCopyTaskActionFunctions.ps1
. $PSScriptRoot\IO\Copy-BulkItems.ps1
. $PSScriptRoot\IO\Copy-FullLogFullPathRecurse.ps1
. $PSScriptRoot\IO\Copy-LogsBasedOnTime.ps1
. $PSScriptRoot\IO\Save-DataInfoToFile.ps1
. $PSScriptRoot\IO\Save-FailoverClusterInformation.ps1
. $PSScriptRoot\IO\Save-LogmanExmonData.ps1
. $PSScriptRoot\IO\Save-LogmanExperfwizData.ps1
. $PSScriptRoot\IO\Save-ServerInfoData.ps1
. $PSScriptRoot\IO\Save-WindowsEventLogs.ps1
Function Invoke-RemoteMain {
    [CmdletBinding()]
    param()
    Write-Verbose("Function Enter: Remote-Main")

    $Script:localServerObject = $PassedInfo.ServerObjects |
        Where-Object { $_.ServerName -eq $env:COMPUTERNAME }

    if ($null -eq $Script:localServerObject -or
        $Script:localServerObject.ServerName -ne $env:COMPUTERNAME) {
        Write-Host "Something went wrong trying to find the correct Server Object for this server. Stopping this instance of execution."
        exit
    }

    $Script:TotalBytesSizeCopied = 0
    $Script:TotalBytesSizeCompressed = 0
    $Script:AdditionalFreeSpaceCushionGB = $PassedInfo.StandardFreeSpaceInGBCheckSize
    $Script:CurrentFreeSpaceGB = Get-FreeSpace -FilePath ("{0}\" -f $Script:RootCopyToDirectory)
    $Script:FreeSpaceMinusCopiedAndCompressedGB = $Script:CurrentFreeSpaceGB
    $Script:localExInstall = Get-ExchangeInstallDirectory
    $Script:localExBin = $Script:localExInstall + "Bin\"
    $Script:taskActionList = New-Object "System.Collections.Generic.List[object]"
    #############################################
    #                                           #
    #              Exchange 2013 +              #
    #                                           #
    #############################################

    if ($Script:localServerObject.Version -ge 15) {
        Write-Verbose("Server Version greater than 15")

        if ($PassedInfo.EWSLogs) {

            if ($Script:localServerObject.Mailbox) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\EWS" "EWS_BE_Logs"
            }

            if ($Script:localServerObject.CAS) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\HttpProxy\Ews" "EWS_Proxy_Logs"
            }
        }

        if ($PassedInfo.RPCLogs) {

            if ($Script:localServerObject.Mailbox) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\RPC Client Access" "RCA_Logs"
            }

            if ($Script:localServerObject.CAS) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\HttpProxy\RpcHttp" "RCA_Proxy_Logs"
            }

            if (-not($Script:localServerObject.Edge)) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\RpcHttp" "RPC_Http_Logs"
            }
        }

        if ($Script:localServerObject.CAS -and $PassedInfo.EASLogs) {
            Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\HttpProxy\Eas" "EAS_Proxy_Logs"
        }

        if ($PassedInfo.AutoDLogs) {

            if ($Script:localServerObject.Mailbox) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\Autodiscover" "AutoD_Logs"
            }

            if ($Script:localServerObject.CAS) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\HttpProxy\Autodiscover" "AutoD_Proxy_Logs"
            }
        }

        if ($PassedInfo.OWALogs) {

            if ($Script:localServerObject.Mailbox) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\OWA" "OWA_Logs"
            }

            if ($Script:localServerObject.CAS) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\HttpProxy\OwaCalendar" "OWA_Proxy_Calendar_Logs"
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\HttpProxy\Owa" "OWA_Proxy_Logs"
            }
        }

        if ($PassedInfo.ADDriverLogs) {
            Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\ADDriver" "AD_Driver_Logs"
        }

        if ($PassedInfo.MapiLogs) {

            if ($Script:localServerObject.Mailbox -and $Script:localServerObject.Version -eq 15) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\MAPI Client Access" "MAPI_Logs"
            } elseif ($Script:localServerObject.Mailbox) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\MapiHttp\Mailbox" "MAPI_Logs"
            }

            if ($Script:localServerObject.CAS) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\HttpProxy\Mapi" "MAPI_Proxy_Logs"
            }
        }

        if ($PassedInfo.ECPLogs) {

            if ($Script:localServerObject.Mailbox) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\ECP" "ECP_Logs"
            }

            if ($Script:localServerObject.CAS) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\HttpProxy\Ecp" "ECP_Proxy_Logs"
            }
        }

        if ($Script:localServerObject.Mailbox -and $PassedInfo.SearchLogs) {
            Add-LogCopyBasedOffTimeTaskAction "$Script:localExBin`Search\Ceres\Diagnostics\Logs" "Search_Diag_Logs"
            Add-LogCopyBasedOffTimeTaskAction "$Script:localExBin`Search\Ceres\Diagnostics\ETLTraces" "Search_Diag_ETLs"
            Add-LogCopyFullTaskAction "$Script:localExInstall`Logging\Search" "Search"
            Add-LogCopyFullTaskAction "$Script:localExInstall`Logging\Monitoring\Search" "Search_Monitoring"

            if ($Script:localServerObject.Version -ge 19) {
                Add-LogCopyBasedOffTimeTaskAction "$Script:localExInstall`Logging\BigFunnelMetricsCollectionAssistant" "BigFunnelMetricsCollectionAssistant"
                Add-LogCopyBasedOffTimeTaskAction  "$Script:localExInstall`Logging\BigFunnelQueryParityAssistant" "BigFunnelQueryParityAssistant" #This might not provide anything
                Add-LogCopyBasedOffTimeTaskAction "$Script:localExInstall`Logging\BigFunnelRetryFeederTimeBasedAssistant" "BigFunnelRetryFeederTimeBasedAssistant"
            }
        }

        if ($PassedInfo.DailyPerformanceLogs) {
            #Daily Performance Logs are always by days worth
            $copyFrom = "$Script:localExinstall`Logging\Diagnostics\DailyPerformanceLogs"

            try {
                $logmanOutput = logman ExchangeDiagnosticsDailyPerformanceLog
                $logmanRootPath = $logmanOutput | Select-String "Root Path:"

                if (!$logmanRootPath.ToString().Contains($copyFrom)) {
                    $copyFrom = $logmanRootPath.ToString().Replace("Root Path:", "").Trim()
                    Write-Verbose "Changing the location to get the daily performance logs to '$copyFrom'"
                }
            } catch {
                Write-Verbose "Couldn't get logman info to verify Daily Performance Logs location"
                Invoke-CatchBlockActions
            }
            Add-LogCopyBasedOffTimeTaskAction $copyFrom "Daily_Performance_Logs"
        }

        if ($PassedInfo.ManagedAvailabilityLogs) {
            Add-LogCopyFullTaskAction "$Script:localExinstall`Logging\Monitoring" "ManagedAvailabilityMonitoringLogs"
        }

        if ($PassedInfo.OABLogs) {
            Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\HttpProxy\OAB" "OAB_Proxy_Logs"
            Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\OABGeneratorLog" "OAB_Generation_Logs"
            Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\OABGeneratorSimpleLog" "OAB_Generation_Simple_Logs"
            Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\MAPI AddressBook Service" "MAPI_AddressBook_Service_Logs"
        }

        if ($PassedInfo.PowerShellLogs) {
            Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\HttpProxy\PowerShell" "PowerShell_Proxy_Logs"
        }

        if ($Script:localServerObject.DAGMember -and
            $PassedInfo.DAGInformation) {
            Add-TaskAction "Save-FailoverClusterInformation"
        }

        if ($PassedInfo.MitigationService) {
            Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\MitigationService" "Mitigation_Service_Logs"
        }
    }

    ############################################
    #                                          #
    #              Exchange 2010               #
    #                                          #
    ############################################
    if ($Script:localServerObject.Version -eq 14) {

        if ($Script:localServerObject.CAS) {

            if ($PassedInfo.RPCLogs) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\RPC Client Access" "RCA_Logs"
            }

            if ($PassedInfo.EWSLogs) {
                Add-DefaultLogCopyTaskAction "$Script:localExinstall`Logging\EWS" "EWS_BE_Logs"
            }
        }
    }

    ############################################
    #                                          #
    #          All Exchange Versions           #
    #                                          #
    ############################################
    if ($PassedInfo.AnyTransportSwitchesEnabled -and
        $Script:localServerObject.TransportInfoCollect) {

        if ($PassedInfo.MessageTrackingLogs -and
            (-not ($Script:localServerObject.Version -eq 15 -and
                $Script:localServerObject.CASOnly))) {
            Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.TransportInfo.HubLoggingInfo.MessageTrackingLogPath "Message_Tracking_Logs"
        }

        if ($PassedInfo.HubProtocolLogs -and
            (-not ($Script:localServerObject.Version -eq 15 -and
                $Script:localServerObject.CASOnly))) {
            Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.TransportInfo.HubLoggingInfo.ReceiveProtocolLogPath "Hub_Receive_Protocol_Logs"
            Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.TransportInfo.HubLoggingInfo.SendProtocolLogPath "Hub_Send_Protocol_Logs"
        }

        if ($PassedInfo.HubConnectivityLogs -and
            (-not ($Script:localServerObject.Version -eq 15 -and
                $Script:localServerObject.CASOnly))) {
            Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.TransportInfo.HubLoggingInfo.ConnectivityLogPath "Hub_Connectivity_Logs"
        }

        if ($PassedInfo.QueueInformation -and
            (-not ($Script:localServerObject.Version -eq 15 -and
                $Script:localServerObject.CASOnly))) {

            if ($Script:localServerObject.Version -ge 15 -and
                $null -ne $Script:localServerObject.TransportInfo.HubLoggingInfo.QueueLogPath) {
                Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.TransportInfo.HubLoggingInfo.QueueLogPath "Queue_V15_Data"
            }
        }

        if ($PassedInfo.TransportConfig) {

            $items = @()
            if ($Script:localServerObject.Version -ge 15 -and (-not($Script:localServerObject.Edge))) {
                $items += $Script:localExBin + "\EdgeTransport.exe.config"
                $items += $Script:localExBin + "\MSExchangeFrontEndTransport.exe.config"
                $items += $Script:localExBin + "\MSExchangeDelivery.exe.config"
                $items += $Script:localExBin + "\MSExchangeSubmission.exe.config"
            } else {
                $items += $Script:localExBin + "\EdgeTransport.exe.config"
            }

            # TODO: Make into a task vs in the main loop
            Copy-BulkItems -CopyToLocation ($Script:RootCopyToDirectory + "\Transport_Configuration") -ItemsToCopyLocation $items
        }

        #Exchange 2013+ only
        if ($Script:localServerObject.Version -ge 15 -and
            (-not($Script:localServerObject.Edge))) {

            if ($PassedInfo.FrontEndConnectivityLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.MailboxOnly))) {
                Write-Verbose("Collecting FrontEndConnectivityLogs")
                Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.TransportInfo.FELoggingInfo.ConnectivityLogPath "FE_Connectivity_Logs"
            }

            if ($PassedInfo.FrontEndProtocolLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.MailboxOnly))) {
                Write-Verbose("Collecting FrontEndProtocolLogs")
                Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.TransportInfo.FELoggingInfo.ReceiveProtocolLogPath "FE_Receive_Protocol_Logs"
                Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.TransportInfo.FELoggingInfo.SendProtocolLogPath "FE_Send_Protocol_Logs"
            }

            if ($PassedInfo.MailboxConnectivityLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.CASOnly))) {
                Write-Verbose("Collecting MailboxConnectivityLogs")
                Add-LogCopyBasedOffTimeTaskAction "$($Script:localServerObject.TransportInfo.MBXLoggingInfo.ConnectivityLogPath)\Delivery" "MBX_Delivery_Connectivity_Logs"
                Add-LogCopyBasedOffTimeTaskAction "$($Script:localServerObject.TransportInfo.MBXLoggingInfo.ConnectivityLogPath)\Submission" "MBX_Submission_Connectivity_Logs"
            }

            if ($PassedInfo.MailboxProtocolLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.CASOnly))) {
                Write-Verbose("Collecting MailboxProtocolLogs")
                Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.TransportInfo.MBXLoggingInfo.ReceiveProtocolLogPath "MBX_Receive_Protocol_Logs"
                Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.TransportInfo.MBXLoggingInfo.SendProtocolLogPath "MBX_Send_Protocol_Logs"
            }

            if ($PassedInfo.MailboxDeliveryThrottlingLogs -and
                (!($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.CASOnly))) {
                Write-Verbose("Collecting Mailbox Delivery Throttling Logs")
                Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.TransportInfo.MBXLoggingInfo.MailboxDeliveryThrottlingLogPath "MBX_Delivery_Throttling_Logs"
            }
        }
    }

    if ($PassedInfo.ImapLogs) {
        Write-Verbose("Collecting IMAP Logs")
        Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.ImapLogsLocation "Imap_Logs"
    }

    if ($PassedInfo.PopLogs) {
        Write-Verbose("Collecting POP Logs")
        Add-LogCopyBasedOffTimeTaskAction $Script:localServerObject.PopLogsLocation "Pop_Logs"
    }

    if ($PassedInfo.IISLogs) {

        Get-IISLogDirectory |
            ForEach-Object {
                $copyTo = "{0}\IIS_{1}_Logs" -f $Script:RootCopyToDirectory, ($_.Substring($_.LastIndexOf("\") + 1))
                Add-LogCopyBasedOffTimeTaskAction $_ $copyTo
            }

        Add-LogCopyBasedOffTimeTaskAction "$env:SystemRoot`\System32\LogFiles\HTTPERR" "HTTPERR_Logs"
    }

    if ($PassedInfo.ServerInformation) {
        Add-TaskAction "Save-ServerInfoData"
    }

    if ($PassedInfo.Experfwiz) {
        Add-TaskAction "Save-LogmanExperfwizData"
    }

    if ($PassedInfo.Exmon) {
        Add-TaskAction "Save-LogmanExmonData"
    }

    Add-TaskAction "Save-WindowsEventLogs"
    #Execute the cmds
    foreach ($taskAction in $Script:taskActionList) {
        Write-Verbose(("Task Action: $(GetTaskActionToString $taskAction)"))

        try {
            $params = $taskAction.Parameters

            if ($null -ne $params) {
                & $taskAction.FunctionName @params -ErrorAction Stop
            } else {
                & $taskAction.FunctionName -ErrorAction Stop
            }
        } catch {
            Write-Verbose("Failed to finish running command: $(GetTaskActionToString $taskAction)")
            Invoke-CatchBlockActions
        }
    }

    if ($Error.Count -ne 0) {
        Save-DataInfoToFile -DataIn $Error -SaveToLocation ("$Script:RootCopyToDirectory\AllErrors")
        Save-DataInfoToFile -DataIn $Script:ErrorsHandled -SaveToLocation ("$Script:RootCopyToDirectory\HandledErrors")
    } else {
        Write-Verbose ("No errors occurred within the script")
    }
}
