# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Invoke-RemoteMain {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Required to be used in the current format')]
    [CmdletBinding()]
    param()
    Write-ScriptDebug("Function Enter: Remote-Main")

    foreach ($server in $PassedInfo.ServerObjects) {

        if ($server.ServerName -eq $env:COMPUTERNAME) {
            $Script:localServerObject = $server
            break
        }
    }

    if ($null -eq $Script:localServerObject -or
        $Script:localServerObject.ServerName -ne $env:COMPUTERNAME) {
        Write-ScriptHost -WriteString ("Something went wrong trying to find the correct Server Object for this server. Stopping this instance of execution.")
        exit
    }

    $Script:TotalBytesSizeCopied = 0
    $Script:TotalBytesSizeCompressed = 0
    $Script:AdditionalFreeSpaceCushionGB = $PassedInfo.StandardFreeSpaceInGBCheckSize
    $Script:CurrentFreeSpaceGB = Get-FreeSpace -FilePath ("{0}\" -f $Script:RootCopyToDirectory)
    $Script:FreeSpaceMinusCopiedAndCompressedGB = $Script:CurrentFreeSpaceGB
    $Script:localExInstall = Get-ExchangeInstallDirectory
    $Script:localExBin = $Script:localExInstall + "Bin\"

    $cmdsToRun = @()
    #############################################
    #                                           #
    #              Exchange 2013 +              #
    #                                           #
    #############################################
    $copyInfo = "-LogPath '{0}' -CopyToThisLocation '{1}'"

    if ($Script:localServerObject.Version -ge 15) {
        Write-ScriptDebug("Server Version greater than 15")

        if ($PassedInfo.EWSLogs) {

            if ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\EWS"), ($Script:RootCopyToDirectory + "\EWS_BE_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += ("Copy-LogsBasedOnTime {0}" -f $info)
                } else {
                    $cmdsToRun += ("Copy-FullLogFullPathRecurse {0}" -f $info)
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Ews"), ($Script:RootCopyToDirectory + "\EWS_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += ("Copy-LogsBasedOnTime {0}" -f $info)
                } else {
                    $cmdsToRun += ("Copy-FullLogFullPathRecurse {0}" -f $info)
                }
            }
        }

        if ($PassedInfo.RPCLogs) {

            if ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\RPC Client Access"), ($Script:RootCopyToDirectory + "\RCA_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\RpcHttp"), ($Script:RootCopyToDirectory + "\RCA_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if (-not($Script:localServerObject.Edge)) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\RpcHttp"), ($Script:RootCopyToDirectory + "\RPC_Http_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }
        }

        if ($Script:localServerObject.CAS -and $PassedInfo.EASLogs) {
            $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Eas"), ($Script:RootCopyToDirectory + "\EAS_Proxy_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }
        }

        if ($PassedInfo.AutoDLogs) {

            if ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\Autodiscover"), ($Script:RootCopyToDirectory + "\AutoD_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Autodiscover"), ($Script:RootCopyToDirectory + "\AutoD_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }
        }

        if ($PassedInfo.OWALogs) {

            if ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\OWA"), ($Script:RootCopyToDirectory + "\OWA_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\OwaCalendar"), ($Script:RootCopyToDirectory + "\OWA_Proxy_Calendar_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }

                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Owa"), ($Script:RootCopyToDirectory + "\OWA_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }
        }

        if ($PassedInfo.ADDriverLogs) {
            $info = ($copyInfo -f ($Script:localExinstall + "Logging\ADDriver"), ($Script:RootCopyToDirectory + "\AD_Driver_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }
        }

        if ($PassedInfo.MapiLogs) {

            if ($Script:localServerObject.Mailbox -and $Script:localServerObject.Version -eq 15) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\MAPI Client Access"), ($Script:RootCopyToDirectory + "\MAPI_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            } elseif ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\MapiHttp\Mailbox"), ($Script:RootCopyToDirectory + "\MAPI_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Mapi"), ($Script:RootCopyToDirectory + "\MAPI_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }
        }

        if ($PassedInfo.ECPLogs) {

            if ($Script:localServerObject.Mailbox) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\ECP"), ($Script:RootCopyToDirectory + "\ECP_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($Script:localServerObject.CAS) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\HttpProxy\Ecp"), ($Script:RootCopyToDirectory + "\ECP_Proxy_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }
        }

        if ($Script:localServerObject.Mailbox -and $PassedInfo.SearchLogs) {
            $info = ($copyInfo -f ($Script:localExBin + "Search\Ceres\Diagnostics\Logs"), ($Script:RootCopyToDirectory + "\Search_Diag_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            $info = ($copyInfo -f ($Script:localExBin + "Search\Ceres\Diagnostics\ETLTraces"), ($Script:RootCopyToDirectory + "\Search_Diag_ETLs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            $info = ($copyInfo -f ($Script:localExInstall + "Logging\Search"), ($Script:RootCopyToDirectory + "\Search"))
            $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            $info = ($copyInfo -f ($Script:localExInstall + "Logging\Monitoring\Search"), ($Script:RootCopyToDirectory + "\Search_Monitoring"))
            $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info

            if ($Script:localServerObject.Version -ge 19) {
                $info = ($copyInfo -f ($Script:localExInstall + "Logging\BigFunnelMetricsCollectionAssistant"), ($Script:RootCopyToDirectory + "\BigFunnelMetricsCollectionAssistant"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                $info = ($copyInfo -f ($Script:localExInstall + "Logging\BigFunnelQueryParityAssistant"), ($Script:RootCopyToDirectory + "\BigFunnelQueryParityAssistant")) #This might not provide anything
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                $info = ($copyInfo -f ($Script:localExInstall + "Logging\BigFunnelRetryFeederTimeBasedAssistant"), ($Script:RootCopyToDirectory + "\BigFunnelRetryFeederTimeBasedAssistant"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
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
                    Write-ScriptDebug "Changing the location to get the daily performance logs to '$copyFrom'"
                }
            } catch {
                Write-ScriptDebug "Couldn't get logman info to verify Daily Performance Logs location"
                Invoke-CatchBlockActions
            }

            $info = ($copyInfo -f $copyFrom, ($Script:RootCopyToDirectory + "\Daily_Performance_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
        }

        if ($PassedInfo.ManagedAvailabilityLogs) {
            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\Monitoring"), ($Script:RootCopyToDirectory + "\ManagedAvailabilityMonitoringLogs"))
            $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
        }

        if ($PassedInfo.OABLogs) {
            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\HttpProxy\OAB"), ($Script:RootCopyToDirectory + "\OAB_Proxy_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }

            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\OABGeneratorLog"), ($Script:RootCopyToDirectory + "\OAB_Generation_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }

            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\OABGeneratorSimpleLog"), ($Script:RootCopyToDirectory + "\OAB_Generation_Simple_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }

            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\MAPI AddressBook Service"), ($Script:RootCopyToDirectory + "\MAPI_AddressBook_Service_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }
        }

        if ($PassedInfo.PowerShellLogs) {
            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\HttpProxy\PowerShell"), ($Script:RootCopyToDirectory + "\PowerShell_Proxy_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }
        }

        if ($Script:localServerObject.DAGMember -and
            $PassedInfo.DAGInformation) {
            $cmdsToRun += "Save-FailoverClusterInformation"
        }

        if ($PassedInfo.MitigationService) {
            $info = ($copyInfo -f ($Script:localExinstall + "\Logging\MitigationService"), ($Script:RootCopyToDirectory + "\Mitigation_Service_Logs"))

            if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            } else {
                $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
            }
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
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\RPC Client Access"), ($Script:RootCopyToDirectory + "\RCA_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                } else {
                    $cmdsToRun += "Copy-FullLogFullPathRecurse {0}" -f $info
                }
            }

            if ($PassedInfo.EWSLogs) {
                $info = ($copyInfo -f ($Script:localExinstall + "Logging\EWS"), ($Script:RootCopyToDirectory + "\EWS_BE_Logs"))

                if ($PassedInfo.CollectAllLogsBasedOnDaysWorth) {
                    $cmdsToRun += ("Copy-LogsBasedOnTime {0}" -f $info)
                } else {
                    $cmdsToRun += ("Copy-FullLogFullPathRecurse {0}" -f $info)
                }
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
            $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.MessageTrackingLogPath), ($Script:RootCopyToDirectory + "\Message_Tracking_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
        }

        if ($PassedInfo.HubProtocolLogs -and
            (-not ($Script:localServerObject.Version -eq 15 -and
                $Script:localServerObject.CASOnly))) {
            $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.ReceiveProtocolLogPath), ($Script:RootCopyToDirectory + "\Hub_Receive_Protocol_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.SendProtocolLogPath), ($Script:RootCopyToDirectory + "\Hub_Send_Protocol_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
        }

        if ($PassedInfo.HubConnectivityLogs -and
            (-not ($Script:localServerObject.Version -eq 15 -and
                $Script:localServerObject.CASOnly))) {
            $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.ConnectivityLogPath), ($Script:RootCopyToDirectory + "\Hub_Connectivity_Logs"))
            $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
        }

        if ($PassedInfo.QueueInformation -and
            (-not ($Script:localServerObject.Version -eq 15 -and
                $Script:localServerObject.CASOnly))) {

            if ($Script:localServerObject.Version -ge 15 -and
                $null -ne $Script:localServerObject.TransportInfo.HubLoggingInfo.QueueLogPath) {
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.HubLoggingInfo.QueueLogPath), ($Script:RootCopyToDirectory + "\Queue_V15_Data"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }
        }

        if ($PassedInfo.TransportConfig) {

            if ($Script:localServerObject.Version -ge 15 -and (-not($Script:localServerObject.Edge))) {
                $items = @()
                $items += $Script:localExBin + "\EdgeTransport.exe.config"
                $items += $Script:localExBin + "\MSExchangeFrontEndTransport.exe.config"
                $items += $Script:localExBin + "\MSExchangeDelivery.exe.config"
                $items += $Script:localExBin + "\MSExchangeSubmission.exe.config"
            } else {
                $items = @()
                $items += $Script:localExBin + "\EdgeTransport.exe.config"
            }

            Copy-BulkItems -CopyToLocation ($Script:RootCopyToDirectory + "\Transport_Configuration") -ItemsToCopyLocation $items
        }

        #Exchange 2013+ only
        if ($Script:localServerObject.Version -ge 15 -and
            (-not($Script:localServerObject.Edge))) {

            if ($PassedInfo.FrontEndConnectivityLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.MailboxOnly))) {
                Write-ScriptDebug("Collecting FrontEndConnectivityLogs")
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.FELoggingInfo.ConnectivityLogPath), ($Script:RootCopyToDirectory + "\FE_Connectivity_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

            if ($PassedInfo.FrontEndProtocolLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.MailboxOnly))) {
                Write-ScriptDebug("Collecting FrontEndProtocolLogs")
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.FELoggingInfo.ReceiveProtocolLogPath), ($Script:RootCopyToDirectory + "\FE_Receive_Protocol_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.FELoggingInfo.SendProtocolLogPath), ($Script:RootCopyToDirectory + "\FE_Send_Protocol_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

            if ($PassedInfo.MailboxConnectivityLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.CASOnly))) {
                Write-ScriptDebug("Collecting MailboxConnectivityLogs")
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.ConnectivityLogPath + "\Delivery"), ($Script:RootCopyToDirectory + "\MBX_Delivery_Connectivity_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.ConnectivityLogPath + "\Submission"), ($Script:RootCopyToDirectory + "\MBX_Submission_Connectivity_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

            if ($PassedInfo.MailboxProtocolLogs -and
                (-not ($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.CASOnly))) {
                Write-ScriptDebug("Collecting MailboxProtocolLogs")
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.ReceiveProtocolLogPath), ($Script:RootCopyToDirectory + "\MBX_Receive_Protocol_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.SendProtocolLogPath), ($Script:RootCopyToDirectory + "\MBX_Send_Protocol_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

            if ($PassedInfo.MailboxDeliveryThrottlingLogs -and
                (!($Script:localServerObject.Version -eq 15 -and
                    $Script:localServerObject.CASOnly))) {
                Write-ScriptDebug("Collecting Mailbox Delivery Throttling Logs")
                $info = ($copyInfo -f ($Script:localServerObject.TransportInfo.MBXLoggingInfo.MailboxDeliveryThrottlingLogPath), ($Script:RootCopyToDirectory + "\MBX_Delivery_Throttling_Logs"))
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }
        }
    }

    if ($PassedInfo.ImapLogs) {
        Write-ScriptDebug("Collecting IMAP Logs")
        $info = ($copyInfo -f ($Script:localServerObject.ImapLogsLocation), ($Script:RootCopyToDirectory + "\Imap_Logs"))
        $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
    }

    if ($PassedInfo.PopLogs) {
        Write-ScriptDebug("Collecting POP Logs")
        $info = ($copyInfo -f ($Script:localServerObject.PopLogsLocation), ($Script:RootCopyToDirectory + "\Pop_Logs"))
        $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
    }

    if ($PassedInfo.IISLogs) {

        Get-IISLogDirectory |
            ForEach-Object {
                $copyTo = "{0}\IIS_{1}_Logs" -f $Script:RootCopyToDirectory, ($_.Substring($_.LastIndexOf("\") + 1))
                $info = ($copyInfo -f $_, $copyTo)
                $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
            }

        $info = ($copyInfo -f ($env:SystemRoot + "\System32\LogFiles\HTTPERR"), ($Script:RootCopyToDirectory + "\HTTPERR_Logs"))
        $cmdsToRun += "Copy-LogsBasedOnTime {0}" -f $info
    }

    if ($PassedInfo.ServerInformation) {
        $cmdsToRun += "Save-ServerInfoData"
    }

    if ($PassedInfo.Experfwiz) {
        $cmdsToRun += "Save-LogmanExperfwizData"
    }

    if ($PassedInfo.Exmon) {
        $cmdsToRun += "Save-LogmanExmonData"
    }

    $cmdsToRun += "Save-WindowsEventLogs"

    #Execute the cmds
    foreach ($cmd in $cmdsToRun) {
        Write-ScriptDebug("cmd: {0}" -f $cmd)

        try {
            Invoke-Expression $cmd -ErrorAction Stop
        } catch {
            Write-ScriptDebug("Failed to finish running command: $cmd")
            Invoke-CatchBlockActions
        }
    }

    if ($Error.Count -ne 0) {
        Save-DataInfoToFile -DataIn $Error -SaveToLocation ("$Script:RootCopyToDirectory\AllErrors")
        Save-DataInfoToFile -DataIn $Script:ErrorsHandled -SaveToLocation ("$Script:RootCopyToDirectory\HandledErrors")
    } else {
        Write-ScriptDebug ("No errors occurred within the script")
    }
}

