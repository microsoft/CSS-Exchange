# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-TransportLoggingInformationPerServer {
    param(
        [string]$Server,
        [int]$Version,
        [bool]$EdgeServer,
        [bool]$CASOnly,
        [bool]$MailboxOnly
    )
    Write-Verbose("Function Enter: Get-TransportLoggingInformationPerServer")
    Write-Verbose("Passed: [string]Server: {0} | [int]Version: {1} | [bool]EdgeServer: {2} | [bool]CASOnly: {3} | [bool]MailboxOnly: {4}" -f $Server, $Version, $EdgeServer, $CASOnly, $MailboxOnly)
    $transportLoggingObject = New-Object PSCustomObject

    if ($Version -ge 15) {

        if (-not($CASOnly)) {
            #Hub Transport Layer
            $data = Get-TransportService -Identity $Server
            $hubObject = [PSCustomObject]@{
                ConnectivityLogPath    = $data.ConnectivityLogPath.ToString()
                MessageTrackingLogPath = $data.MessageTrackingLogPath.ToString()
                PipelineTracingPath    = $data.PipelineTracingPath.ToString()
                ReceiveProtocolLogPath = $data.ReceiveProtocolLogPath.ToString()
                SendProtocolLogPath    = $data.SendProtocolLogPath.ToString()
                WlmLogPath             = $data.WlmLogPath.ToString()
                RoutingTableLogPath    = $data.RoutingTableLogPath.ToString()
                AgentLogPath           = $data.AgentLogPath.ToString()
            }

            if (![string]::IsNullOrEmpty($data.QueueLogPath)) {
                $hubObject | Add-Member -MemberType NoteProperty -Name "QueueLogPath" -Value ($data.QueueLogPath.ToString())
            }

            $transportLoggingObject | Add-Member -MemberType NoteProperty -Name HubLoggingInfo -Value $hubObject
        }

        if (-not ($EdgeServer)) {
            #Front End Transport Layer
            if (($Version -eq 15 -and (-not ($MailboxOnly))) -or $Version -ge 16) {
                $data = Get-FrontendTransportService -Identity $Server

                if ($Version -ne 15 -and (-not([string]::IsNullOrEmpty($data.RoutingTableLogPath)))) {
                    $routingTableLogPath = $data.RoutingTableLogPath.ToString()
                }

                $FETransObject = [PSCustomObject]@{
                    ConnectivityLogPath    = $data.ConnectivityLogPath.ToString()
                    ReceiveProtocolLogPath = $data.ReceiveProtocolLogPath.ToString()
                    SendProtocolLogPath    = $data.SendProtocolLogPath.ToString()
                    AgentLogPath           = $data.AgentLogPath.ToString()
                    RoutingTableLogPath    = $routingTableLogPath
                }
                $transportLoggingObject | Add-Member -MemberType NoteProperty -Name FELoggingInfo -Value $FETransObject
            }

            if (($Version -eq 15 -and (-not ($CASOnly))) -or $Version -ge 16) {
                #Mailbox Transport Layer
                $data = Get-MailboxTransportService -Identity $Server

                if ($Version -ne 15 -and (-not([string]::IsNullOrEmpty($data.RoutingTableLogPath)))) {
                    $routingTableLogPath = $data.RoutingTableLogPath.ToString()
                }

                $mbxObject = [PSCustomObject]@{
                    ConnectivityLogPath              = $data.ConnectivityLogPath.ToString()
                    ReceiveProtocolLogPath           = $data.ReceiveProtocolLogPath.ToString()
                    SendProtocolLogPath              = $data.SendProtocolLogPath.ToString()
                    PipelineTracingPath              = $data.PipelineTracingPath.ToString()
                    MailboxDeliveryThrottlingLogPath = $data.MailboxDeliveryThrottlingLogPath.ToString()
                    MailboxDeliveryAgentLogPath      = $data.MailboxDeliveryAgentLogPath.ToString()
                    MailboxSubmissionAgentLogPath    = $data.MailboxSubmissionAgentLogPath.ToString()
                    RoutingTableLogPath              = $routingTableLogPath
                }
                $transportLoggingObject | Add-Member -MemberType NoteProperty -Name MBXLoggingInfo -Value $mbxObject
            }
        }
    } elseif ($Version -eq 14) {
        $data = Get-TransportServer -Identity $Server
        $hubObject = New-Object PSCustomObject #TODO Remove because we shouldn't support 2010 any longer
        $hubObject | Add-Member -MemberType NoteProperty -Name ConnectivityLogPath -Value ($data.ConnectivityLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name MessageTrackingLogPath -Value ($data.MessageTrackingLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name PipelineTracingPath -Value ($data.PipelineTracingPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name ReceiveProtocolLogPath -Value ($data.ReceiveProtocolLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name SendProtocolLogPath -Value ($data.SendProtocolLogPath.PathName)
        $transportLoggingObject | Add-Member -MemberType NoteProperty -Name HubLoggingInfo -Value $hubObject
    } else {
        Write-Host "trying to determine transport information for server $Server and wasn't able to determine the correct version type"
        return
    }

    Write-Verbose("Function Exit: Get-TransportLoggingInformationPerServer")
    return $transportLoggingObject
}
