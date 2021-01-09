Function Get-TransportLoggingInformationPerServer {
    param(
        [string]$Server,
        [int]$Version,
        [bool]$EdgeServer,
        [bool]$CASOnly,
        [bool]$MailboxOnly
    )
    Write-ScriptDebug("Function Enter: Get-TransportLoggingInformationPerServer")
    Write-ScriptDebug("Passed: [string]Server: {0} | [int]Version: {1} | [bool]EdgeServer: {2} | [bool]CASOnly: {3} | [bool]MailboxOnly: {4}" -f $Server, $Version, $EdgeServer, $CASOnly, $MailboxOnly)
    $hubObject = New-Object PSCustomObject
    $transportLoggingObject = New-Object PSCustomObject

    if ($Version -ge 15) {

        if (-not($CASOnly)) {
            #Hub Transport Layer
            $data = Get-TransportService -Identity $Server
            $hubObject | Add-Member -MemberType NoteProperty -Name ConnectivityLogPath -Value ($data.ConnectivityLogPath.PathName)
            $hubObject | Add-Member -MemberType NoteProperty -Name MessageTrackingLogPath -Value ($data.MessageTrackingLogPath.PathName)
            $hubObject | Add-Member -MemberType NoteProperty -Name PipelineTracingPath -Value ($data.PipelineTracingPath.PathName)
            $hubObject | Add-Member -MemberType NoteProperty -Name ReceiveProtocolLogPath -Value ($data.ReceiveProtocolLogPath.PathName)
            $hubObject | Add-Member -MemberType NoteProperty -Name SendProtocolLogPath -Value ($data.SendProtocolLogPath.PathName)
            $hubObject | Add-Member -MemberType NoteProperty -Name QueueLogPath -Value ($data.QueueLogPath.PathName)
            $hubObject | Add-Member -MemberType NoteProperty -Name WlmLogPath -Value ($data.WlmLogPath.PathName)
            $transportLoggingObject | Add-Member -MemberType NoteProperty -Name HubLoggingInfo -Value $hubObject
        }

        if (-not ($EdgeServer)) {
            #Front End Transport Layer
            if (($Version -eq 15 -and (-not ($MailboxOnly))) -or $Version -ge 16) {
                $FETransObject = New-Object PSCustomObject
                $data = Get-FrontendTransportService -Identity $Server
                $FETransObject | Add-Member -MemberType NoteProperty -Name ConnectivityLogPath -Value ($data.ConnectivityLogPath.PathName)
                $FETransObject | Add-Member -MemberType NoteProperty -Name ReceiveProtocolLogPath -Value ($data.ReceiveProtocolLogPath.PathName)
                $FETransObject | Add-Member -MemberType NoteProperty -Name SendProtocolLogPath -Value ($data.SendProtocolLogPath.PathName)
                $FETransObject | Add-Member -MemberType NoteProperty -Name AgentLogPath -Value ($data.AgentLogPath.PathName)
                $transportLoggingObject | Add-Member -MemberType NoteProperty -Name FELoggingInfo -Value $FETransObject
            }

            if (($Version -eq 15 -and (-not ($CASOnly))) -or $Version -ge 16) {
                #Mailbox Transport Layer
                $mbxObject = New-Object PSCustomObject
                $data = Get-MailboxTransportService -Identity $Server
                $mbxObject | Add-Member -MemberType NoteProperty -Name ConnectivityLogPath -Value ($data.ConnectivityLogPath.PathName)
                $mbxObject | Add-Member -MemberType NoteProperty -Name ReceiveProtocolLogPath -Value ($data.ReceiveProtocolLogPath.PathName)
                $mbxObject | Add-Member -MemberType NoteProperty -Name SendProtocolLogPath -Value ($data.SendProtocolLogPath.PathName)
                $mbxObject | Add-Member -MemberType NoteProperty -Name PipelineTracingPath -Value ($data.PipelineTracingPath.PathName)
                $mbxObject | Add-Member -MemberType NoteProperty -Name MailboxDeliveryThrottlingLogPath -Value ($data.MailboxDeliveryThrottlingLogPath.PathName)
                $transportLoggingObject | Add-Member -MemberType NoteProperty -Name MBXLoggingInfo -Value $mbxObject
            }
        }
    } elseif ($Version -eq 14) {
        $data = Get-TransportServer -Identity $Server
        $hubObject | Add-Member -MemberType NoteProperty -Name ConnectivityLogPath -Value ($data.ConnectivityLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name MessageTrackingLogPath -Value ($data.MessageTrackingLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name PipelineTracingPath -Value ($data.PipelineTracingPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name ReceiveProtocolLogPath -Value ($data.ReceiveProtocolLogPath.PathName)
        $hubObject | Add-Member -MemberType NoteProperty -Name SendProtocolLogPath -Value ($data.SendProtocolLogPath.PathName)
        $transportLoggingObject | Add-Member -MemberType NoteProperty -Name HubLoggingInfo -Value $hubObject
    } else {
        Write-ScriptHost -WriteString ("trying to determine transport information for server {0} and wasn't able to determine the correct version type" -f $Server) -ShowServer $false
        return
    }
    Write-ScriptDebug("ReceiveConnectors: {0} | QueueInformationThisServer: {1}" -f $ReceiveConnectors, $QueueInformationThisServer)

    if ($ReceiveConnectors) {
        $value = Get-ReceiveConnector -Server $Server
        $transportLoggingObject | Add-Member -MemberType NoteProperty -Name ReceiveConnectorData -Value $value
    }

    if ($QueueInformationThisServer -and
        (-not($Version -eq 15 -and
                $CASOnly))) {
        $value = Get-Queue -Server $Server
        $transportLoggingObject | Add-Member -MemberType NoteProperty -Name QueueData -Value $value
    }

    Write-ScriptDebug("Function Exit: Get-TransportLoggingInformationPerServer")
    return $transportLoggingObject
}