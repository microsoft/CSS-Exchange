Function Get-ArgumentList {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'TODO: Change this')]
    param(
        [Parameter(Mandatory = $true)][array]$Servers
    )

    $obj = New-Object PSCustomObject
    $obj | Add-Member -Name FilePath -MemberType NoteProperty -Value $FilePath
    $obj | Add-Member -Name RootFilePath -MemberType NoteProperty -Value $Script:RootFilePath
    $obj | Add-Member -Name ServerObjects -MemberType NoteProperty -Value (Get-ServerObjects -ValidServers $Servers)
    $obj | Add-Member -Name ManagedAvailability -MemberType NoteProperty -Value $ManagedAvailability
    $obj | Add-Member -Name AppSysLogs -MemberType NoteProperty -Value $AppSysLogs
    $obj | Add-Member -Name EWSLogs -MemberType NoteProperty -Value $EWSLogs
    $obj | Add-Member -Name DailyPerformanceLogs -MemberType NoteProperty -Value $DailyPerformanceLogs
    $obj | Add-Member -Name RPCLogs -MemberType NoteProperty -Value $RPCLogs
    $obj | Add-Member -Name EASLogs -MemberType NoteProperty -Value $EASLogs
    $obj | Add-Member -Name ECPLogs -MemberType NoteProperty -Value $ECPLogs
    $obj | Add-Member -Name AutoDLogs -MemberType NoteProperty -Value $AutoDLogs
    $obj | Add-Member -Name OWALogs -MemberType NoteProperty -Value $OWALogs
    $obj | Add-Member -Name ADDriverLogs -MemberType NoteProperty -Value $ADDriverLogs
    $obj | Add-Member -Name SearchLogs -MemberType NoteProperty -Value $SearchLogs
    $obj | Add-Member -Name HighAvailabilityLogs -MemberType NoteProperty -Value $HighAvailabilityLogs
    $obj | Add-Member -Name MapiLogs -MemberType NoteProperty -Value $MapiLogs
    $obj | Add-Member -Name MessageTrackingLogs -MemberType NoteProperty -Value $MessageTrackingLogs
    $obj | Add-Member -Name HubProtocolLogs -MemberType NoteProperty -Value $HubProtocolLogs
    $obj | Add-Member -Name HubConnectivityLogs -MemberType NoteProperty -Value $HubConnectivityLogs
    $obj | Add-Member -Name FrontEndConnectivityLogs -MemberType NoteProperty -Value $FrontEndConnectivityLogs
    $obj | Add-Member -Name FrontEndProtocolLogs -MemberType NoteProperty -Value $FrontEndProtocolLogs
    $obj | Add-Member -Name MailboxConnectivityLogs -MemberType NoteProperty -Value $MailboxConnectivityLogs
    $obj | Add-Member -Name MailboxProtocolLogs -MemberType NoteProperty -Value $MailboxProtocolLogs
    $obj | Add-Member -Name QueueInformationThisServer -MemberType NoteProperty -Value $QueueInformationThisServer
    $obj | Add-Member -Name SendConnectors -MemberType NoteProperty -Value $SendConnectors
    $obj | Add-Member -Name DAGInformation -MemberType NoteProperty -Value $DAGInformation
    $obj | Add-Member -Name GetVdirs -MemberType NoteProperty -Value $GetVdirs
    $obj | Add-Member -Name TransportConfig -MemberType NoteProperty -Value $TransportConfig
    $obj | Add-Member -Name DefaultTransportLogging -MemberType NoteProperty -Value $DefaultTransportLogging
    $obj | Add-Member -Name ServerInfo -MemberType NoteProperty -Value $ServerInfo
    $obj | Add-Member -Name CollectAllLogsBasedOnDaysWorth -MemberType NoteProperty -Value $CollectAllLogsBasedOnDaysWorth
    $obj | Add-Member -Name DaysWorth -MemberType NoteProperty -Value $DaysWorth
    $obj | Add-Member -Name IISLogs -MemberType NoteProperty -Value $IISLogs
    $obj | Add-Member -Name AnyTransportSwitchesEnabled -MemberType NoteProperty -Value $script:AnyTransportSwitchesEnabled
    $obj | Add-Member -Name HostExeServerName -MemberType NoteProperty -Value ($env:COMPUTERNAME)
    $obj | Add-Member -Name Experfwiz -MemberType NoteProperty -Value $Experfwiz
    $obj | Add-Member -Name ExperfwizLogmanName -MemberType NoteProperty -Value $ExperfwizLogmanName
    $obj | Add-Member -Name Exmon -MemberType NoteProperty -Value $Exmon
    $obj | Add-Member -Name ExmonLogmanName -MemberType NoteProperty -Value $ExmonLogmanName
    $obj | Add-Member -Name ScriptDebug -MemberType NoteProperty -Value $ScriptDebug
    $obj | Add-Member -Name ExchangeServerInfo -MemberType NoteProperty -Value $ExchangeServerInfo
    $obj | Add-Member -Name StandardFreeSpaceInGBCheckSize -MemberType NoteProperty $Script:StandardFreeSpaceInGBCheckSize
    $obj | Add-Member -Name PopLogs -MemberType NoteProperty -Value $PopLogs
    $obj | Add-Member -Name ImapLogs -MemberType NoteProperty -Value $ImapLogs
    $obj | Add-Member -Name OABLogs -MemberType NoteProperty -Value $OABLogs
    $obj | Add-Member -Name PowerShellLogs -MemberType NoteProperty -Value $PowerShellLogs
    $obj | Add-Member -Name WindowsSecurityLogs -MemberType NoteProperty $WindowsSecurityLogs

    #Collect only if enabled we are going to just keep it on the base of the passed parameter object to make it simple
    $mbx = $false
    foreach ($svr in $obj.ServerObjects) {
        if ($svr.ServerName -eq $env:COMPUTERNAME) {
            $mbx = $true
            $checkSvr = $svr
        }
    }

    if (($mbx) -and ($HighAvailabilityLogs) -and ($checkSvr.DAGMember)) {
        Write-ScriptHost -WriteString ("Generating cluster logs for the local server's DAG only") -ShowServer $false
        Write-ScriptHost -WriteString ("Server: {0}" -f $checkSvr.ServerName) -ShowServer $false
        #Only going to do this for the local server's DAG
        $cmd = "Cluster log /g"
        Invoke-Expression -Command $cmd | Out-Null
    }

    if ($SendConnectors) {
        #TODO move this to a different location, but for now this should work.
        $value = Get-SendConnector
        $Script:SendConnectorData = $value
        #$obj | Add-Member -MemberType NoteProperty -Name SendConnectorData -Value $value
    }

    return $obj
}