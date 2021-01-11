Function Test-PossibleCommonScenarios {

    #all possible logs
    if ($AllPossibleLogs) {
        $Script:EWSLogs = $true
        $Script:IISLogs = $true
        $Script:DailyPerformanceLogs = $true
        $Script:ManagedAvailability = $true
        $Script:RPCLogs = $true
        $Script:EASLogs = $true
        $Script:AutoDLogs = $true
        $Script:OWALogs = $true
        $Script:ADDriverLogs = $true
        $Script:SearchLogs = $true
        $Script:HighAvailabilityLogs = $true
        $Script:ServerInfo = $true
        $Script:GetVdirs = $true
        $Script:DAGInformation = $true
        $Script:DefaultTransportLogging = $true
        $Script:MapiLogs = $true
        $Script:OrganizationConfig = $true
        $Script:ECPLogs = $true
        $Script:ExchangeServerInfo = $true
        $Script:PopLogs = $true
        $Script:ImapLogs = $true
        $Script:Experfwiz = $true
        $Script:OABLogs = $true
        $Script:PowerShellLogs = $true
        $Script:WindowsSecurityLogs = $true
    }

    if ($DefaultTransportLogging) {
        $Script:HubConnectivityLogs = $true
        $Script:MessageTrackingLogs = $true
        $Script:QueueInformationThisServer = $true
        $Script:SendConnectors = $true
        $Script:ReceiveConnectors = $true
        $Script:TransportConfig = $true
        $Script:FrontEndConnectivityLogs = $true
        $Script:MailboxConnectivityLogs = $true
        $Script:FrontEndProtocolLogs = $true
    }

    if ($DatabaseFailoverIssue) {
        $Script:DailyPerformanceLogs = $true
        $Script:HighAvailabilityLogs = $true
        $Script:ManagedAvailability = $true
        $Script:DAGInformation = $true
        $Script:Experfwiz = $true
        $Script:ServerInfo = $true
    }

    if ($PerformanceIssues) {
        $Script:DailyPerformanceLogs = $true
        $Script:ManagedAvailability = $true
        $Script:Experfwiz = $true
    }

    if ($PerformanceMailflowIssues) {
        $Script:DailyPerformanceLogs = $true
        $Script:Experfwiz = $true
        $Script:MessageTrackingLogs = $true
        $Script:QueueInformationThisServer = $true
        $Script:TransportConfig = $true
    }

    if ($OutlookConnectivityIssues) {
        $Script:DailyPerformanceLogs = $true
        $Script:Experfwiz = $true
        $Script:IISLogs = $true
        $Script:MapiLogs = $true
        $Script:RPCLogs = $true
        $Script:AutoDLogs = $true
        $Script:EWSLogs = $true
        $Script:ServerInfo = $true
    }

    #Because we right out our Receive Connector information in Exchange Server Info now
    if ($ReceiveConnectors -or
        $QueueInformationThisServer) {
        $Script:ExchangeServerInfo = $true
    }

    #See if any transport logging is enabled.
    $Script:AnyTransportSwitchesEnabled = $false
    if ($HubProtocolLogs -or
        $HubConnectivityLogs -or
        $MessageTrackingLogs -or
        $QueueInformationThisServer -or
        $SendConnectors -or
        $ReceiveConnectors -or
        $TransportConfig -or
        $FrontEndConnectivityLogs -or
        $FrontEndProtocolLogs -or
        $MailboxConnectivityLogs -or
        $MailboxProtocolLogs -or
        $DefaultTransportLogging) {
        $Script:AnyTransportSwitchesEnabled = $true
    }

    if ($ServerInfo -or $ManagedAvailability) {
        $Script:ExchangeServerInfo = $true
    }
}