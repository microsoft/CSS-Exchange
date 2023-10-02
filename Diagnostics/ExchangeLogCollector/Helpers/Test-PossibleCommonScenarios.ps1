# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-PossibleCommonScenarios {

    #all possible logs
    if ($AllPossibleLogs) {
        $Script:EWSLogs = $true
        $Script:IISLogs = $true
        $Script:DailyPerformanceLogs = $true
        $Script:ManagedAvailabilityLogs = $true
        $Script:RPCLogs = $true
        $Script:EASLogs = $true
        $Script:AutoDLogs = $true
        $Script:OWALogs = $true
        $Script:ADDriverLogs = $true
        $Script:SearchLogs = $true
        $Script:HighAvailabilityLogs = $true
        $Script:ServerInformation = $true
        $Script:GetVDirs = $true
        $Script:DAGInformation = $true
        $Script:DefaultTransportLogging = $true
        $Script:MapiLogs = $true
        $Script:OrganizationConfig = $true
        $Script:ECPLogs = $true
        $Script:ExchangeServerInformation = $true
        $Script:PopLogs = $true
        $Script:ImapLogs = $true
        $Script:ExPerfWiz = $true
        $Script:OABLogs = $true
        $Script:PowerShellLogs = $true
        $Script:WindowsSecurityLogs = $true
        $Script:CollectFailoverMetrics = $true
        $Script:ConnectivityLogs = $true
        $Script:ProtocolLogs = $true
        $Script:MitigationService = $true
        $Script:MailboxAssistantsLogs = $true
    }

    if ($DefaultTransportLogging) {
        $Script:HubConnectivityLogs = $true
        $Script:MessageTrackingLogs = $true
        $Script:QueueInformation = $true
        $Script:SendConnectors = $true
        $Script:ReceiveConnectors = $true
        $Script:TransportAgentLogs = $true
        $Script:TransportConfig = $true
        $Script:TransportRoutingTableLogs = $true
        $Script:FrontEndConnectivityLogs = $true
        $Script:MailboxConnectivityLogs = $true
        $Script:FrontEndProtocolLogs = $true
        $Script:MailboxDeliveryThrottlingLogs = $true
        $Script:PipelineTracingLogs = $true
        $Script:TransportRules = $true
        $Script:AcceptedRemoteDomain = $true
    }

    if ($ConnectivityLogs) {
        $Script:FrontEndConnectivityLogs = $true
        $Script:HubConnectivityLogs = $true
        $Script:MailboxConnectivityLogs = $true
    }

    if ($ProtocolLogs) {
        $Script:FrontEndProtocolLogs = $true
        $Script:HubProtocolLogs = $true
        $Script:MailboxProtocolLogs = $true
    }

    if ($DatabaseFailoverIssue) {
        $Script:DailyPerformanceLogs = $true
        $Script:HighAvailabilityLogs = $true
        $Script:ManagedAvailabilityLogs = $true
        $Script:DAGInformation = $true
        $Script:ExPerfWiz = $true
        $Script:ServerInformation = $true
        $Script:CollectFailoverMetrics = $true
    }

    if ($PerformanceIssues) {
        $Script:DailyPerformanceLogs = $true
        $Script:ManagedAvailabilityLogs = $true
        $Script:ExPerfWiz = $true
    }

    if ($PerformanceMailFlowIssues) {
        $Script:DailyPerformanceLogs = $true
        $Script:ExPerfWiz = $true
        $Script:MessageTrackingLogs = $true
        $Script:QueueInformation = $true
        $Script:TransportConfig = $true
        $Script:TransportRules = $true
        $Script:AcceptedRemoteDomain = $true
    }

    if ($OutlookConnectivityIssues) {
        $Script:DailyPerformanceLogs = $true
        $Script:ExPerfWiz = $true
        $Script:IISLogs = $true
        $Script:MapiLogs = $true
        $Script:RPCLogs = $true
        $Script:AutoDLogs = $true
        $Script:EWSLogs = $true
        $Script:ServerInformation = $true
    }

    #Because we right out our Receive Connector information in Exchange Server Info now
    if ($ReceiveConnectors -or
        $QueueInformation) {
        $Script:ExchangeServerInformation = $true
    }

    #See if any transport logging is enabled.
    $Script:AnyTransportSwitchesEnabled = $false
    if ($HubProtocolLogs -or
        $HubConnectivityLogs -or
        $MessageTrackingLogs -or
        $QueueInformation -or
        $SendConnectors -or
        $ReceiveConnectors -or
        $TransportConfig -or
        $FrontEndConnectivityLogs -or
        $FrontEndProtocolLogs -or
        $MailboxConnectivityLogs -or
        $MailboxProtocolLogs -or
        $MailboxDeliveryThrottlingLogs -or
        $TransportAgentLogs -or
        $TransportRoutingTableLogs -or
        $DefaultTransportLogging -or
        $PipelineTracingLogs -or
        $TransportRules -or
        $AcceptedRemoteDomain) {
        $Script:AnyTransportSwitchesEnabled = $true
    }

    if ($ServerInformation -or $ManagedAvailabilityLogs) {
        $Script:ExchangeServerInformation = $true
    }
}
