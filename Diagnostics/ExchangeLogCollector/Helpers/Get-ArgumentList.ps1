﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\ExchangeServerInfo\Get-ServerObjects.ps1
function Get-ArgumentList {
    param(
        [Parameter(Mandatory = $true)][array]$Servers
    )

    #First we need to verify if the local computer is in the list or not. If it isn't we need to pick a master server to store
    #the additional information vs having a small amount of data dumped into the local directory.
    $localServerInList = $false
    $Script:MasterServer = $env:COMPUTERNAME
    foreach ($server in $Servers) {

        if ($server.ToUpper().Contains($env:COMPUTERNAME.ToUpper())) {
            $localServerInList = $true
            break
        }
    }

    if (!$localServerInList) {
        $Script:MasterServer = $Servers[0]
    }

    $argumentList = [PSCustomObject]@{
        AcceptedRemoteDomain           = $AcceptedRemoteDomain
        ADDriverLogs                   = $ADDriverLogs
        AnyTransportSwitchesEnabled    = $Script:AnyTransportSwitchesEnabled
        AppSysLogs                     = $AppSysLogs
        AppSysLogsToXml                = $AppSysLogsToXml
        AutoDLogs                      = $AutoDLogs
        CollectAllLogsBasedOnLogAge    = $CollectAllLogsBasedOnLogAge
        ConversationLogs               = $ConversationLogs
        DAGInformation                 = $DAGInformation
        DailyPerformanceLogs           = $DailyPerformanceLogs
        TransportLogging               = $TransportLogging
        EASLogs                        = $EASLogs
        ECPLogs                        = $ECPLogs
        EventBasedAssistantsLogs       = $EventBasedAssistantsLogs
        EWSLogs                        = $EWSLogs
        ExchangeServerInformation      = $ExchangeServerInformation
        ExMon                          = $ExMon
        ExMonLogmanName                = $ExMonLogmanName
        ExPerfWiz                      = $ExPerfWiz
        ExPerfWizLogmanName            = $ExPerfWizLogmanName
        FilePath                       = $FilePath
        FrontEndConnectivityLogs       = $FrontEndConnectivityLogs
        FrontEndProtocolLogs           = $FrontEndProtocolLogs
        GetVDirs                       = $GetVDirs
        HighAvailabilityLogs           = $HighAvailabilityLogs
        HostExeServerName              = $env:COMPUTERNAME
        HubConnectivityLogs            = $HubConnectivityLogs
        HubProtocolLogs                = $HubProtocolLogs
        IISLogs                        = $IISLogs
        ImapLogs                       = $ImapLogs
        TimeSpan                       = $LogAge
        EndTimeSpan                    = $LogEndAge
        MailboxAssistantsLogs          = $MailboxAssistantsLogs
        MailboxConnectivityLogs        = $MailboxConnectivityLogs
        MailboxDeliveryThrottlingLogs  = $MailboxDeliveryThrottlingLogs
        MailboxProtocolLogs            = $MailboxProtocolLogs
        ManagedAvailabilityLogs        = $ManagedAvailabilityLogs
        MapiLogs                       = $MapiLogs
        MasterServer                   = $Script:MasterServer
        MessageTrackingLogs            = $MessageTrackingLogs
        MitigationService              = $MitigationService
        OABLogs                        = $OABLogs
        OWALogs                        = $OWALogs
        PipelineTracingLogs            = $PipelineTracingLogs
        PopLogs                        = $PopLogs
        PowerShellLogs                 = $PowerShellLogs
        QueueInformation               = $QueueInformation
        RootFilePath                   = $Script:RootFilePath
        RPCLogs                        = $RPCLogs
        SearchLogs                     = $SearchLogs
        SendConnectors                 = $SendConnectors
        ServerInformation              = $ServerInformation
        ServerObjects                  = (Get-ServerObjects -ValidServers $Servers)
        ScriptDebug                    = $ScriptDebug
        StandardFreeSpaceInGBCheckSize = $Script:StandardFreeSpaceInGBCheckSize
        TransportAgentLogs             = $TransportAgentLogs
        TransportConfig                = $TransportConfig
        TransportRoutingTableLogs      = $TransportRoutingTableLogs
        TransportRules                 = $TransportRules
        WindowsSecurityLogs            = $WindowsSecurityLogs
    }

    Write-Verbose "Passed arguments"
    $argumentList | Format-List | Out-String | Write-Verbose
    Write-Verbose "Server Object Results"
    $argumentList.ServerObjects | ForEach-Object {
        $currentServer = $_
        $currentServer | Format-List | Out-String | Write-Verbose
        if ($Script:AnyTransportSwitchesEnabled) {
            $currentServer.TransportInfo.FELoggingInfo | Format-List | Out-String | Write-Verbose
            $currentServer.TransportInfo.HubLoggingInfo | Format-List | Out-String | Write-Verbose
            $currentServer.TransportInfo.MbxLoggingInfo | Format-List | Out-String | Write-Verbose
        }

        Write-Verbose "End Server Object Results for $($currentServer.ServerName)"
    }

    return $argumentList
}
