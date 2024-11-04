# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Enter-YesNoLoopAction.ps1
function Test-NoSwitchesProvided {
    if ($EWSLogs -or
        $IISLogs -or
        $DailyPerformanceLogs -or
        $ManagedAvailabilityLogs -or
        $ConversationLogs -or
        $EventBasedAssistantsLogs -or
        $ExPerfWiz -or
        $RPCLogs -or
        $EASLogs -or
        $ECPLogs -or
        $AutoDLogs -or
        $SearchLogs -or
        $OWALogs -or
        $ADDriverLogs -or
        $HighAvailabilityLogs -or
        $MapiLogs -or
        $Script:AnyTransportSwitchesEnabled -or
        $DAGInformation -or
        $GetVDirs -or
        $OrganizationConfig -or
        $ExMon -or
        $ServerInformation -or
        $PopLogs -or
        $ImapLogs -or
        $OABLogs -or
        $PowerShellLogs -or
        $WindowsSecurityLogs -or
        $MailboxAssistantsLogs -or
        $ExchangeServerInformation -or
        $MitigationService
    ) {
        return
    } else {
        Write-Host "`r`nWARNING: Doesn't look like any parameters were provided, are you sure you are running the correct command? This is ONLY going to collect the Application and System Logs." -ForegroundColor "Yellow"
        Enter-YesNoLoopAction -Question "Would you like to continue?" -YesAction { Write-Host "Okay moving on..." } -NoAction { exit }
    }
}
