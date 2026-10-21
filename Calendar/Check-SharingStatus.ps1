# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# This script runs a variety of cmdlets to establish a baseline of the sharing status of a Calendar.
#
# .PARAMETER Identity
#  Owner Mailbox to query, owner of the Mailbox sharing the calendar.
#  Receiver of the shared mailbox, often the Delegate.
#
# .PARAMETER IncludeSensitiveData
#  Includes full-fidelity values in structured finding and error evidence and adds raw evidence to the JSON report. Console output is always full fidelity.
#
# .PARAMETER SkipJsonOutput
#  Skips writing the JSON report. By default, a JSON report is saved to the current directory.
#
# .PARAMETER OwnerCalendarFolderPath
#  Optional owner-mailbox-relative calendar folder path. When omitted, the default calendar is used.
#
# .EXAMPLE
# .\Check-SharingStatus.ps1 -Owner Owner@contoso.com -Receiver Receiver@contoso.com
#
# .EXAMPLE
# .\Check-SharingStatus.ps1 -Owner Owner@contoso.com -Receiver Receiver@contoso.com -OwnerCalendarFolderPath "Calendar\Project Calendar"

# Define the parameters
# cSpell:ignore Dont Sharee Sharees
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Owner,
    [Parameter(Mandatory=$true)]
    [string]$Receiver,
    [Parameter()]
    [switch]$IncludeSensitiveData,
    [Parameter()]
    [switch]$SkipJsonOutput,
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OwnerCalendarFolderPath,
    [Parameter(DontShow)]
    [switch]$SkipMainExecution
)

$BuildVersion = ""

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\CalendarHelpers\Test-CalendarExoConnection.ps1
. $PSScriptRoot\Helpers\SharingPathUtilities.ps1
. $PSScriptRoot\Writers\Write-SharingResults.ps1
. $PSScriptRoot\Helpers\SharingEvidenceUtilities.ps1
. $PSScriptRoot\Helpers\SharingCollectionUtilities.ps1
. $PSScriptRoot\Helpers\SharingFindings.ps1
. $PSScriptRoot\Helpers\SharingPrerequisites.ps1
. $PSScriptRoot\Helpers\SharingLogParsers.ps1
. $PSScriptRoot\Helpers\SharingOwnerDiagnostics.ps1
. $PSScriptRoot\Helpers\SharingReceiverDiagnostics.ps1
. $PSScriptRoot\Helpers\SharingRelationshipChecks.ps1
. $PSScriptRoot\Helpers\SharingDiagnosticLogs.ps1
. $PSScriptRoot\Writers\Write-SharingSummary.ps1

$script:OwnerCalendarFolderPathSpecified = -not [string]::IsNullOrEmpty($OwnerCalendarFolderPath)
$script:OwnerCalendarSubfolderSelected = $false
$script:NormalizedOwnerCalendarFolderPath = if ($script:OwnerCalendarFolderPathSpecified) {
    ConvertTo-NormalizedCalendarFolderPath -FolderPath $OwnerCalendarFolderPath
} else {
    $null
}

if ((-not $SkipMainExecution) -and (Test-ScriptVersion -AutoUpdate)) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command."  -ForegroundColor Yellow
    return
}

Write-Verbose "Script Versions: $BuildVersion"

if ((-not $SkipMainExecution) -and (-not (Test-CalendarExoConnection))) {
    return
}

$script:RunStartedAt = Get-Date
$script:PIIAccess = $true #Assume we have PII access until we find out otherwise
$script:SharingFindings = [System.Collections.Generic.List[object]]::new()
$script:SharingFindingRuleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:ConsoleFindingEvidence = @{}
$script:CollectorStatuses = [ordered]@{}
$script:CollectionErrors = [System.Collections.Generic.List[object]]::new()
$script:EvaluationErrors = [System.Collections.Generic.List[object]]::new()
$script:SanitizedIdentityMap = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:SanitizedIdentitySequence = 0
$script:OwnerInviteData = @()
$script:OwnerInviteLogRaw = $null
$script:ReceiverAcceptLogRaw = $null
$script:SharingDiagnosticLogs = [ordered]@{}
$script:SharingLogScanPerformed = $false
$script:OwnerInviteCheckAvailable = $false
$script:OwnerActiveReceiver = $null
$script:OwnerActiveSharees = @()
$script:ReceiverFolderStatistics = @()
$script:ReceiverCalendarEntries = @()
$script:ReceiverLocalCalendarFolder = $null
$script:ReceiverLocalCalendarFolderIdentity = $null
$script:OwnerActiveSharingAvailable = $false
$script:OwnerCalendarPerms = @()
$script:OwnerCalendarPermsAvailable = $false
$script:OwnerMailboxPerms = @()
$script:OwnerMailboxPermsAvailable = $false
$script:OwnerCalendarStats = @()
$script:OwnerSelectedCalendar = $null
$script:OwnerCalendarFolder = $null
$script:OwnerCalendarFolderIdentity = $null
$script:OwnerCalendarRootName = $null
$script:OwnerCalendarLeafName = $null
$script:OwnerCalendarLeafNameCandidate = $null
$script:RequestedOwnerCalendarLeafName = if ($script:OwnerCalendarFolderPathSpecified) {
    $script:NormalizedOwnerCalendarFolderPath.Split("\")[-1]
} else {
    $null
}
$script:ReceiverAcceptLogEntries = @()
$script:ReceiverSelectedAcceptLogEntries = @()
$script:ReceiverMatchedCalendar = $null
$script:ReceiverCalendarCandidates = @()
$script:CalendarStatisticsComparisonPerformed = $false
$script:CalendarStatisticsComparison = $null
$script:FatalPrerequisiteFailure = $null
$script:LegacyMapiSharing = $false
$script:PublishedSharing = $false
$script:OwnerPublished = $false
$script:OwnerPublishedICalUrl = $null
$script:ReceiverInternetCalendarEntries = @()
$script:ReceiverPublishedCalendarEntry = $null
$script:ReceiverPublishedCalendarFolder = $null
$script:ModernSharingRuleIds = @(
    "SHR121", "SHR122",
    "SHR210", "SHR211", "SHR212", "SHR213", "SHR220",
    "SHR231", "SHR232", "SHR240", "SHR241", "SHR242", "SHR243",
    "SHR300", "SHR301", "SHR310", "SHR311", "SHR312",
    "SHR320", "SHR321", "SHR322", "SHR323",
    "SHR400", "SHR401", "SHR402", "SHR403", "SHR404", "SHR405", "SHR406", "SHR407",
    "SHR410", "SHR411", "SHR412", "SHR413", "SHR432"
)
$script:ModernSharingCollectorNames = @(
    "OwnerInviteLog", "ActiveSharing", "ReceiverAcceptLog", "ReceiverLocalCalendarFolder",
    "ReceiverSharingSyncAssistantLog", "ReceiverSharingLog"
)

# Sharing diagnostic rule IDs use the SHR prefix. The hundreds digit identifies the owning area:
# SHR1xx owner, SHR2xx receiver, SHR3xx relationship, and SHR4xx sync/performance.
$script:SharingRuleCatalog = @(
    [PSCustomObject]@{ RuleId = "SHR100"; Severity = "Error"; Title = "Owner mailbox evidence is unavailable"; Aliases = @("The owner mailbox lookup failed.", "The owner mailbox lookup returned no mailbox."); NextStep = "Verify the owner identity and rerun the mailbox diagnostics with sufficient access." }
    [PSCustomObject]@{ RuleId = "SHR101"; Severity = "Warning"; Title = "Owner PII is redacted"; Aliases = @("Owner PII was redacted, limiting pair-specific checks."); NextStep = "Obtain PII access for the owner mailbox database and rerun the pair diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR110"; Severity = "Warning"; Title = "Owner folder statistics are unavailable"; Aliases = @("The owner calendar-folder checks were unavailable.", "The owner default-calendar checks could not be completed."); NextStep = "Rerun Get-MailboxFolderStatistics with sufficient access and inspect the owner calendar." }
    [PSCustomObject]@{ RuleId = "SHR111"; Severity = "Warning"; Title = "Owner calendar permissions are unavailable"; Aliases = @("The pair-specific permission check was unavailable."); NextStep = "Rerun Get-MailboxFolderPermission and compare permissions with the sharing relationship." }
    [PSCustomObject]@{ RuleId = "SHR112"; Severity = "Warning"; Title = "Owner calendar folder has a duplicate-style numeric suffix"; Aliases = @(); NextStep = "Review the owner calendar folders ending in a one- or two-digit numeric suffix and remove obsolete duplicates if appropriate." }
    [PSCustomObject]@{ RuleId = "SHR113"; Severity = "Error"; Title = "Owner calendar is named Outbox"; Aliases = @(); NextStep = "This is a known issue. Escalate to Microsoft Support to resolve the renamed calendar before further troubleshooting." }
    [PSCustomObject]@{ RuleId = "SHR430"; Severity = "Warning"; Title = "Owner calendar is oversized"; Aliases = @("The owner calendar is larger than 1 GB."); NextStep = "Review folder statistics and item or attachment distribution before remediation." }
    [PSCustomObject]@{ RuleId = "SHR431"; Severity = "Warning"; Title = "Owner calendar has too many items"; Aliases = @("The owner calendar has more than 100,000 visible items."); NextStep = "Review folder statistics and item distribution before remediation." }
    [PSCustomObject]@{ RuleId = "SHR120"; Severity = "Warning"; Title = "Owner calendar folder evidence is unavailable"; Aliases = @("The owner calendar-flag checks were unavailable."); NextStep = "Rerun Get-MailboxCalendarFolder and inspect sharing diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR121"; Severity = "Error"; Title = "Owner calendar is missing SharedOut"; Aliases = @("The owner calendar is missing SharedOut."); NextStep = "Run SharingPolicyAssistant or calendar-sharing validator diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR122"; Severity = "Error"; Title = "Owner calendar is missing ExchangeShareFolder"; Aliases = @("The owner calendar is missing ExchangeShareFolder."); NextStep = "Run SharingPolicyAssistant or calendar-sharing validator diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR123"; Severity = "Error"; Title = "Selected owner calendar belongs to another mailbox"; Aliases = @(); NextStep = "If the actual calendar owner is the supplied Receiver, the Owner and Receiver appear reversed; rerun with them swapped. Otherwise, correct the Owner or owner calendar folder path." }
    [PSCustomObject]@{ RuleId = "SHR130"; Severity = "Warning"; Title = "Owner mailbox permissions are unavailable"; Aliases = @("The owner mailbox-permission check was unavailable."); NextStep = "Rerun Get-MailboxPermission with sufficient access." }
    [PSCustomObject]@{ RuleId = "SHR200"; Severity = "Error"; Title = "Receiver mailbox evidence is unavailable"; Aliases = @("The receiver mailbox lookup failed.", "The receiver mailbox lookup returned no mailbox."); NextStep = "Verify the receiver identity and rerun the mailbox diagnostics with sufficient access." }
    [PSCustomObject]@{ RuleId = "SHR201"; Severity = "Warning"; Title = "Receiver PII is redacted"; Aliases = @("Receiver PII was redacted, limiting folder matching."); NextStep = "Obtain PII access for the receiver mailbox database and rerun the pair diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR210"; Severity = "Warning"; Title = "Receiver folder statistics are unavailable"; Aliases = @("The receiver local-folder checks were unavailable."); NextStep = "Rerun Get-MailboxFolderStatistics and compare calendar entries and logs." }
    [PSCustomObject]@{ RuleId = "SHR211"; Severity = "Warning"; Title = "Receiver has duplicate owner calendar folders"; Aliases = @("Multiple local folders may represent the owner's shared calendar."); NextStep = "Compare folder identifiers, calendar entries, and invite or accept logs." }
    [PSCustomObject]@{ RuleId = "SHR212"; Severity = "Warning"; Title = "Receiver has multiple generically named calendars"; Aliases = @("The receiver has multiple calendars whose names begin with Calendar."); NextStep = "Use folder identifiers and calendar entries to distinguish the shared folder." }
    [PSCustomObject]@{ RuleId = "SHR213"; Severity = "Error"; Title = "Receiver local owner calendar is missing"; Aliases = @("A local folder for the expected owner was not found."); NextStep = "Inspect invite or accept logs and calendar entries for the pair." }
    [PSCustomObject]@{ RuleId = "SHR214"; Severity = "Warning"; Title = "Receiver calendar folder has a duplicate-style numeric suffix"; Aliases = @(); NextStep = "Review the receiver calendar folders ending in a one- or two-digit numeric suffix and remove obsolete duplicates if appropriate." }
    [PSCustomObject]@{ RuleId = "SHR215"; Severity = "Error"; Title = "Receiver calendar is named Outbox"; Aliases = @(); NextStep = "This is a known issue. Escalate to Microsoft Support to resolve the renamed calendar before further troubleshooting." }
    [PSCustomObject]@{ RuleId = "SHR220"; Severity = "Warning"; Title = "Receiver accept-log evidence is unavailable"; Aliases = @("The receiver accept-log check was unavailable.", "The receiver accept-log check failed.", "The receiver accept-log check had no data.", "No relevant receiver accept-log entries were available.", "The receiver accept logs could not be parsed.", "Accept-log timestamps could not be parsed."); NextStep = "Collect and inspect AcceptCalendarSharingInvite logs for the pair." }
    [PSCustomObject]@{ RuleId = "SHR230"; Severity = "Warning"; Title = "Calendar-entry evidence is unavailable"; Aliases = @("The receiver calendar-entry check was unavailable.", "Get-CalendarEntries is unavailable."); NextStep = "Rerun Get-CalendarEntries in a session with sufficient access." }
    [PSCustomObject]@{ RuleId = "SHR231"; Severity = "Error"; Title = "Pair-specific new-model calendar entry is missing"; Aliases = @("The pair-specific new-model calendar entry is missing."); NextStep = "Inspect invite or accept logs and sharing assistant diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR232"; Severity = "Error"; Title = "Pair-specific calendar entry is orphaned"; Aliases = @("The pair-specific new-model calendar entry is orphaned."); NextStep = "Run SharingPolicyAssistant or calendar-sharing validator diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR233"; Severity = "Warning"; Title = "Pair-specific old-model calendar entry exists"; Aliases = @("A relevant old-model calendar entry exists for the expected owner."); NextStep = "Inspect the pair before considering configuration changes." }
    [PSCustomObject]@{ RuleId = "SHR240"; Severity = "Warning"; Title = "Receiver local calendar-folder evidence is unavailable"; Aliases = @("The matched receiver calendar folder could not be queried.", "The receiver local-folder detail check could not be completed."); NextStep = "Verify the folder identity and rerun the pair diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR241"; Severity = "Error"; Title = "Receiver local calendar is missing SharedIn"; Aliases = @("The receiver local folder is missing SharedIn."); NextStep = "Run SharingPolicyAssistant or calendar-sharing validator diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR242"; Severity = "Error"; Title = "Receiver local calendar is missing ExchangeShareFolder"; Aliases = @("The receiver local folder is missing ExchangeShareFolder."); NextStep = "Run SharingPolicyAssistant or calendar-sharing validator diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR243"; Severity = "Error"; Title = "Receiver folder owner does not match expected owner"; Aliases = @("CalendarSharingOwnerSmtpAddress does not match the expected owner."); NextStep = "Compare calendar entries and invite or accept logs, then run the validator." }
    [PSCustomObject]@{ RuleId = "SHR300"; Severity = "Warning"; Title = "Owner invite-log evidence is unavailable"; Aliases = @("The owner invite-log check was unavailable.", "The owner invite-log check had no data."); NextStep = "Collect CalendarSharingInvite logs and inspect the expected pair." }
    [PSCustomObject]@{ RuleId = "SHR301"; Severity = "Error"; Title = "Pair-specific sharing invite is missing"; Aliases = @("No pair-specific sharing invite was found for the expected receiver."); NextStep = "Inspect owner invite and receiver accept logs for the pair." }
    [PSCustomObject]@{ RuleId = "SHR310"; Severity = "Warning"; Title = "Active-sharing evidence is unavailable"; Aliases = @("The active-sharing relationship check was unavailable.", "The active-sharing relationship check returned no data.", "Get-CalendarActiveSharingInformation is unavailable."); NextStep = "Rerun Get-CalendarActiveSharingInformation in a supported session." }
    [PSCustomObject]@{ RuleId = "SHR311"; Severity = "Error"; Title = "Expected receiver is absent from active sharing"; Aliases = @("The expected receiver is absent from the owner's active-sharing relationships."); NextStep = "Inspect invite or accept logs and sharing assistant diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR312"; Severity = "Warning"; Title = "Expected receiver has non-default ActiveShareeFlags"; Aliases = @("The expected receiver has non-None ActiveShareeFlags."); NextStep = "Inspect SharingPolicyAssistant and calendar-sharing validator diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR320"; Severity = "Error"; Title = "Active relationship lacks owner permission"; Aliases = @("The expected active relationship has no matching owner calendar permission."); NextStep = "Compare permissions, active sharing, and invite or accept logs." }
    [PSCustomObject]@{ RuleId = "SHR321"; Severity = "Error"; Title = "Owner permission lacks active relationship"; Aliases = @("The owner calendar permission exists but the expected active relationship is absent."); NextStep = "Compare permissions, active sharing, and invite or accept logs." }
    [PSCustomObject]@{ RuleId = "SHR322"; Severity = "Warning"; Title = "Owner and receiver permission flags differ"; Aliases = @("Owner and receiver sharing permission flags differ."); NextStep = "Compare the pair configuration with sharing diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR323"; Severity = "Warning"; Title = "Active-sharing and receiver permission flags differ"; Aliases = @("Active-sharing and receiver-folder permission flags differ."); NextStep = "Compare the pair configuration with sharing diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR324"; Severity = "Warning"; Title = "Internal relationship uses legacy MAPI calendar sharing"; Aliases = @(); NextStep = "Upgrade to Modern Calendar Sharing by following https://support.microsoft.com/en-us/outlook/calendar-sharing-in-microsoft-365" }
    [PSCustomObject]@{ RuleId = "SHR325"; Severity = "Error"; Title = "Receiver delegate lacks explicit calendar delegate permissions"; Aliases = @(); NextStep = "Grant the receiver an individual permission entry on the selected owner calendar with AccessRights Editor and SharingPermissionFlags Delegate. Group, Default, and mailbox FullAccess permissions do not satisfy calendar delegation." }
    [PSCustomObject]@{ RuleId = "SHR400"; Severity = "Warning"; Title = "Periodic synchronization is stale"; Aliases = @("Periodic synchronization is stale and the assistant may not be running."); NextStep = "Inspect SharingSyncAssistant logs for the receiver." }
    [PSCustomObject]@{ RuleId = "SHR401"; Severity = "Warning"; Title = "Periodic synchronization timestamps are incomplete"; Aliases = @("Periodic synchronization timestamps are incomplete."); NextStep = "Inspect SharingSyncAssistant logs and rerun folder diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR402"; Severity = "Error"; Title = "Recent periodic synchronization attempt failed"; Aliases = @("A recent periodic synchronization attempt failed."); NextStep = "Inspect SharingSyncAssistant logs." }
    [PSCustomObject]@{ RuleId = "SHR403"; Severity = "Error"; Title = "Receiver local calendar has never successfully synchronized"; Aliases = @(); NextStep = "Inspect SharingSyncAssistant and calendar-sharing validator diagnostics for the selected receiver folder." }
    [PSCustomObject]@{ RuleId = "SHR404"; Severity = "Warning"; Title = "Receiver SharingSyncAssistant log has no entries in the last 24 hours"; Aliases = @(); NextStep = "Inspect the SharingSyncAssistant log and confirm that the receiver mailbox is being processed." }
    [PSCustomObject]@{ RuleId = "SHR405"; Severity = "Error"; Title = "Receiver SharingSyncAssistant log has no entries in the last 7 days"; Aliases = @(); NextStep = "The sharing sync assistant does not appear to be processing the receiver mailbox. Inspect the SharingSyncAssistant log and escalate to Microsoft Support if the condition persists." }
    [PSCustomObject]@{ RuleId = "SHR406"; Severity = "Warning"; Title = "Receiver Sharing log has no entries in the last 24 hours"; Aliases = @(); NextStep = "Inspect the Sharing log and confirm that sharing activity is being recorded for the receiver mailbox." }
    [PSCustomObject]@{ RuleId = "SHR407"; Severity = "Error"; Title = "Receiver Sharing log has no entries in the last 7 days"; Aliases = @(); NextStep = "No sharing activity has been recorded for the receiver mailbox. Inspect the Sharing log and escalate to Microsoft Support if the condition persists." }
    [PSCustomObject]@{ RuleId = "SHR408"; Severity = "Error"; Title = "Sharing logs report a named property quota exception"; Aliases = @(); NextStep = "MapiExceptionNamedPropsQuotaExceeded means the mailbox exhausted its named property quota, which can block sharing synchronization. Escalate to Microsoft Support." }
    [PSCustomObject]@{ RuleId = "SHR409"; Severity = "Warning"; Title = "Sharing logs contain exceptions"; Aliases = @(); NextStep = "Review the exceptions in the sharing logs (rawData in the JSON report) and correlate them with the synchronization state." }
    [PSCustomObject]@{ RuleId = "SHR410"; Severity = "Warning"; Title = "Synchronization start date cannot be parsed"; Aliases = @("SharedCalendarSyncStartDate could not be interpreted as a date."); NextStep = "Inspect raw folder data and SharingSyncAssistant logs." }
    [PSCustomObject]@{ RuleId = "SHR411"; Severity = "Warning"; Title = "Synchronization start is later than folder creation"; Aliases = @("SharedCalendarSyncStartDate is later than the local folder CreationTime."); NextStep = "Inspect invite, accept, and synchronization logs." }
    [PSCustomObject]@{ RuleId = "SHR412"; Severity = "Information"; Title = "Synchronization start is very recent"; Aliases = @("SharedCalendarSyncStartDate is very recent and may reflect backfill or folder recreation context."); NextStep = "Correlate invite, accept, and synchronization logs." }
    [PSCustomObject]@{ RuleId = "SHR413"; Severity = "Warning"; Title = "Synchronization start date is unavailable"; Aliases = @("SharedCalendarSyncStartDate is null."); NextStep = "Inspect SharingSyncAssistant and validator diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR420"; Severity = "Warning"; Title = "InternetCalendar evidence is unavailable"; Aliases = @("The published-calendar log check was unavailable."); NextStep = "Collect InternetCalendar logs when published-calendar behavior is in scope." }
    [PSCustomObject]@{ RuleId = "SHR421"; Severity = "Warning"; Title = "Receiver published-calendar subscription is missing"; Aliases = @(); NextStep = "Subscribe the receiver to the owner's PublishedICalUrl and verify that the InternetCalendar entry is created." }
    [PSCustomObject]@{ RuleId = "SHR422"; Severity = "Warning"; Title = "Receiver published-calendar local folder is missing"; Aliases = @(); NextStep = "Remove and re-add the published calendar subscription, then verify that its local calendar folder is created." }
    [PSCustomObject]@{ RuleId = "SHR423"; Severity = "Warning"; Title = "Owner published-calendar URL is unavailable"; Aliases = @(); NextStep = "Verify the owner's PublishEnabled, PublishedCalendarUrl, and PublishedICalUrl values." }
    [PSCustomObject]@{ RuleId = "SHR432"; Severity = "Warning"; Title = "Receiver local calendar has significantly more visible items than owner folder"; Aliases = @(); NextStep = "Review the selected folder mapping, synchronization state, and item retention differences before remediation." }
)

$collectorNames = @(
    "OwnerMailbox", "ReceiverMailbox", "OwnerFolderStatistics", "ReceiverFolderStatistics",
    "OwnerCalendarPermissions", "OwnerMailboxPermissions", "OwnerInviteLog", "OwnerCalendarFolder",
    "ActiveSharing", "ReceiverAcceptLog", "CalendarEntries", "ReceiverLocalCalendarFolder",
    "InternetCalendar", "ReceiverSharingSyncAssistantLog", "ReceiverSharingLog"
)
foreach ($collectorName in $collectorNames) {
    $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{
        status = "NotRun"
        error  = $null
    }
}

function Invoke-SharingDiagnostics {
    if ($null -ne $script:FatalPrerequisiteFailure) {
        Write-SharingSummary -Owner $Owner -Receiver $Receiver
        return
    }
    if (-not (Resolve-SharingMailboxPrerequisites)) {
        Write-SharingSummary -Owner $Owner -Receiver $Receiver
        return
    }
    if (-not (Resolve-OwnerCalendarPrerequisite)) {
        Write-SharingSummary -Owner $Owner -Receiver $Receiver
        return
    }

    Invoke-SharingEvaluation -Name "Owner diagnostics" -Action {
        GetOwnerInformation -Owner $Owner
    }
    if ($null -ne $script:FatalPrerequisiteFailure) {
        Write-SharingSummary -Owner $Owner -Receiver $Receiver
        return
    }
    if ($script:CollectorStatuses["OwnerInviteLog"].status -eq "NotRun") {
        Invoke-SharingEvaluation -Name "Owner invite-log diagnostics" -Action {
            ProcessCalendarSharingInviteLogs -Identity $Owner
        }
    }

    Invoke-SharingEvaluation -Name "Receiver diagnostics" -Action {
        GetReceiverInformation -Receiver $Receiver
    }
    if ($null -ne $script:FatalPrerequisiteFailure) {
        Write-SharingSummary -Owner $Owner -Receiver $Receiver
        return
    }
    if ($script:CollectorStatuses["ReceiverAcceptLog"].status -eq "NotRun") {
        Invoke-SharingEvaluation -Name "Receiver accept-log diagnostics" -Action {
            ProcessCalendarSharingAcceptLogs -Identity $Receiver
        }
    }
    if ($script:OwnerPublished -and
        ($script:CollectorStatuses["InternetCalendar"].status -eq "NotRun")) {
        Invoke-SharingEvaluation -Name "InternetCalendar diagnostics" -Action {
            ProcessInternetCalendarLogs -Identity $Receiver
        }
    }
    Invoke-SharingEvaluation -Name "Receiver delegate permissions" -RuleIds @("SHR325") -Action {
        Test-ReceiverDelegatePermissions
    }
    if ($script:ModernSharing) {
        Invoke-SharingEvaluation -Name "Receiver sharing log freshness" -RuleIds @("SHR404", "SHR405", "SHR406", "SHR407") -Action {
            Test-ReceiverSharingLogFreshness
        }
    }
    Invoke-SharingEvaluation -Name "Sharing log collection" -Action {
        Get-SharingDiagnosticLogs
    }
    Invoke-SharingEvaluation -Name "Sharing log exception scan" -RuleIds @("SHR408", "SHR409") -Action {
        Test-SharingLogExceptions
    }

    Write-SharingSummary -Owner $Owner -Receiver $Receiver
}

if ($SkipMainExecution) {
    return
}

# Main
$script:ModernSharing = $false
$script:LegacyMapiSharing = $false
$script:PublishedSharing = $false
$script:SharingType = $null
$script:OwnerMB = $null
$script:ReceiverMB = $null
Invoke-SharingDiagnostics

if (-not $SkipJsonOutput) {
    try {
        $ownerFileStem = ConvertTo-CalendarDiagnosticFileNameStem -Value $Owner
        $receiverFileStem = ConvertTo-CalendarDiagnosticFileNameStem -Value $Receiver
        $jsonFilename = "Sharing-Status-For_$ownerFileStem`_And_$receiverFileStem`_$($script:RunStartedAt.ToString('yyyy-MM-dd_HH-mm-ss')).json"
        Write-SharingJsonReport -Path $jsonFilename
        Write-Host -ForegroundColor Cyan "`r`nSharing JSON Output saved as [$jsonFilename] in the current directory."
    } catch {
        $errorInfo = ConvertTo-CalendarDiagnosticErrorInfo -ErrorRecord $_
        Write-Warning "Unable to write Sharing JSON output: $($errorInfo.message)"
    }
}
