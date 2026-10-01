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
#  Includes full-fidelity values in structured finding and error evidence. Console output is always full fidelity.
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
# cSpell:ignore Dont
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Owner,
    [Parameter(Mandatory=$true)]
    [string]$Receiver,
    [Parameter()]
    [switch]$IncludeSensitiveData,
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OwnerCalendarFolderPath,
    [Parameter(DontShow)]
    [switch]$SkipMainExecution
)

$BuildVersion = ""

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

function ConvertTo-NormalizedCalendarFolderPath {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FolderPath
    )

    $normalizedFolderPath = $FolderPath.Trim()
    if ([string]::IsNullOrWhiteSpace($normalizedFolderPath)) {
        throw "OwnerCalendarFolderPath cannot be empty or whitespace."
    }
    if ($normalizedFolderPath -match "^[^\\/]+:\s*[\\/]") {
        throw "OwnerCalendarFolderPath must contain only the owner-relative path. Do not provide a mailbox identity prefix such as owner@contoso.com:\."
    }

    $normalizedFolderPath = $normalizedFolderPath.Replace("/", "\").TrimStart("\")
    $normalizedFolderPath = $normalizedFolderPath -replace "\\+", "\"
    if ([string]::IsNullOrWhiteSpace($normalizedFolderPath)) {
        throw "OwnerCalendarFolderPath must identify a folder in the owner mailbox."
    }

    return "\$normalizedFolderPath"
}

function Get-CanonicalMailboxFolderIdentity {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Mailbox,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CalendarRootName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FolderPath
    )

    $normalizedFolderPath = ConvertTo-NormalizedCalendarFolderPath -FolderPath $FolderPath
    $normalizedCalendarRootPath = ConvertTo-NormalizedCalendarFolderPath -FolderPath $CalendarRootName
    if (($normalizedFolderPath -ne $normalizedCalendarRootPath) -and
        (-not $normalizedFolderPath.StartsWith(
            "$normalizedCalendarRootPath\",
            [System.StringComparison]::OrdinalIgnoreCase))) {
        $normalizedFolderPath = "$normalizedCalendarRootPath$normalizedFolderPath"
    }

    return "${Mailbox}:$normalizedFolderPath"
}

function ConvertTo-NormalizedFolderFlags {
    param(
        [AllowNull()]
        [object[]]$Flags
    )

    return @(
        foreach ($flag in $Flags) {
            if ($null -eq $flag) {
                continue
            }

            foreach ($token in @($flag.ToString() -split ",")) {
                $normalizedFlag = $token.Trim()
                if (-not [string]::IsNullOrWhiteSpace($normalizedFlag)) {
                    $normalizedFlag
                }
            }
        }
    )
}

function Get-DuplicateStyleCalendarFolders {
    param(
        [AllowNull()]
        [object[]]$FolderStatistics
    )

    return @($FolderStatistics | Where-Object -FilterScript {
            $folderName = if (-not [string]::IsNullOrWhiteSpace([string]$_.Name)) {
                [string]$_.Name
            } else {
                [string]$_.FolderPath
            }
            $folderName -match "\(\d{1,2}\)\s*$"
        })
}

function Compare-CalendarFolderStatistics {
    param(
        [AllowNull()]
        [object]$OwnerFolderStatistics,

        [AllowNull()]
        [object]$ReceiverFolderStatistics
    )

    $script:CalendarStatisticsComparisonPerformed = $true
    Write-Host -ForegroundColor Cyan "`r`rSelected Owner and Receiver Calendar Statistics Comparison:"

    if ($null -eq $OwnerFolderStatistics) {
        Write-Host -ForegroundColor Yellow "Owner calendar statistics are unavailable, so the comparison cannot be evaluated."
        Add-SharingFinding -RuleId "SHR432" -Status NotEvaluated -Evidence @{
            reason = "Selected owner calendar statistics are unavailable."
        }
        return
    }
    if ($null -eq $ReceiverFolderStatistics) {
        $receiverStatisticsAvailable = (
            $script:CollectorStatuses["ReceiverFolderStatistics"].status -eq "Success")
        $status = if ($receiverStatisticsAvailable) {
            "NotApplicable"
        } else {
            "NotEvaluated"
        }
        $reason = if ($receiverStatisticsAvailable) {
            "A unique receiver calendar folder was not identified."
        } else {
            "Receiver calendar folder statistics are unavailable."
        }
        Write-Host -ForegroundColor Yellow "$reason The comparison cannot be evaluated."
        Add-SharingFinding -RuleId "SHR432" -Status $status -Evidence @{
            reason = $reason
        }
        return
    }

    $ownerCount = [int64]0
    $receiverCount = [int64]0
    $ownerCountAvailable = [int64]::TryParse(
        [string]$OwnerFolderStatistics.VisibleItemsInFolder,
        [ref]$ownerCount)
    $receiverCountAvailable = [int64]::TryParse(
        [string]$ReceiverFolderStatistics.VisibleItemsInFolder,
        [ref]$receiverCount)

    $countDelta = if ($ownerCountAvailable -and $receiverCountAvailable) {
        $receiverCount - $ownerCount
    } else {
        $null
    }
    $countRatio = if ($ownerCountAvailable -and
        $receiverCountAvailable -and
        ($ownerCount -gt 0)) {
        [math]::Round(($receiverCount / $ownerCount), 2)
    } else {
        $null
    }

    $script:CalendarStatisticsComparison = [PSCustomObject]@{
        ownerCount    = $(if ($ownerCountAvailable) { $ownerCount } else { $null })
        receiverCount = $(if ($receiverCountAvailable) { $receiverCount } else { $null })
        countDelta    = $countDelta
        countRatio    = $countRatio
    }

    [PSCustomObject]@{
        Metric             = "VisibleItemsInFolder"
        Owner              = $(if ($ownerCountAvailable) { $ownerCount } else { "Unavailable" })
        Receiver           = $(if ($receiverCountAvailable) { $receiverCount } else { "Unavailable" })
        ReceiverMinusOwner = $(if ($null -ne $countDelta) { $countDelta } else { "Unavailable" })
        ReceiverOwnerRatio = $(if ($null -ne $countRatio) { $countRatio } else { "Unavailable" })
    } | Format-Table -AutoSize

    if (-not ($ownerCountAvailable -and $receiverCountAvailable)) {
        Add-SharingFinding -RuleId "SHR432" -Status NotEvaluated -Evidence @{
            reason = "Owner or receiver visible item count could not be converted to an integer."
        }
    } else {
        $countMultiplierMet = if ($ownerCount -eq 0) {
            $receiverCount -gt 0
        } else {
            $receiverCount -ge (2 * $ownerCount)
        }
        if (($receiverCount -gt $ownerCount) -and
            $countMultiplierMet -and
            ($countDelta -ge 100)) {
            Add-SharingFinding -RuleId "SHR432" -Status Detected -Evidence @{
                ownerCount          = $ownerCount
                receiverCount       = $receiverCount
                delta               = $countDelta
                ratio               = $countRatio
                multiplierThreshold = 2
                absoluteThreshold   = 100
            }
        }
    }
}

$script:OwnerCalendarFolderPathSpecified = -not [string]::IsNullOrEmpty($OwnerCalendarFolderPath)
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
$script:OwnerInviteCheckAvailable = $false
$script:OwnerActiveReceiver = $null
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
    "SHR400", "SHR401", "SHR402", "SHR403",
    "SHR410", "SHR411", "SHR412", "SHR413", "SHR432"
)
$script:ModernSharingCollectorNames = @(
    "OwnerInviteLog", "ActiveSharing", "ReceiverAcceptLog", "ReceiverLocalCalendarFolder"
)

# Sharing diagnostic rule IDs use the SHR prefix. The hundreds digit identifies the owning area:
# SHR1xx owner, SHR2xx receiver, SHR3xx relationship, and SHR4xx sync/performance.
$script:SharingRuleCatalog = @(
    [PSCustomObject]@{ RuleId = "SHR100"; Severity = "Error"; Title = "Owner mailbox evidence is unavailable"; Aliases = @("The owner mailbox lookup failed.", "The owner mailbox lookup returned no mailbox."); NextStep = "Verify the owner identity and rerun the mailbox diagnostics with sufficient access." }
    [PSCustomObject]@{ RuleId = "SHR101"; Severity = "Warning"; Title = "Owner PII is redacted"; Aliases = @("Owner PII was redacted, limiting pair-specific checks."); NextStep = "Obtain PII access for the owner mailbox database and rerun the pair diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR110"; Severity = "Warning"; Title = "Owner folder statistics are unavailable"; Aliases = @("The owner calendar-folder checks were unavailable.", "The owner default-calendar checks could not be completed."); NextStep = "Rerun Get-MailboxFolderStatistics with sufficient access and inspect the owner calendar." }
    [PSCustomObject]@{ RuleId = "SHR111"; Severity = "Warning"; Title = "Owner calendar permissions are unavailable"; Aliases = @("The pair-specific permission check was unavailable."); NextStep = "Rerun Get-MailboxFolderPermission and compare permissions with the sharing relationship." }
    [PSCustomObject]@{ RuleId = "SHR112"; Severity = "Warning"; Title = "Owner calendar folder has a duplicate-style numeric suffix"; Aliases = @(); NextStep = "Review the owner calendar folders ending in a one- or two-digit numeric suffix and remove obsolete duplicates if appropriate." }
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
    [PSCustomObject]@{ RuleId = "SHR400"; Severity = "Warning"; Title = "Periodic synchronization is stale"; Aliases = @("Periodic synchronization is stale and the assistant may not be running."); NextStep = "Inspect SharingSyncAssistant logs for the receiver." }
    [PSCustomObject]@{ RuleId = "SHR401"; Severity = "Warning"; Title = "Periodic synchronization timestamps are incomplete"; Aliases = @("Periodic synchronization timestamps are incomplete."); NextStep = "Inspect SharingSyncAssistant logs and rerun folder diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR402"; Severity = "Error"; Title = "Recent periodic synchronization attempt failed"; Aliases = @("A recent periodic synchronization attempt failed."); NextStep = "Inspect SharingSyncAssistant logs." }
    [PSCustomObject]@{ RuleId = "SHR403"; Severity = "Error"; Title = "Receiver local calendar appears never synchronized"; Aliases = @(); NextStep = "Inspect SharingSyncAssistant and calendar-sharing validator diagnostics for the selected receiver folder." }
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
    "InternetCalendar"
)
foreach ($collectorName in $collectorNames) {
    $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{
        status = "NotRun"
        error  = $null
    }
}

function ConvertTo-SharingErrorInfo {
    param(
        [AllowNull()]
        [object]$ErrorRecord
    )

    $message = [string]$ErrorRecord
    $exceptionType = $null
    if ($null -ne $ErrorRecord) {
        try {
            if ($null -ne $ErrorRecord.Exception) {
                $message = [string]$ErrorRecord.Exception.Message
                $exceptionType = $ErrorRecord.Exception.GetType().FullName
            }
        } catch {
            $message = [string]$ErrorRecord
        }
    }
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = "Unknown error."
    }
    $message = ($message -replace '[\r\n\t]+', ' ').Trim()
    if ($message.Length -gt 1024) {
        $message = $message.Substring(0, 1024)
    }
    if (-not $IncludeSensitiveData) {
        $message = "Error details omitted in sanitized mode."
    }

    return [PSCustomObject]@{
        message       = $message
        exceptionType = $exceptionType
    }
}

function Invoke-SharingCollector {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ScriptBlock]$Action,

        [switch]$AllowNull
    )

    try {
        $result = & $Action
        if (($null -eq $result) -and (-not $AllowNull)) {
            throw "$Name returned no data."
        }
        $script:CollectorStatuses[$Name] = [PSCustomObject]@{ status = "Success"; error = $null }
        return $result
    } catch {
        $errorInfo = ConvertTo-SharingErrorInfo -ErrorRecord $_
        $script:CollectorStatuses[$Name] = [PSCustomObject]@{ status = "Failed"; error = $errorInfo }
        $script:CollectionErrors.Add([PSCustomObject]@{
                collector = $Name
                error     = $errorInfo
            })
        throw
    }
}

function Invoke-SharingEvaluation {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ScriptBlock]$Action,

        [Parameter()]
        [ValidatePattern("^SHR\d{3}$")]
        [string[]]$RuleIds
    )

    try {
        & $Action
    } catch {
        $errorInfo = ConvertTo-SharingErrorInfo -ErrorRecord $_
        $script:EvaluationErrors.Add([PSCustomObject]@{
                evaluation = $Name
                error      = $errorInfo
            })
        foreach ($ruleId in $RuleIds) {
            Add-SharingFinding -RuleId $ruleId -Status NotEvaluated -Evidence @{
                reason = "$Name evaluation failed."
            }
        }
        Write-Warning "$Name evaluation failed: $($_.Exception.Message) Other safe evaluations will continue."
    }
}

function Get-SanitizedSharingIdentity {
    param(
        [AllowNull()]
        [object]$Identity
    )

    $identityText = [string]$Identity
    if ($IncludeSensitiveData) {
        return $identityText
    }
    if (Test-SmtpAddressEqual -First $identityText -Second $Owner) {
        return "Owner"
    }
    if (Test-SmtpAddressEqual -First $identityText -Second $Receiver) {
        return "Receiver"
    }

    $identityKey = $identityText.Trim().ToLowerInvariant()
    if ($script:SanitizedIdentityMap.ContainsKey($identityKey)) {
        return $script:SanitizedIdentityMap[$identityKey]
    }
    $script:SanitizedIdentitySequence++
    $placeholder = "Identity-$($script:SanitizedIdentitySequence)"
    $script:SanitizedIdentityMap[$identityKey] = $placeholder
    return $placeholder
}

function ConvertTo-SharingEvidence {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern("^SHR\d{3}$")]
        [string]$RuleId,

        [AllowNull()]
        [object]$Evidence
    )

    if ($null -eq $Evidence) {
        return @{}
    }
    if ($Evidence -is [System.Collections.IDictionary] -or $Evidence -is [PSCustomObject]) {
        if ($IncludeSensitiveData) {
            return $Evidence
        }

        $sanitizedEvidence = [ordered]@{}
        $evidenceProperties = if ($Evidence -is [System.Collections.IDictionary]) {
            @($Evidence.Keys | ForEach-Object {
                    [PSCustomObject]@{ Name = [string]$_; Value = $Evidence[$_] }
                })
        } else {
            @($Evidence.PSObject.Properties | ForEach-Object {
                    [PSCustomObject]@{ Name = $_.Name; Value = $_.Value }
                })
        }
        foreach ($property in $evidenceProperties) {
            if ($property.Name -match "(?i)publishingUrl|url") {
                $sanitizedEvidence[$property.Name] = "UrlOmitted"
            } elseif ($property.Name -match "(?i)folderName|folderPath") {
                $sanitizedEvidence[$property.Name] = "Folder"
            } elseif ($property.Name -match "(?i)^(owner|receiver)(Count|Bytes)$") {
                $sanitizedEvidence[$property.Name] = $property.Value
            } elseif ($property.Name -match "(?i)^actualOwner$") {
                $sanitizedEvidence[$property.Name] = Get-SanitizedSharingIdentity -Identity $property.Value
            } elseif ($property.Name -match "(?i)owner") {
                $sanitizedEvidence[$property.Name] = "Owner"
            } elseif ($property.Name -match "(?i)receiver") {
                $sanitizedEvidence[$property.Name] = "Receiver"
            } elseif ($property.Name -match "(?i)identity|email|smtp|displayName") {
                $sanitizedEvidence[$property.Name] = Get-SanitizedSharingIdentity -Identity $property.Value
            } elseif ($property.Value -is [string]) {
                $sanitizedEvidence[$property.Name] = if ($property.Name -in @("reason", "source", "mailboxRole", "fieldName")) {
                    $boundedValue = $property.Value -replace '[\r\n\t]+', ' '
                    if ($boundedValue.Length -gt 256) {
                        $boundedValue.Substring(0, 256)
                    } else {
                        $boundedValue
                    }
                } else {
                    "ValueOmitted"
                }
            } else {
                $sanitizedEvidence[$property.Name] = $property.Value
            }
        }
        return $sanitizedEvidence
    }

    $evidenceText = [string]$Evidence
    $values = @([regex]::Matches($evidenceText, '\[(?<Value>[^\]]*)\]') | ForEach-Object {
            $_.Groups["Value"].Value
        })
    $ownerValue = if ($IncludeSensitiveData) { [string]$Owner } else { "Owner" }
    $receiverValue = if ($IncludeSensitiveData) { [string]$Receiver } else { "Receiver" }

    switch ($RuleId) {
        "SHR100" { return @{ owner = $ownerValue; source = "Get-Mailbox" } }
        "SHR101" { return @{ owner = $ownerValue; piiAvailable = $false } }
        "SHR110" { return @{ owner = $ownerValue; source = "Get-MailboxFolderStatistics" } }
        "SHR111" { return @{ owner = $ownerValue; source = "Get-MailboxFolderPermission" } }
        "SHR120" { return @{ owner = $ownerValue; source = "Get-MailboxCalendarFolder" } }
        "SHR121" { return @{ owner = $ownerValue; extendedFolderFlags = @($values[0] -split ', ' | Where-Object { $_ }) } }
        "SHR122" { return @{ owner = $ownerValue; extendedFolderFlags = @($values[0] -split ', ' | Where-Object { $_ }) } }
        "SHR123" {
            return @{
                expectedOwner  = $ownerValue
                actualOwner    = $(if ($IncludeSensitiveData -and $values.Count -gt 1) {
                        Get-SanitizedSharingIdentity -Identity $values[1]
                    } else {
                        "Identity-1"
                    })
                inputsReversed = $(if ($values.Count -gt 2) { [bool]::Parse($values[2]) } else { $false })
            }
        }
        "SHR130" { return @{ owner = $ownerValue; source = "Get-MailboxPermission" } }
        "SHR200" { return @{ receiver = $receiverValue; source = "Get-Mailbox" } }
        "SHR201" { return @{ receiver = $receiverValue; piiAvailable = $false } }
        "SHR210" { return @{ receiver = $receiverValue; source = "Get-MailboxFolderStatistics" } }
        "SHR211" {
            $result = @{ receiver = $receiverValue; matchedFolderCount = [int]$values[0] }
            if ($IncludeSensitiveData -and $values.Count -gt 1) {
                $result.matchedFolderNames = @($values[1] -split ', ')
            }
            return $result
        }
        "SHR212" { return @{ receiver = $receiverValue; genericCalendarCount = "Multiple" } }
        "SHR213" {
            $result = @{ owner = $ownerValue; receiver = $receiverValue; matchedFolderCount = 0 }
            if ($IncludeSensitiveData -and $values.Count -gt 1) {
                $result.ownerDisplayName = $values[1]
            }
            return $result
        }
        "SHR220" {
            $result = @{ receiver = $receiverValue; source = "AcceptCalendarSharingInvite" }
            if ($evidenceText -match 'contained \[(?<ElementCount>\d+)\] comma-delimited') {
                $result.elementCount = [int]$Matches["ElementCount"]
            }
            return $result
        }
        "SHR230" { return @{ receiver = $receiverValue; source = "Get-CalendarEntries" } }
        "SHR231" { return @{ owner = $ownerValue; receiver = $receiverValue; newModelEntryFound = $false } }
        "SHR232" {
            $result = @{ owner = $ownerValue; receiver = $receiverValue; isOrphanedEntry = $true }
            if ($IncludeSensitiveData -and $values.Count -gt 0) {
                $result.calendarName = $values[0]
            }
            return $result
        }
        "SHR233" {
            return @{
                owner              = $ownerValue
                receiver           = $receiverValue
                oldModelEntryCount = $(if ($values.Count -gt 0) { [int]$values[0] } else { 1 })
            }
        }
        "SHR240" { return @{ owner = $ownerValue; receiver = $receiverValue; source = "Get-MailboxCalendarFolder" } }
        "SHR241" { return @{ receiver = $receiverValue; extendedFolderFlags = @($values[0] -split ', ' | Where-Object { $_ }) } }
        "SHR242" { return @{ receiver = $receiverValue; extendedFolderFlags = @($values[0] -split ', ' | Where-Object { $_ }) } }
        "SHR243" {
            return @{
                expectedOwner = $ownerValue
                actualOwner   = $(if ($IncludeSensitiveData -and $values.Count -gt 1) {
                        Get-SanitizedSharingIdentity -Identity $values[1]
                    } else {
                        "Identity-1"
                    })
            }
        }
        "SHR300" { return @{ owner = $ownerValue; source = "CalendarSharingInvite" } }
        "SHR301" { return @{ owner = $ownerValue; receiver = $receiverValue; matchingInviteFound = $false } }
        "SHR310" { return @{ owner = $ownerValue; source = "Get-CalendarActiveSharingInformation" } }
        "SHR311" { return @{ owner = $ownerValue; receiver = $receiverValue; activeRelationshipFound = $false } }
        "SHR312" { return @{ receiver = $receiverValue; activeShareeFlags = @($values[0] -split ', ' | Where-Object { $_ }) } }
        "SHR320" { return @{ receiver = $receiverValue; activeRelationshipFound = $true; ownerPermissionFound = $false } }
        "SHR321" { return @{ receiver = $receiverValue; activeRelationshipFound = $false; ownerPermissionFound = $true } }
        "SHR322" {
            return @{
                ownerFlags    = @($values[0] -split ', ' | Where-Object { $_ })
                receiverFlags = @($values[1] -split ', ' | Where-Object { $_ })
            }
        }
        "SHR323" {
            return @{
                activeRelationshipFlags = @($values[0] -split ', ' | Where-Object { $_ })
                receiverFlags           = @($values[1] -split ', ' | Where-Object { $_ })
            }
        }
        "SHR400" {
            return @{
                lastAttemptedSyncTime  = $(if ($values.Count -gt 0) { $values[0] } else { $null })
                lastSuccessfulSyncTime = $(if ($values.Count -gt 1) { $values[1] } else { $null })
                staleThresholdHours    = 24
            }
        }
        "SHR401" {
            return @{
                lastAttemptedSyncTime  = $(if ($values.Count -gt 0) { $values[0] } else { $null })
                lastSuccessfulSyncTime = $(if ($values.Count -gt 1) { $values[1] } else { $null })
            }
        }
        "SHR402" {
            return @{
                lastAttemptedSyncTime  = $(if ($values.Count -gt 0) { $values[0] } else { $null })
                lastSuccessfulSyncTime = $(if ($values.Count -gt 1) { $values[1] } else { $null })
            }
        }
        "SHR410" { return @{ sharedCalendarSyncStartDate = $(if ($values.Count -gt 0) { $values[0] } else { $null }) } }
        "SHR411" {
            return @{
                sharedCalendarSyncStartDate = $(if ($values.Count -gt 0) { $values[0] } else { $null })
                folderCreationTime          = $(if ($values.Count -gt 1) { $values[1] } else { $null })
            }
        }
        "SHR412" { return @{ sharedCalendarSyncStartDate = $(if ($values.Count -gt 0) { $values[0] } else { $null }) } }
        "SHR413" { return @{ sharedCalendarSyncStartDate = $null } }
        "SHR420" { return @{ receiver = $receiverValue; source = "InternetCalendar" } }
        default { return @{ observed = $true } }
    }
}

function Add-SharingFinding {
    param(
        [Parameter()]
        [ValidateSet("Critical", "Error", "Warning", "Information")]
        [string]$Severity,

        [Parameter()]
        [string]$Area,

        [Parameter()]
        [string]$Issue,

        [Parameter()]
        [AllowNull()]
        [object]$Evidence,

        [Parameter()]
        [string]$RecommendedNextStep,

        [Parameter()]
        [switch]$Incomplete,

        [Parameter()]
        [ValidatePattern("^SHR\d{3}$")]
        [string]$RuleId,

        [Parameter()]
        [ValidateSet("Detected", "NotDetected", "NotEvaluated", "NotApplicable")]
        [string]$Status
    )

    $rule = if (-not [string]::IsNullOrWhiteSpace($RuleId)) {
        $script:SharingRuleCatalog | Where-Object -Property RuleId -EQ $RuleId | Select-Object -First 1
    } else {
        $script:SharingRuleCatalog | Where-Object -FilterScript {
            $_.Aliases -contains $Issue
        } | Select-Object -First 1
    }
    if ($null -eq $rule) {
        throw "No sharing rule is registered for finding [$RuleId$Issue]."
    }
    if (-not $script:SharingFindingRuleIds.Add($rule.RuleId)) {
        return
    }

    $script:ConsoleFindingEvidence[$rule.RuleId] = $Evidence
    $findingStatus = if (-not [string]::IsNullOrWhiteSpace($Status)) {
        $Status
    } elseif ($Incomplete) {
        "NotEvaluated"
    } else {
        "Detected"
    }
    $script:SharingFindings.Add([PSCustomObject]@{
            ruleId              = $rule.RuleId
            severity            = $rule.Severity
            status              = $findingStatus
            title               = $rule.Title
            evidence            = ConvertTo-SharingEvidence -RuleId $rule.RuleId -Evidence $Evidence
            recommendedNextStep = $rule.NextStep
            area                = $Area
        })
}

function Complete-SharingFindings {
    $ruleCollectors = @{
        SHR100 = @("OwnerMailbox"); SHR101 = @("OwnerMailbox")
        SHR110 = @("OwnerFolderStatistics"); SHR111 = @("OwnerCalendarPermissions")
        SHR112 = @("OwnerFolderStatistics")
        SHR430 = @("OwnerFolderStatistics"); SHR431 = @("OwnerFolderStatistics")
        SHR120 = @("OwnerCalendarFolder"); SHR121 = @("OwnerCalendarFolder"); SHR122 = @("OwnerCalendarFolder")
        SHR123 = @("OwnerCalendarFolder")
        SHR130 = @("OwnerMailboxPermissions")
        SHR200 = @("ReceiverMailbox"); SHR201 = @("ReceiverMailbox")
        SHR210 = @("ReceiverFolderStatistics"); SHR211 = @("ReceiverFolderStatistics")
        SHR212 = @("ReceiverFolderStatistics"); SHR213 = @("ReceiverFolderStatistics")
        SHR214 = @("ReceiverFolderStatistics")
        SHR220 = @("ReceiverAcceptLog")
        SHR230 = @("CalendarEntries"); SHR231 = @("CalendarEntries")
        SHR232 = @("CalendarEntries"); SHR233 = @("CalendarEntries")
        SHR240 = @("ReceiverLocalCalendarFolder"); SHR241 = @("ReceiverLocalCalendarFolder")
        SHR242 = @("ReceiverLocalCalendarFolder"); SHR243 = @("ReceiverLocalCalendarFolder")
        SHR300 = @("OwnerInviteLog"); SHR301 = @("OwnerInviteLog")
        SHR310 = @("ActiveSharing"); SHR311 = @("ActiveSharing"); SHR312 = @("ActiveSharing")
        SHR320 = @("OwnerCalendarPermissions", "ActiveSharing")
        SHR321 = @("OwnerCalendarPermissions", "ActiveSharing")
        SHR322 = @("OwnerCalendarPermissions", "ReceiverLocalCalendarFolder")
        SHR323 = @("ActiveSharing", "ReceiverLocalCalendarFolder")
        SHR400 = @("ReceiverLocalCalendarFolder"); SHR401 = @("ReceiverLocalCalendarFolder")
        SHR402 = @("ReceiverLocalCalendarFolder"); SHR403 = @("ReceiverLocalCalendarFolder")
        SHR410 = @("ReceiverLocalCalendarFolder")
        SHR411 = @("ReceiverLocalCalendarFolder"); SHR412 = @("ReceiverLocalCalendarFolder")
        SHR413 = @("ReceiverLocalCalendarFolder"); SHR420 = @("InternetCalendar")
        SHR421 = @("InternetCalendar"); SHR422 = @("InternetCalendar", "ReceiverFolderStatistics")
        SHR423 = @("OwnerCalendarFolder")
        SHR432 = @("OwnerFolderStatistics", "ReceiverFolderStatistics")
    }

    if ($null -ne $script:FatalPrerequisiteFailure) {
        $skipReason = "Skipped after fatal prerequisite failure: $($script:FatalPrerequisiteFailure.ruleId)"
        foreach ($finding in $script:SharingFindings) {
            if ($finding.ruleId -ne $script:FatalPrerequisiteFailure.ruleId) {
                $finding.status = "NotApplicable"
                $finding.evidence = ConvertTo-SharingEvidence -RuleId $finding.ruleId -Evidence @{
                    reason = $skipReason
                }
                $script:ConsoleFindingEvidence[$finding.ruleId] = @{
                    reason = $skipReason
                }
            }
        }
        foreach ($rule in $script:SharingRuleCatalog) {
            if (-not $script:SharingFindingRuleIds.Contains($rule.RuleId)) {
                Add-SharingFinding -RuleId $rule.RuleId -Status NotApplicable -Evidence @{
                    reason = $skipReason
                }
            }
        }

        $rootCollector = @{
            SHR100 = "OwnerMailbox"
            SHR101 = "OwnerMailbox"
            SHR200 = "ReceiverMailbox"
            SHR201 = "ReceiverMailbox"
            SHR110 = "OwnerFolderStatistics"
            SHR123 = "OwnerCalendarFolder"
        }[$script:FatalPrerequisiteFailure.ruleId]
        $rootCollectionErrors = @($script:CollectionErrors | Where-Object -Property collector -EQ $rootCollector)
        $script:CollectionErrors.Clear()
        foreach ($collectionError in $rootCollectionErrors) {
            $script:CollectionErrors.Add($collectionError)
        }
        $script:EvaluationErrors.Clear()
        return
    }

    if ($script:LegacyMapiSharing -or $script:PublishedSharing) {
        $nonModernReason = if ($script:PublishedSharing) {
            "Not applicable to a published-calendar relationship."
        } else {
            "Not applicable to an internal legacy MAPI calendar-sharing relationship."
        }
        foreach ($finding in $script:SharingFindings) {
            if ($finding.ruleId -in $script:ModernSharingRuleIds) {
                $finding.status = "NotApplicable"
                $finding.evidence = ConvertTo-SharingEvidence -RuleId $finding.ruleId -Evidence @{
                    reason = $nonModernReason
                }
                $script:ConsoleFindingEvidence[$finding.ruleId] = @{
                    reason = $nonModernReason
                }
            }
        }
        foreach ($collectorName in $script:ModernSharingCollectorNames) {
            $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{
                status = "NotApplicable"
                error  = $null
            }
        }
        $relevantCollectionErrors = @($script:CollectionErrors | Where-Object {
                $_.collector -notin $script:ModernSharingCollectorNames
            })
        $script:CollectionErrors.Clear()
        foreach ($collectionError in $relevantCollectionErrors) {
            $script:CollectionErrors.Add($collectionError)
        }
    }

    if ((-not $script:OwnerPublished) -and
        $script:CollectorStatuses["InternetCalendar"].status -eq "NotRun") {
        $script:CollectorStatuses["InternetCalendar"] = [PSCustomObject]@{ status = "NotApplicable"; error = $null }
    }
    foreach ($collectorName in @($script:CollectorStatuses.Keys)) {
        if ($script:CollectorStatuses[$collectorName].status -eq "NotRun") {
            $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{ status = "NotEvaluated"; error = $null }
        }
    }

    foreach ($rule in $script:SharingRuleCatalog) {
        if ($script:SharingFindingRuleIds.Add($rule.RuleId)) {
            $status = "NotDetected"
            if ($script:LegacyMapiSharing -and
                ($rule.RuleId -in $script:ModernSharingRuleIds)) {
                $status = "NotApplicable"
            } elseif ($script:PublishedSharing -and
                ($rule.RuleId -in $script:ModernSharingRuleIds)) {
                $status = "NotApplicable"
            } elseif (($rule.RuleId -in @("SHR421", "SHR422", "SHR423")) -and
                (-not $script:PublishedSharing)) {
                $status = "NotApplicable"
            } elseif (($rule.RuleId -eq "SHR420") -and
                (-not $script:OwnerPublished)) {
                $status = "NotApplicable"
            } elseif ($ruleCollectors.ContainsKey($rule.RuleId)) {
                $requiredCollectorStatuses = @($ruleCollectors[$rule.RuleId] | ForEach-Object {
                        $script:CollectorStatuses[$_].status
                    })
                if (($rule.RuleId -eq "SHR420") -and
                    ($requiredCollectorStatuses -eq "NoData")) {
                    $status = "NotDetected"
                } elseif (@($requiredCollectorStatuses | Where-Object { $_ -ne "Success" }).Count -gt 0) {
                    $status = "NotEvaluated"
                }
            }
            if (($rule.RuleId -eq "SHR432") -and
                (-not $script:LegacyMapiSharing) -and
                (-not $script:PublishedSharing) -and
                (-not $script:CalendarStatisticsComparisonPerformed)) {
                $status = "NotEvaluated"
            }
            $receiverFolderMissing = (
                $script:CollectorStatuses["ReceiverFolderStatistics"].status -eq "Success" -and
                $script:ReceiverCalendarCandidates.Count -eq 0)
            if ($receiverFolderMissing -and
                $rule.RuleId -in @(
                    "SHR240", "SHR241", "SHR242", "SHR243",
                    "SHR400", "SHR401", "SHR402", "SHR403", "SHR410",
                    "SHR411", "SHR412", "SHR413")) {
                $status = "NotApplicable"
            }
            if ($rule.RuleId -in @("SHR400", "SHR402") -and
                @($script:SharingFindings | Where-Object {
                        $_.ruleId -eq "SHR401" -and $_.status -eq "NotEvaluated"
                    }).Count -gt 0) {
                $status = "NotEvaluated"
            }
            if ($rule.RuleId -in @("SHR410", "SHR411", "SHR412") -and
                @($script:SharingFindings | Where-Object {
                        $_.ruleId -eq "SHR413" -and $_.status -eq "Detected"
                    }).Count -gt 0) {
                $status = "NotApplicable"
            } elseif ($rule.RuleId -in @("SHR411", "SHR412") -and
                @($script:SharingFindings | Where-Object {
                        $_.ruleId -eq "SHR410" -and $_.status -in @("Detected", "NotEvaluated")
                    }).Count -gt 0) {
                $status = "NotEvaluated"
            }
            $script:SharingFindings.Add([PSCustomObject]@{
                    ruleId              = $rule.RuleId
                    severity            = $rule.Severity
                    status              = $status
                    title               = $rule.Title
                    evidence            = @{}
                    recommendedNextStep = $rule.NextStep
                    area                = $null
                })
        }
    }
}

function Test-SmtpAddressEqual {
    param(
        [AllowNull()]
        [object]$First,

        [AllowNull()]
        [object]$Second
    )

    if (($null -eq $First) -or ($null -eq $Second)) {
        return $false
    }

    return [string]::Equals(
        $First.ToString().Trim(),
        $Second.ToString().Trim(),
        [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-PermissionEntriesForIdentity {
    param(
        [AllowNull()]
        [object[]]$PermissionEntries,

        [Parameter(Mandatory)]
        [string]$Identity
    )

    return @($PermissionEntries | Where-Object -FilterScript {
            (Test-SmtpAddressEqual -First $_.User -Second $Identity) -or
            (Test-SmtpAddressEqual -First $_.User.PrimarySmtpAddress -Second $Identity) -or
            (Test-SmtpAddressEqual -First $_.User.RecipientPrincipal.PrimarySmtpAddress -Second $Identity)
        })
}

function Get-PermissionRightsText {
    param(
        [AllowNull()]
        [object[]]$PermissionEntries,

        [switch]$IncludeSharingFlags
    )

    $accessRights = @($PermissionEntries | ForEach-Object {
            @($_.AccessRights) | ForEach-Object {
                if ($null -ne $_) {
                    $_.ToString()
                }
            }
        } | Sort-Object -Unique)
    $rightsText = if ($accessRights.Count -gt 0) {
        $accessRights -join ", "
    } else {
        "None"
    }
    if ($IncludeSharingFlags) {
        $sharingFlags = @($PermissionEntries | ForEach-Object {
                @($_.SharingPermissionFlags) | ForEach-Object {
                    if (-not [string]::IsNullOrWhiteSpace([string]$_)) {
                        $_.ToString()
                    }
                }
            } | Sort-Object -Unique)
        if ($sharingFlags.Count -gt 0) {
            $rightsText = "$rightsText; SharingPermissionFlags: $($sharingFlags -join ', ')"
        }
    }

    return $rightsText
}

function Write-SharingFindingDetails {
    param(
        [AllowEmptyCollection()]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [hashtable]$SeverityOrder
    )

    $displayFindings = @($Findings |
            ForEach-Object {
                [PSCustomObject]@{
                    severity            = $_.severity
                    ruleId              = $_.ruleId
                    title               = $_.title
                    evidence            = $script:ConsoleFindingEvidence[$_.ruleId]
                    recommendedNextStep = $_.recommendedNextStep
                }
            } |
            Sort-Object -Property @{ Expression = { $SeverityOrder[$_.severity] } }, ruleId)

    $displayFindings |
        Format-Table -AutoSize -Wrap -Property @{
            Label      = "Severity"
            Expression = { $_.severity }
        }, @{
            Label      = "RuleId"
            Expression = { $_.ruleId }
        }, @{
            Label      = "Title"
            Expression = { $_.title }
        }, @{
            Label      = "Evidence"
            Expression = { $_.evidence }
        }
    Write-Host -ForegroundColor Blue "`rRecommended Next Steps:"
    foreach ($finding in $displayFindings) {
        Write-Host -ForegroundColor Yellow "[$($finding.ruleId)] $($finding.recommendedNextStep)"
    }
}

function Write-OwnerReceiverPermissionSummary {
    param(
        [Parameter(Mandatory)]
        [string]$Receiver
    )

    $receiverCalendarPermissions = Get-PermissionEntriesForIdentity `
        -PermissionEntries $script:OwnerCalendarPerms `
        -Identity $Receiver
    $receiverMailboxPermissions = Get-PermissionEntriesForIdentity `
        -PermissionEntries $script:OwnerMailboxPerms `
        -Identity $Receiver
    $calendarRights = if ($receiverCalendarPermissions.Count -gt 0) {
        Get-PermissionRightsText `
            -PermissionEntries $receiverCalendarPermissions `
            -IncludeSharingFlags
    } else {
        $null
    }
    $mailboxRights = if ($receiverMailboxPermissions.Count -gt 0) {
        Get-PermissionRightsText -PermissionEntries $receiverMailboxPermissions
    } else {
        $null
    }

    Write-Host -ForegroundColor DarkYellow "Owner-to-Receiver Permission Summary:"
    if (($null -ne $calendarRights) -and ($null -ne $mailboxRights)) {
        Write-Host -ForegroundColor Green "Receiver [$Receiver] has [$calendarRights] on the owner Calendar folder and [$mailboxRights] on the owner Mailbox."
    } elseif ($null -ne $calendarRights) {
        Write-Host -ForegroundColor Green "Receiver [$Receiver] is using [$calendarRights] on the owner Calendar folder."
    } elseif ($null -ne $mailboxRights) {
        Write-Host -ForegroundColor Green "Receiver [$Receiver] has [$mailboxRights] on the owner Mailbox."
    } elseif ($script:OwnerCalendarPermsAvailable -and $script:OwnerMailboxPermsAvailable) {
        Write-Host -ForegroundColor Yellow "Receiver [$Receiver] does not have an individual permission entry on the owner Calendar folder or Mailbox; access may come from Default or a group permission."
    } else {
        Write-Host -ForegroundColor Yellow "Receiver-specific permissions could not be fully evaluated because the owner Calendar folder or Mailbox permission query was unavailable."
    }
}

function Test-UninitializedCalendarDate {
    param(
        [AllowNull()]
        [object]$Value
    )

    $dateValue = $Value -as [DateTime]
    return ($null -ne $dateValue) -and ($dateValue.Year -eq 1)
}

function Register-SharingFatalPrerequisiteFailure {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("SHR100", "SHR101", "SHR110", "SHR123", "SHR200", "SHR201")]
        [string]$RuleId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Reason
    )

    if ($null -ne $script:FatalPrerequisiteFailure) {
        return
    }

    $boundedReason = ($Reason -replace '[\r\n\t]+', ' ').Trim()
    if ($boundedReason.Length -gt 256) {
        $boundedReason = $boundedReason.Substring(0, 256)
    }
    $script:FatalPrerequisiteFailure = [PSCustomObject]@{
        ruleId = $RuleId
        reason = $boundedReason
    }
}

function Test-SharingMailboxNamePrerequisite {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Owner", "Receiver")]
        [string]$Role,

        [Parameter(Mandatory)]
        [object]$Mailbox
    )

    $redactedProperty = @("DisplayName", "Name", "Alias") |
        ForEach-Object {
            $property = $Mailbox.PSObject.Properties[$_]
            if (($null -ne $property) -and
                (-not [string]::IsNullOrWhiteSpace([string]$property.Value)) -and
                ([string]$property.Value -match "^\s*REDACTED-")) {
                [PSCustomObject]@{
                    Name  = $property.Name
                    Value = [string]$property.Value
                }
            }
        } |
        Select-Object -First 1
    if ($null -eq $redactedProperty) {
        return $true
    }

    $ruleId = if ($Role -eq "Owner") { "SHR101" } else { "SHR201" }
    $database = [string]$Mailbox.Database
    $databaseGuidance = if ([string]::IsNullOrWhiteSpace($database)) {
        ""
    } else {
        " for mailbox database [$database]"
    }
    $reason = "$Role mailbox name is redacted."
    Write-Host -ForegroundColor Red "$reason Obtain PII access$databaseGuidance and rerun."
    Add-SharingFinding -RuleId $ruleId -Status Detected -Area "$Role mailbox prerequisite" -Evidence @{
        mailboxRole   = $Role
        fieldName     = $redactedProperty.Name
        piiAvailable  = $false
        redactedValue = $redactedProperty.Value
        database      = $database
    }
    Register-SharingFatalPrerequisiteFailure -RuleId $ruleId -Reason $reason
    return $false
}

function Resolve-SharingMailboxPrerequisite {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Owner", "Receiver")]
        [string]$Role,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity
    )

    $collectorName = "${Role}Mailbox"
    $ruleId = if ($Role -eq "Owner") { "SHR100" } else { "SHR200" }
    $cachedMailbox = if ($Role -eq "Owner") { $script:OwnerMB } else { $script:ReceiverMB }
    if (($null -ne $cachedMailbox) -and
        ($script:CollectorStatuses[$collectorName].status -eq "Success")) {
        return Test-SharingMailboxNamePrerequisite -Role $Role -Mailbox $cachedMailbox
    }

    Write-Host -ForegroundColor Cyan "Prerequisite: Get-Mailbox -Identity $Identity"
    try {
        $mailbox = Invoke-SharingCollector -Name $collectorName -Action {
            Get-Mailbox -Identity $Identity -ErrorAction Stop
        } -AllowNull
    } catch {
        $reason = "$Role mailbox lookup failed; prerequisite evidence is unavailable."
        Write-Host -ForegroundColor Red $reason
        Add-SharingFinding -RuleId $ruleId -Status NotEvaluated -Area "$Role mailbox prerequisite" -Evidence @{
            reason = $reason
        }
        Register-SharingFatalPrerequisiteFailure -RuleId $ruleId -Reason $reason
        return $false
    }

    if ($null -eq $mailbox) {
        $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{ status = "NoData"; error = $null }
        $reason = "Get-Mailbox returned no $Role mailbox object."
        Write-Host -ForegroundColor Red $reason
        Add-SharingFinding -RuleId $ruleId -Status Detected -Area "$Role mailbox prerequisite" -Evidence @{
            reason = $reason
        }
        Register-SharingFatalPrerequisiteFailure -RuleId $ruleId -Reason $reason
        return $false
    }

    if ($Role -eq "Owner") {
        $script:OwnerMB = $mailbox
    } else {
        $script:ReceiverMB = $mailbox
    }
    return Test-SharingMailboxNamePrerequisite -Role $Role -Mailbox $mailbox
}

function Resolve-SharingMailboxPrerequisites {
    Write-Host -ForegroundColor Cyan "`r`rPrerequisite mailbox resolution:"
    if (-not (Resolve-SharingMailboxPrerequisite -Role Owner -Identity $Owner)) {
        return $false
    }
    if (-not (Resolve-SharingMailboxPrerequisite -Role Receiver -Identity $Receiver)) {
        return $false
    }
    return $true
}

function Resolve-OwnerCalendarPrerequisite {
    if (($null -ne $script:OwnerSelectedCalendar) -and
        ($null -ne $script:OwnerCalendarFolder) -and
        ($script:CollectorStatuses["OwnerFolderStatistics"].status -eq "Success") -and
        ($script:CollectorStatuses["OwnerCalendarFolder"].status -eq "Success")) {
        return $true
    }

    Write-Host -ForegroundColor Cyan "Prerequisite: Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar"
    try {
        $script:OwnerCalendarStats = @(Invoke-SharingCollector -Name "OwnerFolderStatistics" -Action {
                @(Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar -ErrorAction Stop)
            })
    } catch {
        $reason = "Owner calendar folder statistics are unavailable."
        Add-SharingFinding -RuleId "SHR110" -Status NotEvaluated -Area "Owner calendar prerequisite" -Evidence @{
            reason = $reason
        }
        Register-SharingFatalPrerequisiteFailure -RuleId "SHR110" -Reason $reason
        return $false
    }

    $ownerDefaultCalendarStats = @($script:OwnerCalendarStats |
            Where-Object -Property FolderType -EQ "Calendar")
    $ownerDefaultCalendarStat = if ($ownerDefaultCalendarStats.Count -eq 1) {
        $ownerDefaultCalendarStats[0]
    } else {
        $null
    }
    $script:OwnerCalendarRootName = $ownerDefaultCalendarStat.Name
    $matchingOwnerCalendarStats = @()
    if ($script:OwnerCalendarFolderPathSpecified -and
        ($null -ne $ownerDefaultCalendarStat)) {
        $requestedFolderIdentity = Get-CanonicalMailboxFolderIdentity `
            -Mailbox $Owner `
            -CalendarRootName $script:OwnerCalendarRootName `
            -FolderPath $script:NormalizedOwnerCalendarFolderPath
        $script:NormalizedOwnerCalendarFolderPath = $requestedFolderIdentity.Substring($requestedFolderIdentity.IndexOf(":") + 1)
        $matchingOwnerCalendarStats = @($script:OwnerCalendarStats | Where-Object -FilterScript {
                $statisticsFolderIdentity = Get-CanonicalMailboxFolderIdentity `
                    -Mailbox $Owner `
                    -CalendarRootName $script:OwnerCalendarRootName `
                    -FolderPath $_.FolderPath.ToString()
                $normalizedStatisticsPath = $statisticsFolderIdentity.Substring($statisticsFolderIdentity.IndexOf(":") + 1)
                [string]::Equals(
                    $normalizedStatisticsPath,
                    $script:NormalizedOwnerCalendarFolderPath,
                    [System.StringComparison]::OrdinalIgnoreCase)
            })
        $ownerCalendarStat = if ($matchingOwnerCalendarStats.Count -eq 1) {
            $matchingOwnerCalendarStats[0]
        } else {
            $null
        }
    } else {
        $ownerCalendarStat = if ($script:OwnerCalendarFolderPathSpecified) {
            $null
        } else {
            $ownerDefaultCalendarStat
        }
    }

    if ($null -eq $ownerCalendarStat) {
        $script:CollectorStatuses["OwnerFolderStatistics"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        $selectionReason = if ($ownerDefaultCalendarStats.Count -gt 1) {
            "The default owner calendar folder selection matched more than one folder."
        } elseif (-not $script:OwnerCalendarFolderPathSpecified) {
            "The default owner calendar folder could not be identified."
        } elseif ($ownerDefaultCalendarStats.Count -eq 0) {
            "The default owner calendar root could not be identified for the requested path."
        } elseif ($matchingOwnerCalendarStats.Count -eq 0) {
            "The requested owner calendar folder path was not found."
        } else {
            "The requested owner calendar folder path matched more than one folder."
        }
        Write-Host -ForegroundColor Red "$selectionReason Requested owner-relative path: [$($script:NormalizedOwnerCalendarFolderPath)]."
        if ($script:OwnerCalendarStats.Count -gt 0) {
            Write-Host -ForegroundColor Yellow "Available Owner Calendar folders returned by Get-MailboxFolderStatistics:"
            $availableOwnerCalendarTable = $script:OwnerCalendarStats |
                Sort-Object -Property FolderPath |
                Format-Table -AutoSize -Property Name, FolderPath, @{
                    Label      = "ItemsInFolder"
                    Expression = { $_.VisibleItemsInFolder }
                } |
                Out-String
            Write-Host $availableOwnerCalendarTable
        }
        Add-SharingFinding -RuleId "SHR110" -Status NotEvaluated -Area "Owner calendar prerequisite" -Evidence @{
            folderPath = $script:NormalizedOwnerCalendarFolderPath
            reason     = $selectionReason
        }
        Register-SharingFatalPrerequisiteFailure -RuleId "SHR110" -Reason $selectionReason
        return $false
    }

    $script:OwnerSelectedCalendar = $ownerCalendarStat
    $script:OwnerCalendarFolderIdentity = Get-CanonicalMailboxFolderIdentity `
        -Mailbox $Owner `
        -CalendarRootName $script:OwnerCalendarRootName `
        -FolderPath $ownerCalendarStat.FolderPath.ToString()
    $script:OwnerCalendarLeafName = $ownerCalendarStat.Name
    if ($script:OwnerCalendarFolderPathSpecified -and
        ($ownerCalendarStat.FolderType -ne "Calendar")) {
        $script:OwnerCalendarLeafNameCandidate = $ownerCalendarStat.Name
    }

    Write-Host -ForegroundColor Cyan "Prerequisite: Get-MailboxCalendarFolder -Identity `"$($script:OwnerCalendarFolderIdentity)`""
    try {
        $script:OwnerCalendarFolder = Invoke-SharingCollector -Name "OwnerCalendarFolder" -Action {
            Get-MailboxCalendarFolder -Identity $script:OwnerCalendarFolderIdentity -ErrorAction Stop
        }
    } catch {
        $reason = "Selected owner calendar ownership evidence is unavailable."
        Add-SharingFinding -RuleId "SHR123" -Status NotEvaluated -Area "Owner calendar prerequisite" -Evidence @{
            reason = $reason
        }
        Register-SharingFatalPrerequisiteFailure -RuleId "SHR123" -Reason $reason
        return $false
    }

    $actualOwnerCalendarOwner = [string]$script:OwnerCalendarFolder.CalendarSharingOwnerSmtpAddress
    if ((-not [string]::IsNullOrWhiteSpace($actualOwnerCalendarOwner)) -and
        (-not (Test-SmtpAddressEqual -First $actualOwnerCalendarOwner -Second $Owner))) {
        $inputsReversed = Test-SmtpAddressEqual -First $actualOwnerCalendarOwner -Second $Receiver
        if ($inputsReversed) {
            Write-Host -ForegroundColor Red "Selected Owner Calendar ownership mismatch. Expected Owner: [$Owner]. Actual calendar owner: [$actualOwnerCalendarOwner]. The Owner and Receiver appear reversed. Rerun the script with Owner and Receiver swapped."
        } else {
            Write-Host -ForegroundColor Red "Selected Owner Calendar ownership mismatch. Expected Owner: [$Owner]. Actual calendar owner: [$actualOwnerCalendarOwner]. The selected folder is a shared copy owned by another mailbox. Correct the Owner or owner calendar folder path."
        }
        Add-SharingFinding -RuleId "SHR123" -Status Detected -Area "Owner calendar identity" -Evidence @{
            expectedOwner  = $Owner
            actualOwner    = $actualOwnerCalendarOwner
            inputsReversed = $inputsReversed
        }
        $reason = if ($inputsReversed) {
            "Selected owner calendar belongs to the supplied Receiver; Owner and Receiver appear reversed."
        } else {
            "Selected owner calendar belongs to another mailbox."
        }
        Register-SharingFatalPrerequisiteFailure -RuleId "SHR123" -Reason $reason
        return $false
    }

    return $true
}

function Get-ReceiverFolderIdentity {
    param(
        [Parameter(Mandatory)]
        [string]$Receiver,

        [Parameter(Mandatory)]
        [string]$ReceiverCalendarName,

        [Parameter(Mandatory)]
        [string]$FolderPath
    )

    $receiverFolderPath = $FolderPath.TrimStart("/").Replace("/", "\")
    if (($receiverFolderPath -ne $ReceiverCalendarName) -and
        (-not $receiverFolderPath.StartsWith("$ReceiverCalendarName\", [System.StringComparison]::OrdinalIgnoreCase))) {
        $receiverFolderPath = "$ReceiverCalendarName\$receiverFolderPath"
    }

    return "${Receiver}:\$receiverFolderPath"
}

<#
.SYNOPSIS
    Formats the CalendarSharingInvite logs from Export-MailboxDiagnosticLogs for a given identity.
.DESCRIPTION
    This function processes calendar sharing accept logs for a given identity and outputs the most recent update for each recipient.
.PARAMETER Identity
    The SMTP Address for which to process calendar sharing accept logs.
#>
function ProcessCalendarSharingInviteLogs {
    param (
        [string]$Identity
    )

    # Define the header row
    $header = "Timestamp", "Mailbox", "Entry MailboxOwner", "Recipient", "RecipientType", "SharingType", "DetailLevel"
    $csvString = @()
    $csvString = $header -join ","
    $csvString += "`n"

    try {
        # -ErrorAction is not supported on Export-MailboxDiagnosticLogs
        # $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName CalendarSharingInvite -ErrorAction SilentlyContinue

        $logOutput = Invoke-SharingCollector -Name "OwnerInviteLog" -Action {
            Export-MailboxDiagnosticLogs -Identity $Identity -ComponentName CalendarSharingInvite
        }
    } catch {
        Write-Warning "Failed to retrieve CalendarSharingInvite logs for [$Identity]: $($_.Exception.Message)"
        Add-SharingFinding -Severity Warning -Area "CalendarSharingInvite" -Issue "The owner invite-log check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Collect CalendarSharingInvite logs with sufficient access and inspect the invite for the expected receiver." -Incomplete
        return
    }

    # check if the output is empty
    if ($null -eq $logOutput.MailboxLog) {
        $script:CollectorStatuses["OwnerInviteLog"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host "No data found for [$Identity]."
        Add-SharingFinding -Severity Warning -Area "CalendarSharingInvite" -Issue "The owner invite-log check had no data." -Evidence "CalendarSharingInvite returned no MailboxLog data for [$Identity]." -RecommendedNextStep "Collect CalendarSharingInvite logs and verify whether an invite was generated for [$Receiver]." -Incomplete
        return
    }

    # Split the output into an array of lines
    $logLines = $logOutput.MailboxLog -split "`r`n"

    # Loop through each line of the output
    foreach ($line in $logLines) {
        if ($line -like "*RecipientType*") {
            $csvString += $line + "`n"
        }
    }

    # Clean up output
    $csvString = $csvString.Replace("Mailbox: ", "")
    $csvString = $csvString.Replace("Entry MailboxOwner:", "")
    $csvString = $csvString.Replace("Recipient:", "")
    $csvString = $csvString.Replace("RecipientType:", "")
    $csvString = $csvString.Replace("Handler=", "")
    $csvString = $csvString.Replace("ms-exchange-", "")
    $csvString = $csvString.Replace("DetailLevel=", "")

    # Convert the CSV string to an object
    $csvObject = Invoke-SharingEvaluation -Name "Owner invite-log parsing" -RuleIds @("SHR300", "SHR301") -Action {
        $csvString | ConvertFrom-Csv
    }
    if ($null -eq $csvObject) {
        Add-SharingFinding -Severity Warning -Area "CalendarSharingInvite" -Issue "The owner invite-log check was unavailable." -Evidence "CalendarSharingInvite data could not be parsed." -RecommendedNextStep "Inspect the raw CalendarSharingInvite logs." -Incomplete
        return
    }
    $script:OwnerInviteCheckAvailable = $true
    $script:OwnerInviteData = @($csvObject)

    # Access the values as properties of the object
    foreach ($row in $csvObject) {
        Write-Debug "$($row.Recipient) - $($row.SharingType) - $($row.detailLevel)"
    }

    #Filter the output to get the most recent update foreach recipient
    $mostRecentRecipients = $csvObject | Sort-Object Recipient -Unique | Sort-Object Timestamp -Descending

    # Output the results to the console
    Write-Host "User [$Identity] has shared their calendar with the following recipients:"
    $mostRecentRecipients | Format-Table -a Timestamp, Recipient, SharingType, DetailLevel

    $receiverInvites = @($csvObject | Where-Object -FilterScript {
            Test-SmtpAddressEqual -First $_.Recipient -Second $Receiver
        })
    if ($receiverInvites.Count -eq 0) {
        Add-SharingFinding -Severity Error -Area "CalendarSharingInvite" -Issue "No pair-specific sharing invite was found for the expected receiver." -Evidence "Parsed owner CalendarSharingInvite data did not contain receiver [$Receiver]." -RecommendedNextStep "Inspect CalendarSharingInvite and AcceptCalendarSharingInvite logs for this owner/receiver pair."
    }
}

<#
.SYNOPSIS
    Formats the AcceptCalendarSharingInvite logs from Export-MailboxDiagnosticLogs for a given identity.
.DESCRIPTION
    This function processes calendar sharing invite logs.
.PARAMETER Identity
    The SMTP Address for which to process calendar sharing accept logs.
#>
function ProcessCalendarSharingAcceptLogs {
    param (
        [string]$Identity
    )

    # Define the header row
    $header4Line = "Timestamp", "Mailbox", "SharedCalendarOwner", "FolderName"
    $header5Line = "Timestamp", "MailboxLast", "MailboxFirst", "SharedCalendarOwner", "FolderName"

    try {
        # -ErrorAction is not supported on Export-MailboxDiagnosticLogs
        # $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName AcceptCalendarSharingInvite -ErrorAction SilentlyContinue
        Write-Host "Collecting AcceptCalendarSharingInvite logs for [$Identity] ..."
        $logOutput = Invoke-SharingCollector -Name "ReceiverAcceptLog" -Action {
            Export-MailboxDiagnosticLogs -Identity $Identity -ComponentName AcceptCalendarSharingInvite
        }
    } catch {
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match "(?i)not\s+found|no\s+logs") {
            Write-Warning "No AcceptCalendarSharingInvite logs found for [$Identity]. Details: $errorMessage"
            Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "The receiver accept-log check was unavailable." -Evidence $errorMessage -RecommendedNextStep "Collect AcceptCalendarSharingInvite logs and verify acceptance for the expected owner." -Incomplete
            return
        }

        Write-Warning "Failed to collect AcceptCalendarSharingInvite logs for [$Identity]: $errorMessage"
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "The receiver accept-log check failed." -Evidence $errorMessage -RecommendedNextStep "Collect AcceptCalendarSharingInvite logs and verify acceptance for the expected owner." -Incomplete
        return
    }

    # check if the output is empty
    if ($null -eq $logOutput.MailboxLog) {
        $script:CollectorStatuses["ReceiverAcceptLog"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host "No AcceptCalendarSharingInvite Logs found for [$Identity]."
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "The receiver accept-log check had no data." -Evidence "AcceptCalendarSharingInvite returned no MailboxLog data for [$Identity]." -RecommendedNextStep "Collect AcceptCalendarSharingInvite logs and verify acceptance for owner [$Owner]." -Incomplete
        return
    }

    # Split the output into an array of lines
    $logLines = $logOutput.MailboxLog -split "`r`n"

    # Loop through each line of the output
    $filteredLogLines = @()
    foreach ($line in $logLines) {
        if ($line -like "*CreateInternalSharedCalendarGroupEntry*") {
            $filteredLogLines += $line + "`n"
        }
    }
    if ($filteredLogLines.Count -eq 0) {
        $script:CollectorStatuses["ReceiverAcceptLog"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host "No CreateInternalSharedCalendarGroupEntry entries found for [$Identity]."
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "No relevant receiver accept-log entries were available." -Evidence "No CreateInternalSharedCalendarGroupEntry entries were returned for [$Identity]." -RecommendedNextStep "Inspect AcceptCalendarSharingInvite logs for acceptance of the calendar from [$Owner]." -Incomplete
        return
    }
    $ElementCount = ($filteredLogLines[0] -split ',').Count

    if ($ElementCount -eq 4) {
        $header = $header4Line
    } elseif ($ElementCount -eq 5) {
        $header = $header5Line
    } else {
        $parseError = ConvertTo-SharingErrorInfo -ErrorRecord "Unexpected receiver accept-log format."
        $script:CollectorStatuses["ReceiverAcceptLog"] = [PSCustomObject]@{ status = "Failed"; error = $parseError }
        $script:CollectionErrors.Add([PSCustomObject]@{
                collector = "ReceiverAcceptLog"
                error     = $parseError
            })
        Write-Host "Unexpected number of elements [$ElementCount] in the log lines for [$Identity]."
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "The receiver accept logs could not be parsed." -Evidence "The relevant log entry contained [$ElementCount] comma-delimited elements." -RecommendedNextStep "Inspect the raw AcceptCalendarSharingInvite logs for the owner/receiver pair." -Incomplete
        return
    }

    $csvString = @()
    $csvString = $header -join ","
    $csvString += "`n"

    foreach ($line in $filteredLogLines) {
        $csvString += $line + "`n"
    }

    # Clean up output
    $csvString = $csvString.Replace("Mailbox: ", "")
    $csvString = $csvString.Replace("'", "")
    $csvString = $csvString.Replace("Entry MailboxOwner:", "")
    $csvString = $csvString.Replace("Entry CreateInternalSharedCalendarGroupEntry: ", "")
    $csvString = $csvString.Replace("Creating a shared calendar for ", "")
    $csvString = $csvString.Replace("calendar name ", "")

    # Convert the CSV string to an object
    $csvObject = Invoke-SharingEvaluation -Name "Receiver accept-log parsing" -RuleIds @("SHR220") -Action {
        $csvString | ConvertFrom-Csv
    }
    if ($null -eq $csvObject) {
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "The receiver accept logs could not be parsed." -Evidence "AcceptCalendarSharingInvite data could not be parsed." -RecommendedNextStep "Inspect the raw AcceptCalendarSharingInvite logs." -Incomplete
        return
    }
    $script:ReceiverAcceptLogEntries = @($csvObject)
    $displayCsvObject = if ($script:OwnerCalendarFolderPathSpecified) {
        @($csvObject | Where-Object -FilterScript {
                (Test-SmtpAddressEqual -First $_.SharedCalendarOwner -Second $Owner) -and
                [string]::Equals(
                    $_.FolderName,
                    $script:RequestedOwnerCalendarLeafName,
                    [System.StringComparison]::OrdinalIgnoreCase)
            })
    } else {
        @($csvObject)
    }
    $script:ReceiverSelectedAcceptLogEntries = @($displayCsvObject)

    # Access the values as properties of the object
    foreach ($row in $csvObject) {
        Write-Debug "$($row.Timestamp) - $($row.SharedCalendarOwner) - $($row.FolderName) "
    }

    if ($script:OwnerCalendarFolderPathSpecified) {
        Write-Host "Receiver [$Identity] accept-log entries for selected owner calendar [$($script:RequestedOwnerCalendarLeafName)] in the last 180 days:"
    } else {
        Write-Host "Receiver [$Identity] has accepted copies of the shared calendar from the following recipients in the last 180 days:"
    }
    # Try to determine date format by examining timestamps (updated to deal with 2/6/2026 5:20:07 PM)
    $culture = [System.Globalization.CultureInfo]::CreateSpecificCulture("en-US")
    foreach ($entry in $csvObject) {
        $timestamp = $entry.Timestamp
        if ([string]::IsNullOrEmpty($timestamp)) { continue }

        $monthOrDay = $timestamp.Split(" ")[0]
        if ([string]::IsNullOrEmpty($monthOrDay)) { continue }

        $firstValue = $monthOrDay.Split("/")[0]
        if ([string]::IsNullOrEmpty($firstValue)) { continue }

        $valueToTest = 0
        if ([int]::TryParse($firstValue, [ref]$valueToTest)) {
            if ($valueToTest -gt 12) {
                Write-Verbose "Looks like European DateTime Format - dd/MM/yyyy HH:mm:ss"
                $culture = [System.Globalization.CultureInfo]::CreateSpecificCulture("en-GB")
                break
            }
        }
    }

    try {
        $displayCsvObject | Where-Object { [DateTime]::Parse($_.Timestamp, $culture) -gt (Get-Date).AddDays(-180) } | Format-Table -a Timestamp, SharedCalendarOwner, FolderName
    } catch {
        $errorInfo = ConvertTo-SharingErrorInfo -ErrorRecord $_
        $script:EvaluationErrors.Add([PSCustomObject]@{
                evaluation = "Receiver accept-log timestamp parsing"
                error      = $errorInfo
            })
        Write-Error "Error parsing dates in the log entries.  Outputting all entries without date filtering."
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "Accept-log timestamps could not be parsed." -Evidence $_.Exception.Message -RecommendedNextStep "Inspect the raw AcceptCalendarSharingInvite logs and their timestamp culture." -Incomplete
        $displayCsvObject |  Format-Table -a Timestamp, SharedCalendarOwner, FolderName
    }
}

<#
.SYNOPSIS
    Formats the InternetCalendar logs from Export-MailboxDiagnosticLogs for a given identity.
.DESCRIPTION
    This function processes calendar sharing invite logs.
.PARAMETER Identity
    The SMTP Address for which to process calendar sharing accept logs.
#>
function ProcessInternetCalendarLogs {
    param (
        [string]$Identity
    )

    $script:ReceiverInternetCalendarEntries = @()

    # Define the header row
    $header = "Timestamp", "Mailbox", "SyncDetails", "PublishingUrl", "RemoteFolderName", "LocalFolderId", "Folder"

    $csvString = @()
    $csvString = $header -join ","
    $csvString += "`n"

    $logOutput = $null
    try {
        # Call the Export-MailboxDiagnosticLogs cmdlet and store the output in a variable
        # -ErrorAction is not supported on Export-MailboxDiagnosticLogs
        # $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName AcceptCalendarSharingInvite -ErrorAction SilentlyContinue
        $logOutput = Invoke-SharingCollector -Name "InternetCalendar" -Action {
            Export-MailboxDiagnosticLogs -Identity $Identity -ComponentName InternetCalendar
        }
    } catch {
        Write-Warning "No InternetCalendar logs found for [$Identity]."
        Add-SharingFinding -Severity Warning -Area "InternetCalendar" -Issue "The published-calendar log check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Collect InternetCalendar logs if published-calendar behavior must be investigated." -Incomplete
        return
    }

    # check if the output is empty
    if ($null -eq $logOutput.MailboxLog) {
        $script:CollectorStatuses["InternetCalendar"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host -ForegroundColor Green "No InternetCalendar Logs found for [$Identity]."
        Write-Host -ForegroundColor Green "User [$Identity] is not receiving any Published Calendars."
        return
    }

    # Split the output into an array of lines
    $logLines = $logOutput.MailboxLog -split "`r`n"

    # Loop through each line of the output
    foreach ($line in $logLines) {
        if ($line -like "*Entry Sync Details for InternetCalendar subscription DataType=calendar*") {
            $csvString += $line + "`n"
        }
    }
    if ($csvString -eq (($header -join ",") + "`n")) {
        $script:CollectorStatuses["InternetCalendar"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host -ForegroundColor Green "No InternetCalendar subscription entries found for [$Identity]."
        return
    }

    # Clean up output
    $csvString = $csvString.Replace("Mailbox: ", "")
    $csvString = $csvString.Replace("Entry Sync Details for InternetCalendar subscription DataType=calendar", "InternetCalendar")
    $csvString = $csvString.Replace("PublishingUrl=", "")
    $csvString = $csvString.Replace("RemoteFolderName=", "")
    $csvString = $csvString.Replace("LocalFolderId=", "")
    $csvString = $csvString.Replace("folder ", "")

    # Convert the CSV string to an object
    $csvObject = Invoke-SharingEvaluation -Name "InternetCalendar log parsing" -RuleIds @("SHR420") -Action {
        $csvString | ConvertFrom-Csv
    }
    if ($null -eq $csvObject) {
        Add-SharingFinding -Severity Warning -Area "InternetCalendar" -Issue "The published-calendar log check was unavailable." -Evidence "InternetCalendar data could not be parsed." -RecommendedNextStep "Inspect the raw InternetCalendar logs." -Incomplete
        return
    }

    # Clean up the Folder column
    foreach ($row in $csvObject) {
        $row.Folder = $row.Folder.Split("with")[0]
    }
    $script:ReceiverInternetCalendarEntries = @($csvObject)

    Write-Host -ForegroundColor Cyan "Receiver [$Identity] is/was receiving the following Published Calendars:"
    $csvObject | Sort-Object -Unique RemoteFolderName | Format-Table -a RemoteFolderName, Folder, PublishingUrl
}

<#
.SYNOPSIS
    Display Calendar Owner information.
.DESCRIPTION
    This function displays key Calendar Owner information.
.PARAMETER Identity
    The SMTP Address for Owner of the shared calendar.
#>
function GetOwnerInformation {
    param (
        [string]$Owner
    )

    if ($null -ne $script:FatalPrerequisiteFailure) {
        return
    }
    if (($null -eq $script:OwnerMB) -and
        (-not (Resolve-SharingMailboxPrerequisite -Role Owner -Identity $Owner))) {
        return
    }
    if ((($null -eq $script:OwnerSelectedCalendar) -or
            ($null -eq $script:OwnerCalendarFolder)) -and
        (-not (Resolve-OwnerCalendarPrerequisite))) {
        return
    }

    #Standard Owner information
    Write-Host -ForegroundColor DarkYellow "------------------------------------------------"
    Write-Host -ForegroundColor DarkYellow "Key Owner Mailbox Information:"
    Write-Host -ForegroundColor DarkYellow "`t Using prerequisite result from 'Get-Mailbox $Owner'"

    $script:OwnerMB | Format-List DisplayName, Database, ServerName, LitigationHoldEnabled, CalendarVersionStoreDisabled, CalendarRepairDisabled, RecipientType*

    Write-Host -ForegroundColor DarkYellow "Send on Behalf Granted to :"
    foreach ($del in $($script:OwnerMB.GrantSendOnBehalfTo)) {
        Write-Host -ForegroundColor Blue "`t$($del)"
    }
    Write-Host "`n`n`n"

    if ($script:OwnerMB.DisplayName -like "Redacted*") {
        Write-Host -ForegroundColor Yellow "Do Not have PII information for the Owner."
        Write-Host -ForegroundColor Yellow "Get PII Access for $($script:OwnerMB.Database)."
        $script:PIIAccess = $false
        Add-SharingFinding -Severity Warning -Area "PII access" -Issue "Owner PII was redacted, limiting pair-specific checks." -Evidence "The owner DisplayName begins with Redacted." -RecommendedNextStep "Obtain PII access for the owner mailbox database and rerun the pair diagnostics." -Incomplete
    }

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Folder Statistics:"
    $OwnerCalendarStats = @($script:OwnerCalendarStats)
    $ownerCalendarStat = $script:OwnerSelectedCalendar

    $OwnerCalendarStats | Format-Table -a FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize
    $ownerDuplicateStyleFolders = Get-DuplicateStyleCalendarFolders -FolderStatistics $OwnerCalendarStats
    if ($ownerDuplicateStyleFolders.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "Warning: Owner calendar folders ending in a one- or two-digit numeric suffix may be duplicate folders."
        $ownerDuplicateStyleFolders |
            Format-Table -AutoSize FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize
        Add-SharingFinding -RuleId "SHR112" -Status Detected -Area "Owner calendar naming" -Evidence @{
            folderCount = $ownerDuplicateStyleFolders.Count
            folderNames = @($ownerDuplicateStyleFolders.Name)
        }
    }

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Permissions:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxFolderPermission `"$($script:OwnerCalendarFolderIdentity)`" | Format-Table -a User, AccessRights, SharingPermissionFlags'"
    try {
        $script:OwnerCalendarPerms = @(Invoke-SharingCollector -Name "OwnerCalendarPermissions" -Action {
                @(Get-MailboxFolderPermission -Identity $script:OwnerCalendarFolderIdentity -ErrorAction Stop)
            } -AllowNull)
        $script:OwnerCalendarPermsAvailable = $true
    } catch {
        $script:OwnerCalendarPerms = @()
        $script:OwnerCalendarPermsAvailable = $false
        Write-Warning "Failed to retrieve Owner Calendar permissions for [$Owner]: $($_.Exception.Message)"
        Add-SharingFinding -Severity Warning -Area "Owner calendar permissions" -Issue "The pair-specific permission check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-MailboxFolderPermission with sufficient access and compare the result with active-sharing and receiver-folder data." -Incomplete
    }
    $script:OwnerCalendarPerms | Format-Table -a User, AccessRights, SharingPermissionFlags

    # Warn if the size is greater than 1 GB.
    $folderSizeBytes = $null
    try {
        if ($null -ne $ownerCalendarStat.FolderSize.Value -and
            $null -ne $ownerCalendarStat.FolderSize.Value.PSObject.Methods["ToBytes"]) {
            $folderSizeBytes = [int64]$ownerCalendarStat.FolderSize.Value.ToBytes()
        } elseif ([string]$ownerCalendarStat.FolderSize -match "\((?<Bytes>[\d,\.\s]+)\s+bytes\)") {
            $numericBytes = $Matches["Bytes"] -replace "\D", ""
            $parsedBytes = [int64]0
            if ([int64]::TryParse($numericBytes, [ref]$parsedBytes)) {
                $folderSizeBytes = $parsedBytes
            }
        }
    } catch {
        Write-Verbose "Owner calendar size could not be converted to bytes."
    }
    if ($null -eq $folderSizeBytes) {
        Add-SharingFinding -RuleId "SHR430" -Status NotEvaluated -Evidence @{
            reason = "Folder size could not be converted to bytes."
        }
    } elseif ($folderSizeBytes -gt 1000000000) {
        Write-Host -ForegroundColor Yellow "Warning: Owner Calendar size is greater than 1 GB. This can impact calendar performance."
        Write-Host -ForegroundColor Yellow "`t Consider archiving old calendar items or reducing the size of attachments in calendar items."
        Add-SharingFinding -RuleId "SHR430" -Status Detected -Evidence @{
            folderSizeBytes = $folderSizeBytes
            thresholdBytes  = 1000000000
        }
    }

    # Warn if the Calendar count is greater than 100,000 items
    $visibleItemCount = [int64]0
    $visibleItemCountAvailable = [int64]::TryParse(
        [string]$ownerCalendarStat.VisibleItemsInFolder,
        [ref]$visibleItemCount)
    if (-not $visibleItemCountAvailable) {
        Add-SharingFinding -RuleId "SHR431" -Status NotEvaluated -Evidence @{
            reason = "Visible item count could not be converted to an integer."
        }
    } elseif ($visibleItemCount -gt 100000) {
        Write-Host -ForegroundColor Yellow "Warning: Owner Calendar has more than 100,000 items. This can impact calendar performance."
        Write-Host -ForegroundColor Yellow "`t Consider archiving old calendar items."
        Add-SharingFinding -RuleId "SHR431" -Status Detected -Evidence @{
            visibleItemCount = $visibleItemCount
            thresholdCount   = 100000
        }
    }

    Write-Host -ForegroundColor DarkYellow "Owner Root Mailbox Permissions:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxPermission $Owner | Format-Table -a User, AccessRights, SharingPermissionFlags'"
    try {
        $script:OwnerMailboxPerms = @(Invoke-SharingCollector -Name "OwnerMailboxPermissions" -Action {
                @(Get-MailboxPermission -Identity $Owner -ErrorAction Stop)
            } -AllowNull)
        $script:OwnerMailboxPermsAvailable = $true
        $script:OwnerMailboxPerms | Format-Table -a User, AccessRights, SharingPermissionFlags
    } catch {
        $script:OwnerMailboxPerms = @()
        $script:OwnerMailboxPermsAvailable = $false
        Write-Warning "Failed to retrieve Owner mailbox permissions for [$Owner]: $($_.Exception.Message)"
        Add-SharingFinding -Severity Warning -Area "Owner mailbox permissions" -Issue "The owner mailbox-permission check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-MailboxPermission with sufficient access." -Incomplete
    }
    Write-OwnerReceiverPermissionSummary -Receiver $Receiver

    Write-Host -ForegroundColor DarkYellow "Owner Modern Sharing Sent Invites"
    ProcessCalendarSharingInviteLogs -Identity $Owner

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Folder Information:"
    Write-Host -ForegroundColor DarkYellow "`t Using prerequisite result from 'Get-MailboxCalendarFolder `"$($script:OwnerCalendarFolderIdentity)`"'"
    $OwnerCalendarFolder = $script:OwnerCalendarFolder
    $OwnerCalendarFolder |
        Format-List Identity, CreationTime, PublishEnabled, PublishedCalendarUrl, PublishedICalUrl, ExtendedFolderFlags
    if ($OwnerCalendarFolder.PublishEnabled) {
        Write-Host -ForegroundColor Green "Owner Calendar is Published."
        $script:OwnerPublished = $true
        $script:OwnerPublishedICalUrl = [string]$OwnerCalendarFolder.PublishedICalUrl
    } else {
        Write-Host -ForegroundColor Yellow "Owner Calendar is not Published."
        $script:OwnerPublished = $false
        $script:OwnerPublishedICalUrl = $null
    }

    $ownerExtendedFolderFlags = ConvertTo-NormalizedFolderFlags -Flags @($OwnerCalendarFolder.ExtendedFolderFlags)
    Write-Host -ForegroundColor DarkYellow "`t ExtendedFolderFlags: $($ownerExtendedFolderFlags)"
    if ($ownerExtendedFolderFlags -contains "SharedOut") {
        Write-Host -ForegroundColor Green "Owner Calendar is Shared Out using Modern Sharing."
        $script:OwnerModernSharing = $true
    } else {
        Write-Host -ForegroundColor Yellow "Owner Calendar is not Shared Out."
        $script:OwnerModernSharing = $false
        Add-SharingFinding -Severity Error -Area "Owner calendar flags" -Issue "The owner calendar is missing SharedOut." -Evidence "ExtendedFolderFlags: [$($ownerExtendedFolderFlags -join ', ')]." -RecommendedNextStep "Run the SharingPolicyAssistant or calendar-sharing validator diagnostics and inspect invite processing."
    }
    if ($ownerExtendedFolderFlags -notcontains "ExchangeShareFolder") {
        Write-Host -ForegroundColor Yellow "Owner Calendar is missing the ExchangeShareFolder flag."
        Add-SharingFinding -Severity Error -Area "Owner calendar flags" -Issue "The owner calendar is missing ExchangeShareFolder." -Evidence "ExtendedFolderFlags: [$($ownerExtendedFolderFlags -join ', ')]." -RecommendedNextStep "Run the SharingPolicyAssistant or calendar-sharing validator diagnostics and inspect invite processing."
    }

    # cSpell:ignore Sharee Sharees
    if (Get-Command -Name Get-CalendarActiveSharingInformation -ErrorAction SilentlyContinue) {
        Write-Host -ForegroundColor DarkYellow "`t Running 'Get-CalendarActiveSharingInformation -Identity `"$($script:OwnerCalendarFolderIdentity)`"'"
        try {
            $OwnerActiveSharingInfo = Invoke-SharingCollector -Name "ActiveSharing" -Action {
                Get-CalendarActiveSharingInformation -Identity $script:OwnerCalendarFolderIdentity -ErrorAction Stop
            }
        } catch {
            Write-Warning "Failed to retrieve active sharing information for [$Owner]: $($_.Exception.Message)"
            Add-SharingFinding -Severity Warning -Area "Active sharing information" -Issue "The active-sharing relationship check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-CalendarActiveSharingInformation and inspect SharingPolicyAssistant or validator diagnostics." -Incomplete
            $OwnerActiveSharingInfo = $null
        }
        if ($null -eq $OwnerActiveSharingInfo) {
            $script:CollectorStatuses["ActiveSharing"] = [PSCustomObject]@{ status = "NoData"; error = $null }
            Add-SharingFinding -Severity Warning -Area "Active sharing information" -Issue "The active-sharing relationship check returned no data." -Evidence "Get-CalendarActiveSharingInformation returned no object for [$Owner]." -RecommendedNextStep "Rerun Get-CalendarActiveSharingInformation and inspect SharingPolicyAssistant or validator diagnostics." -Incomplete
            Write-Host -ForegroundColor DarkYellow "`n`n`n------------------------------------------------"
            return
        }
        $script:OwnerActiveSharingAvailable = $true
        if ($OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees.count -gt 0) {
            Write-Host -ForegroundColor Green "`t Calendar has [$($OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees.count)] Active Receivers."
            $receivers = $OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees | ForEach-Object {
                [PSCustomObject]@{
                    EmailAddress          = $_.EmailAddress
                    SharingPermissionFlag = ($_.SharingPermissionFlags -join ",")
                    ActiveShareeFlags     = ($_.ActiveShareeFlags -join ",")
                    LastSyncTime          = $_.LastSyncTime
                }
            }
            Write-Host -ForegroundColor DarkYellow "Look for the Receiver [$Receiver] in the list of Active Receivers."

            $receivers | Format-Table -AutoSize EmailAddress, SharingPermissionFlag, ActiveShareeFlags, LastSyncTime
        } else {
            Write-Host -ForegroundColor Yellow "`t Calendar has no Active Receivers according to Get-CalendarActiveSharingInformation."
        }
        $script:OwnerActiveReceiver = @($OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees | Where-Object -FilterScript {
                Test-SmtpAddressEqual -First $_.EmailAddress -Second $Receiver
            }) | Select-Object -First 1
        if ($null -eq $script:OwnerActiveReceiver) {
            Add-SharingFinding -Severity Error -Area "Active sharing information" -Issue "The expected receiver is absent from the owner's active-sharing relationships." -Evidence "Get-CalendarActiveSharingInformation did not contain [$Receiver]." -RecommendedNextStep "Inspect invite/accept logs and run SharingPolicyAssistant or calendar-sharing validator diagnostics."
        } else {
            $activeShareeFlags = @($script:OwnerActiveReceiver.ActiveShareeFlags)
            $nonDefaultActiveShareeFlags = @($activeShareeFlags | Where-Object -FilterScript {
                    (-not [string]::IsNullOrWhiteSpace($_)) -and ($_ -ne "None")
                })
            if ($nonDefaultActiveShareeFlags.Count -gt 0) {
                Add-SharingFinding -Severity Warning -Area "Active sharing information" -Issue "The expected receiver has non-None ActiveShareeFlags." -Evidence "ActiveShareeFlags: [$($activeShareeFlags -join ', ')]." -RecommendedNextStep "Inspect SharingPolicyAssistant and calendar-sharing validator diagnostics for the pair."
            }
        }
    } else {
        $script:CollectorStatuses["ActiveSharing"] = [PSCustomObject]@{ status = "Unavailable"; error = $null }
        Add-SharingFinding -Severity Warning -Area "Active sharing information" -Issue "Get-CalendarActiveSharingInformation is unavailable." -Evidence "The cmdlet was not found in the current session." -RecommendedNextStep "Run the check in a session where Get-CalendarActiveSharingInformation is available." -Incomplete
    }
    Write-Host -ForegroundColor DarkYellow "`n`n`n------------------------------------------------"
}

<#
.SYNOPSIS
    Displays key information from the receiver of the shared Calendar.
.DESCRIPTION
    This function displays key Calendar Receiver information.
.PARAMETER Identity
    The SMTP Address for Receiver of the shared calendar.
#>
function GetReceiverInformation {
    param (
        [string]$Receiver
    )

    if ($null -ne $script:FatalPrerequisiteFailure) {
        return
    }
    if (($null -eq $script:ReceiverMB) -and
        (-not (Resolve-SharingMailboxPrerequisite -Role Receiver -Identity $Receiver))) {
        return
    }

    #Standard Receiver information
    Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
    Write-Host -ForegroundColor Cyan "Key Receiver MB Information: [$Receiver]"
    Write-Host -ForegroundColor Cyan "Using prerequisite result from: 'Get-Mailbox $Receiver'"

    $script:ReceiverMB | Format-List DisplayName, Database, LitigationHoldEnabled, CalendarVersionStoreDisabled, CalendarRepairDisabled, RecipientType*

    if (($null -ne $script:OwnerMB) -and
        ($script:OwnerMB.OrganizationalUnitRoot -eq $script:ReceiverMB.OrganizationalUnitRoot)) {
        Write-Host -ForegroundColor Yellow "Owner and Receiver are in the same OU."
        Write-Host -ForegroundColor Yellow "Owner and Receiver will be using Internal Sharing."
        $script:SharingType = "InternalSharing"
    } else {
        Write-Host -ForegroundColor Yellow "Owner and Receiver are in different OUs."
        Write-Host -ForegroundColor Yellow "Owner and Receiver will be using External Sharing or Publishing."
        $script:SharingType = "ExternalSharing"
    }

    $OwnerCalendarName = $($script:OwnerMB.DisplayName)
    $selectedOwnerCalendarName = if ($script:OwnerCalendarFolderPathSpecified) {
        $script:RequestedOwnerCalendarLeafName
    } else {
        $OwnerCalendarName
    }
    Write-Host -ForegroundColor Cyan "Receiver Calendar Folders (look for a copy of [$selectedOwnerCalendarName] Calendar):"
    Write-Host -ForegroundColor Cyan "Running: 'Get-MailboxFolderStatistics -Identity $Receiver -FolderScope Calendar'"
    $receiverFolderStatsAvailable = $true
    try {
        $CalStats = @(Invoke-SharingCollector -Name "ReceiverFolderStatistics" -Action {
                @(Get-MailboxFolderStatistics -Identity $Receiver -FolderScope Calendar -ErrorAction Stop)
            } -AllowNull)
    } catch {
        Write-Warning "Failed to retrieve Receiver Calendar folder statistics for [$Receiver]: $($_.Exception.Message)"
        Add-SharingFinding -Severity Warning -Area "Receiver calendar folders" -Issue "The receiver local-folder checks were unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-MailboxFolderStatistics with sufficient access, then compare Get-CalendarEntries and invite/accept logs." -Incomplete
        $CalStats = @()
        $receiverFolderStatsAvailable = $false
    }
    $CalStats | Format-Table -a FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize
    $receiverDuplicateStyleFolders = Get-DuplicateStyleCalendarFolders -FolderStatistics $CalStats
    if ($receiverDuplicateStyleFolders.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "Warning: Receiver calendar folders ending in a one- or two-digit numeric suffix may be duplicate folders."
        $receiverDuplicateStyleFolders |
            Format-Table -AutoSize FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize
        Add-SharingFinding -RuleId "SHR214" -Status Detected -Area "Receiver calendar naming" -Evidence @{
            folderCount = $receiverDuplicateStyleFolders.Count
            folderNames = @($receiverDuplicateStyleFolders.Name)
        }
    }
    $receiverCalendarFolderNamesRedacted = @($CalStats | Where-Object -FilterScript {
            ([string]$_.Name -match "^\s*REDACTED-") -or
            ([string]$_.FolderPath -match "^\s*[\\/]*\s*REDACTED-")
        }).Count -gt 0
    if ($receiverCalendarFolderNamesRedacted) {
        Write-Host -ForegroundColor Yellow "Cannot read [$selectedOwnerCalendarName] calendar folder names. Get more access."
        $script:PIIAccess = $false
        Add-SharingFinding -RuleId "SHR201" -Status Detected -Area "PII access" -Evidence @{
            reason = "Receiver calendar folder names are redacted."
        }
    }
    $receiverDefaultCalendar = $CalStats |
        Where-Object -Property FolderType -EQ "Calendar" |
        Select-Object -First 1
    $ReceiverCalendarName = $receiverDefaultCalendar.Name
    if ($receiverFolderStatsAvailable -and ($null -eq $receiverDefaultCalendar)) {
        Add-SharingFinding -RuleId "SHR201" -Status NotEvaluated -Evidence @{
            reason = "The receiver default calendar could not be identified."
        }
    }

    if ($script:OwnerCalendarFolderPathSpecified) {
        $requestedRelativeFolderPath = if (-not [string]::IsNullOrWhiteSpace($script:NormalizedOwnerCalendarFolderPath)) {
            $requestedFolderSegments = @($script:NormalizedOwnerCalendarFolderPath.TrimStart("\").Split("\"))
            @($requestedFolderSegments | Select-Object -Skip 1) -join "\"
        } else {
            $selectedOwnerCalendarName
        }
        $expectedReceiverFolderPath = if ([string]::IsNullOrWhiteSpace($requestedRelativeFolderPath)) {
            "\$ReceiverCalendarName"
        } else {
            "\$ReceiverCalendarName\$requestedRelativeFolderPath"
        }
        $matchingOwnerCalendars = @($CalStats | Where-Object -FilterScript {
                $calendarName = [string]$_.Name
                $receiverStatisticsPath = if ((-not [string]::IsNullOrWhiteSpace($ReceiverCalendarName)) -and
                    ($null -ne $_.FolderPath)) {
                    $receiverStatisticsIdentity = Get-CanonicalMailboxFolderIdentity `
                        -Mailbox $Receiver `
                        -CalendarRootName $ReceiverCalendarName `
                        -FolderPath $_.FolderPath.ToString()
                    $receiverStatisticsIdentity.Substring($receiverStatisticsIdentity.IndexOf(":") + 1)
                } else {
                    $null
                }
                [string]::Equals(
                    $calendarName,
                    $selectedOwnerCalendarName,
                    [System.StringComparison]::OrdinalIgnoreCase) -or
                [string]::Equals(
                    $receiverStatisticsPath,
                    $expectedReceiverFolderPath,
                    [System.StringComparison]::OrdinalIgnoreCase) -or
                $calendarName -match "^$([regex]::Escape($selectedOwnerCalendarName))\s+\(\d{1,2}\)$"
            })
        $exactSelectedOwnerCalendars = @($matchingOwnerCalendars | Where-Object -FilterScript {
                $receiverStatisticsPath = if ((-not [string]::IsNullOrWhiteSpace($ReceiverCalendarName)) -and
                    ($null -ne $_.FolderPath)) {
                    $receiverStatisticsIdentity = Get-CanonicalMailboxFolderIdentity `
                        -Mailbox $Receiver `
                        -CalendarRootName $ReceiverCalendarName `
                        -FolderPath $_.FolderPath.ToString()
                    $receiverStatisticsIdentity.Substring($receiverStatisticsIdentity.IndexOf(":") + 1)
                } else {
                    $null
                }
                ([string]::Equals(
                    $_.Name,
                    $selectedOwnerCalendarName,
                    [System.StringComparison]::OrdinalIgnoreCase)) -or
                ([string]::Equals(
                    $receiverStatisticsPath,
                    $expectedReceiverFolderPath,
                    [System.StringComparison]::OrdinalIgnoreCase))
            })
    } else {
        $ownerNames = @($Owner, $script:OwnerMB.DisplayName) | Where-Object -FilterScript {
            -not [string]::IsNullOrWhiteSpace($_)
        }
        $matchingOwnerCalendars = @($CalStats | Where-Object -FilterScript {
                $calendarName = $_.Name
                foreach ($ownerName in $ownerNames) {
                    if ($calendarName -like "$([WildcardPattern]::Escape($ownerName))*") {
                        return $true
                    }
                }
                return $false
            })
        $exactSelectedOwnerCalendars = @()
    }
    $script:ReceiverCalendarCandidates = $matchingOwnerCalendars
    if ($exactSelectedOwnerCalendars.Count -eq 1) {
        $script:ReceiverMatchedCalendar = $exactSelectedOwnerCalendars[0]
    } elseif ($matchingOwnerCalendars.Count -eq 1) {
        $script:ReceiverMatchedCalendar = $matchingOwnerCalendars[0]
    }

    # Warning if there are multiple copies of the Owner Calendar in the Receiver Mailbox.
    if ($matchingOwnerCalendars.Count -gt 1) {
        if ($script:OwnerCalendarFolderPathSpecified) {
            Write-Host -ForegroundColor Yellow "Warning: Might have found more than one copy of the selected Owner Calendar [$selectedOwnerCalendarName] in the Receiver Mailbox."
        } else {
            Write-Host -ForegroundColor Yellow "Warning: Might have found more than one copy of the Owner Calendar in the Receiver Mailbox."
        }
        Add-SharingFinding -Severity Warning -Area "Receiver calendar folders" -Issue "Multiple local folders may represent the owner's shared calendar." -Evidence "Matched [$($matchingOwnerCalendars.Count)] folders: [$($matchingOwnerCalendars.Name -join ', ')]." -RecommendedNextStep "Compare Get-CalendarEntries, folder identifiers, and invite/accept logs to identify the active pair-specific folder."
    }

    # Warning if the Receivers copy of the Calendar name is the default "Calendar".
    if (($CalStats.name -like "Calendar*").count -gt 1) {
        Write-Host -ForegroundColor Yellow "Warning: Receiver might have multiple Calendars named 'Calendar'."
        Write-Host -ForegroundColor Yellow "Warning: This can cause confusion with which calendar is being referenced."
        Add-SharingFinding -Severity Warning -Area "Receiver calendar naming" -Issue "The receiver has multiple calendars whose names begin with Calendar." -Evidence "Folder statistics returned more than one matching folder." -RecommendedNextStep "Use folder identifiers and Get-CalendarEntries to distinguish the shared folder during further diagnostics."
    }

    # Note $Owner has a * at the end in case we have had multiple setup for the same user, they will be appended with a " 1", etc.
    if ($matchingOwnerCalendars.Count -gt 0) {
        if ($script:OwnerCalendarFolderPathSpecified) {
            Write-Host -ForegroundColor Green "Looks like we might have found a copy of the selected Owner Calendar [$selectedOwnerCalendarName] in the Receiver Mailbox."
        } else {
            Write-Host -ForegroundColor Green "Looks like we might have found a copy of the Owner Calendar in the Receiver Mailbox."
        }
        Write-Host -ForegroundColor Green "This is a good indication the there is a Modern Sharing Relationship between these users."
        Write-Host -ForegroundColor Green "If the clients use the Modern Sharing or not is a up to the client."
        $script:ModernSharing = $true

        $matchingOwnerCalendars | Format-Table -a FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize
        if ($matchingOwnerCalendars.Count -gt 1) {
            Write-Host -ForegroundColor Yellow "Warning: Might have found more than one copy of the Owner Calendar in the Receiver Mailbox."
        }
    } else {
        if ($receiverCalendarFolderNamesRedacted) {
            Write-Verbose "Receiver calendar folder matching was skipped because folder names are redacted."
        } else {
            Write-Verbose "No receiver local folder was matched before calendar-entry evaluation."
        }
    }

    ProcessCalendarSharingAcceptLogs -Identity $Receiver
    if ($script:OwnerPublished) {
        ProcessInternetCalendarLogs -Identity $Receiver
    }

    if (($script:SharingType -like "InternalSharing") -or
        ($script:SharingType -like "ExternalSharing")) {
        # Validate Modern Sharing Status
        if (Get-Command -Name Get-CalendarEntries -ErrorAction SilentlyContinue) {
            Write-Verbose "Found Get-CalendarEntries cmdlet. Running cmdlet: Get-CalendarEntries -Identity $Receiver"
            $calendarEntriesAvailable = $true
            try {
                $ReceiverCalEntries = @(Invoke-SharingCollector -Name "CalendarEntries" -Action {
                        @(Get-CalendarEntries -Identity $Receiver -ErrorAction Stop)
                    } -AllowNull)
            } catch {
                Write-Warning "Failed to retrieve calendar entries for [$Receiver]: $($_.Exception.Message)"
                Add-SharingFinding -Severity Warning -Area "Calendar entries" -Issue "The receiver calendar-entry check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-CalendarEntries with sufficient access and inspect the owner/receiver pair." -Incomplete
                $ReceiverCalEntries = @()
                $calendarEntriesAvailable = $false
            }

            Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
            Write-Host "New Model Calendar Sharing Entries:"
            $ReceiverCalEntries | Where-Object SharingModelType -Like New | Format-Table CalendarGroupName, CalendarName, OwnerEmailAddress, SharingModelType, IsOrphanedEntry
            $pairNewEntries = @($ReceiverCalEntries | Where-Object -FilterScript {
                    ($_.SharingModelType -like "New") -and
                    (Test-SmtpAddressEqual -First $_.OwnerEmailAddress -Second $Owner) -and
                    ((-not $script:OwnerCalendarFolderPathSpecified) -or
                    [string]::Equals(
                        $_.CalendarName,
                        $selectedOwnerCalendarName,
                        [System.StringComparison]::OrdinalIgnoreCase))
                })
            if ($pairNewEntries.Count -gt 0) {
                $pairCalendarNames = @($pairNewEntries.CalendarName | Where-Object -FilterScript {
                        -not [string]::IsNullOrWhiteSpace($_)
                    })
                $entryFolderMatches = @($CalStats | Where-Object -FilterScript {
                        $receiverFolderName = $_.Name
                        @($pairCalendarNames | Where-Object -FilterScript {
                                [string]::Equals(
                                    $receiverFolderName,
                                    $_,
                                    [System.StringComparison]::OrdinalIgnoreCase)
                            }).Count -gt 0
                    })
                if ($entryFolderMatches.Count -eq 1) {
                    $script:ReceiverMatchedCalendar = $entryFolderMatches[0]
                    $script:ReceiverCalendarCandidates = @($entryFolderMatches[0])
                    $script:ModernSharing = $true
                }
            }
            foreach ($pairNewEntry in $pairNewEntries) {
                if ($pairNewEntry.IsOrphanedEntry -eq $true) {
                    Add-SharingFinding -Severity Error -Area "Calendar entries" -Issue "The pair-specific new-model calendar entry is orphaned." -Evidence "Calendar [$($pairNewEntry.CalendarName)] has IsOrphanedEntry=True." -RecommendedNextStep "Run SharingPolicyAssistant or calendar-sharing validator diagnostics and inspect invite/accept processing."
                }
            }

            $pairOldEntries = @($ReceiverCalEntries | Where-Object -FilterScript {
                    ($_.SharingModelType -like "Old") -and
                    (Test-SmtpAddressEqual -First $_.OwnerEmailAddress -Second $Owner) -and
                    ((-not $script:OwnerCalendarFolderPathSpecified) -or
                    [string]::Equals(
                        $_.CalendarName,
                        $selectedOwnerCalendarName,
                        [System.StringComparison]::OrdinalIgnoreCase))
                })
            $matchingPublishedEntries = @()
            if ($script:OwnerPublished -and
                (-not [string]::IsNullOrWhiteSpace($script:OwnerPublishedICalUrl))) {
                $matchingPublishedEntries = @($script:ReceiverInternetCalendarEntries |
                        Where-Object -FilterScript {
                            [string]::Equals(
                                ([string]$_.PublishingUrl).Trim(),
                                $script:OwnerPublishedICalUrl.Trim(),
                                [System.StringComparison]::OrdinalIgnoreCase)
                        })
            }
            $script:PublishedSharing = (
                $script:OwnerPublished -and
                ($pairNewEntries.Count -eq 0) -and
                (($null -eq $script:ReceiverMatchedCalendar) -or
                ($matchingPublishedEntries.Count -gt 0)))
            if ($script:PublishedSharing) {
                $script:ModernSharing = $false
                if ([string]::IsNullOrWhiteSpace($script:OwnerPublishedICalUrl)) {
                    Add-SharingFinding -RuleId "SHR423" -Status Detected -Area "Published calendar" -Evidence @{
                        reason = "PublishEnabled is true, but PublishedICalUrl is unavailable."
                    }
                    foreach ($ruleId in @("SHR421", "SHR422")) {
                        Add-SharingFinding -RuleId $ruleId -Status NotApplicable -Evidence @{
                            reason = "The owner PublishedICalUrl is unavailable."
                        }
                    }
                } elseif (($matchingPublishedEntries.Count -eq 0) -and
                    ($script:CollectorStatuses["InternetCalendar"].status -in @("Success", "NoData"))) {
                    Add-SharingFinding -RuleId "SHR421" -Status Detected -Area "Published calendar" -Evidence @{
                        reason = "No receiver InternetCalendar entry matches the owner PublishedICalUrl."
                    }
                    Add-SharingFinding -RuleId "SHR422" -Status NotApplicable -Evidence @{
                        reason = "No matching receiver published-calendar subscription was found."
                    }
                } else {
                    $script:ReceiverPublishedCalendarEntry = $matchingPublishedEntries |
                        Select-Object -First 1
                    $publishedLocalFolderNames = if (-not [string]::IsNullOrWhiteSpace(
                            [string]$script:ReceiverPublishedCalendarEntry.Folder)) {
                        @(([string]$script:ReceiverPublishedCalendarEntry.Folder).Trim().TrimStart("\", "/"))
                    } elseif (-not [string]::IsNullOrWhiteSpace(
                            [string]$script:ReceiverPublishedCalendarEntry.RemoteFolderName)) {
                        @(([string]$script:ReceiverPublishedCalendarEntry.RemoteFolderName).Trim().TrimStart("\", "/"))
                    } else {
                        @()
                    }
                    $publishedLocalFolderId = [string]$script:ReceiverPublishedCalendarEntry.LocalFolderId
                    $script:ReceiverPublishedCalendarFolder = @($CalStats |
                            Where-Object -FilterScript {
                                $statisticsFolderName = [string]$_.Name
                                $statisticsFolderPath = ([string]$_.FolderPath).Trim().TrimStart("\", "/")
                                if (-not [string]::IsNullOrWhiteSpace($publishedLocalFolderId)) {
                                    return [string]::Equals(
                                        [string]$_.FolderId,
                                        $publishedLocalFolderId,
                                        [System.StringComparison]::OrdinalIgnoreCase)
                                }
                                return @($publishedLocalFolderNames | Where-Object -FilterScript {
                                        [string]::Equals(
                                            $statisticsFolderName,
                                            $_,
                                            [System.StringComparison]::OrdinalIgnoreCase) -or
                                        [string]::Equals(
                                            $statisticsFolderPath,
                                            $_,
                                            [System.StringComparison]::OrdinalIgnoreCase)
                                    }).Count -gt 0
                            }) | Select-Object -First 1
                    if ($null -eq $script:ReceiverPublishedCalendarFolder) {
                        Add-SharingFinding -RuleId "SHR422" -Status Detected -Area "Published calendar" -Evidence @{
                            folderName = $script:ReceiverPublishedCalendarEntry.Folder
                            reason     = "The matching InternetCalendar subscription has no matching receiver calendar folder."
                        }
                    } else {
                        Write-Host -ForegroundColor Green "Receiver published-calendar local folder: [$($script:ReceiverPublishedCalendarFolder.FolderPath)]."
                    }
                }
            }
            $script:LegacyMapiSharing = (
                (-not $script:PublishedSharing) -and
                ($script:SharingType -eq "InternalSharing") -and
                $receiverFolderStatsAvailable -and
                (-not $receiverCalendarFolderNamesRedacted) -and
                $calendarEntriesAvailable -and
                ($pairNewEntries.Count -eq 0) -and
                ((-not $script:OwnerCalendarFolderPathSpecified) -or
                ($pairOldEntries.Count -gt 0)) -and
                ($null -eq $script:ReceiverMatchedCalendar))
            if ($script:LegacyMapiSharing) {
                $legacyEvidence = if ($pairOldEntries.Count -gt 0) {
                    "A pair-specific Old calendar entry was found and no Modern local copy or New entry was identified."
                } else {
                    "No Modern local copy or pair-specific New calendar entry was identified."
                }
                Write-Host -ForegroundColor Yellow "Warning: This internal relationship is using legacy MAPI calendar sharing."
                Write-Host -ForegroundColor Yellow "Microsoft recommends upgrading to Modern Calendar Sharing: https://support.microsoft.com/en-us/outlook/calendar-sharing-in-microsoft-365"
                Add-SharingFinding -RuleId "SHR324" -Status Detected -Area "Sharing model" -Evidence @{
                    reason             = $legacyEvidence
                    oldModelEntryCount = $pairOldEntries.Count
                }
            } elseif ($calendarEntriesAvailable -and ($pairNewEntries.Count -eq 0)) {
                Add-SharingFinding -Severity Error -Area "Calendar entries" -Issue "The pair-specific new-model calendar entry is missing." -Evidence "Get-CalendarEntries returned data but no New entry for owner [$Owner] and selected calendar [$selectedOwnerCalendarName]." -RecommendedNextStep "Inspect invite/accept logs and SharingPolicyAssistant or calendar-sharing validator diagnostics."
            }

            if ($pairOldEntries.Count -gt 0) {
                Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
                Write-Host "Old Model Calendar Sharing Entries:"
                Write-Host "Consider upgrading these to the new model."
                $pairOldEntries | Format-Table CalendarGroupName, CalendarName, OwnerEmailAddress, SharingModelType, IsOrphanedEntry
            }
            if ($pairOldEntries.Count -gt 0) {
                Add-SharingFinding -Severity Warning -Area "Calendar entries" -Issue "A relevant old-model calendar entry exists for the expected owner." -Evidence "Get-CalendarEntries returned [$($pairOldEntries.Count)] Old entry(s) for [$Owner]." -RecommendedNextStep "Inspect invite/accept logs and SharingPolicyAssistant or calendar-sharing validator diagnostics before considering configuration changes."
            }
        } else {
            $script:CollectorStatuses["CalendarEntries"] = [PSCustomObject]@{ status = "Unavailable"; error = $null }
            Add-SharingFinding -Severity Warning -Area "Calendar entries" -Issue "Get-CalendarEntries is unavailable." -Evidence "The cmdlet was not found in the current session." -RecommendedNextStep "Run the check in a session where Get-CalendarEntries is available." -Incomplete
        }

        if ($receiverFolderStatsAvailable -and
            ($null -eq $script:ReceiverMatchedCalendar)) {
            if ($receiverCalendarFolderNamesRedacted) {
                Add-SharingFinding -RuleId "SHR213" -Status NotEvaluated -Evidence @{
                    reason = "Receiver calendar folder names are redacted."
                }
            } elseif ($script:LegacyMapiSharing) {
                Write-Verbose "A local receiver folder is not expected for legacy MAPI calendar sharing."
            } elseif ($script:PublishedSharing) {
                Write-Verbose "Modern Sharing local-folder matching is not applicable to a published-calendar relationship."
            } else {
                if ($script:OwnerCalendarFolderPathSpecified) {
                    Write-Host -ForegroundColor Yellow "Warning: Could not identify the selected Owner Calendar [$selectedOwnerCalendarName] in the Receiver Mailbox."
                } else {
                    Write-Host -ForegroundColor Yellow "Warning: Could not Identify the Owner's [$Owner] Calendar in the Receiver Mailbox."
                }
                Add-SharingFinding -Severity Error -Area "Receiver calendar folders" -Issue "A local folder for the expected owner was not found." -Evidence "Receiver calendar folder statistics and pair-specific calendar entries did not uniquely identify a folder for owner [$Owner]." -RecommendedNextStep "Inspect invite/accept logs and Get-CalendarEntries for the owner/receiver pair."
            }
        }

        if ((-not $script:LegacyMapiSharing) -and
            (-not $script:PublishedSharing)) {
            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $script:OwnerSelectedCalendar `
                -ReceiverFolderStatistics $script:ReceiverMatchedCalendar
        }

        #Output key Modern Sharing information
        if (($script:PIIAccess) -and
            (-not $script:PublishedSharing) -and
            ($null -ne $script:OwnerMB) -and
            ($null -ne $script:ReceiverMatchedCalendar) -and
            (-not [string]::IsNullOrWhiteSpace($ReceiverCalendarName))) {
            if ($script:OwnerCalendarFolderPathSpecified) {
                Write-Host "Checking selected Owner Calendar [$selectedOwnerCalendarName] in the Receiver Calendar:"
            } else {
                Write-Host "Checking for Owner copy Calendar in Receiver Calendar:"
            }
            Write-Host "Running cmdlet:"
            $receiverFolderIdentity = Get-ReceiverFolderIdentity -Receiver $Receiver -ReceiverCalendarName $ReceiverCalendarName -FolderPath $script:ReceiverMatchedCalendar.FolderPath.ToString()
            Write-Host -NoNewline -ForegroundColor Yellow "Get-MailboxCalendarFolder -Identity `"$receiverFolderIdentity`""
            $MBCalFolder = $null
            try {
                $MBCalFolder = Invoke-SharingCollector -Name "ReceiverLocalCalendarFolder" -Action {
                    Get-MailboxCalendarFolder -Identity $receiverFolderIdentity -ErrorAction Stop
                }
                $MBCalFolder | Format-List Identity, CreationTime, ExtendedFolderFlags, CalendarSharingFolderFlags, CalendarSharingOwnerSmtpAddress, CalendarSharingPermissionLevel, SharingLevelOfDetails, SharingPermissionFlags, LastAttemptedSyncTime, LastSuccessfulSyncTime, SharedCalendarSyncStartDate

                $receiverExtendedFolderFlags = ConvertTo-NormalizedFolderFlags -Flags @($MBCalFolder.ExtendedFolderFlags)
                if ($receiverExtendedFolderFlags -notcontains "SharedIn") {
                    Write-Host -ForegroundColor Yellow "Warning: The Receiver's copy of the Owner's Calendar is missing SharedIn."
                    Add-SharingFinding -Severity Error -Area "Receiver calendar flags" -Issue "The receiver local folder is missing SharedIn." -Evidence "ExtendedFolderFlags: [$($receiverExtendedFolderFlags -join ', ')]." -RecommendedNextStep "Run SharingPolicyAssistant or calendar-sharing validator diagnostics for the pair."
                }
                if ($receiverExtendedFolderFlags -notcontains "ExchangeShareFolder") {
                    Write-Host -ForegroundColor Yellow "Warning: The Receiver's copy of the Owner's Calendar is missing ExchangeShareFolder."
                    Add-SharingFinding -Severity Error -Area "Receiver calendar flags" -Issue "The receiver local folder is missing ExchangeShareFolder." -Evidence "ExtendedFolderFlags: [$($receiverExtendedFolderFlags -join ', ')]." -RecommendedNextStep "Run SharingPolicyAssistant or calendar-sharing validator diagnostics for the pair."
                }
                if (-not (Test-SmtpAddressEqual -First $MBCalFolder.CalendarSharingOwnerSmtpAddress -Second $Owner)) {
                    Write-Host -ForegroundColor Red "Warning: CalendarSharingOwnerSmtpAddress does not match the expected Owner."
                    Add-SharingFinding -Severity Error -Area "Receiver calendar owner" -Issue "CalendarSharingOwnerSmtpAddress does not match the expected owner." -Evidence "Expected [$Owner]; found [$($MBCalFolder.CalendarSharingOwnerSmtpAddress)]." -RecommendedNextStep "Compare Get-CalendarEntries and invite/accept logs, then run the calendar-sharing validator."
                }

                $lastAttemptedSyncTime = $MBCalFolder.LastAttemptedSyncTime -as [DateTime]
                $lastSuccessfulSyncTime = $MBCalFolder.LastSuccessfulSyncTime -as [DateTime]
                $attemptedSyncTimeUninitialized = Test-UninitializedCalendarDate -Value $lastAttemptedSyncTime
                $successfulSyncTimeUninitialized = Test-UninitializedCalendarDate -Value $lastSuccessfulSyncTime
                $syncStartDate = $MBCalFolder.SharedCalendarSyncStartDate -as [DateTime]
                $syncStartDateUninitialized = Test-UninitializedCalendarDate -Value $syncStartDate
                $neverSynchronized = $attemptedSyncTimeUninitialized -and $successfulSyncTimeUninitialized

                if ($neverSynchronized) {
                    Write-Host -ForegroundColor Red "The selected receiver calendar appears never to have synchronized. LastAttemptedSyncTime and LastSuccessfulSyncTime contain uninitialized year-1 values."
                    Add-SharingFinding -RuleId "SHR403" -Status Detected -Area "Periodic synchronization" -Evidence @{
                        attemptedSyncTimeUninitialized  = $attemptedSyncTimeUninitialized
                        successfulSyncTimeUninitialized = $successfulSyncTimeUninitialized
                        syncStartDateUninitialized      = $syncStartDateUninitialized
                    }
                    foreach ($ruleId in @("SHR400", "SHR402", "SHR410", "SHR411", "SHR412")) {
                        Add-SharingFinding -RuleId $ruleId -Status NotApplicable -Evidence @{
                            reason = "The selected receiver calendar has never synchronized."
                        }
                    }
                } else {
                    if ($attemptedSyncTimeUninitialized) {
                        $lastAttemptedSyncTime = $null
                    }
                    if ($successfulSyncTimeUninitialized) {
                        $lastSuccessfulSyncTime = $null
                    }
                    $bothSyncTimesStale = ($null -ne $lastAttemptedSyncTime) -and
                    ($null -ne $lastSuccessfulSyncTime) -and
                    ($lastAttemptedSyncTime -lt (Get-Date).AddHours(-24)) -and
                    ($lastSuccessfulSyncTime -lt (Get-Date).AddHours(-24))
                    if ($bothSyncTimesStale) {
                        Write-Host -ForegroundColor Yellow "Warning: Periodic calendar synchronization is stale; both sync timestamps are older than 24 hours."
                        Add-SharingFinding -Severity Warning -Area "Periodic synchronization" -Issue "Periodic synchronization is stale and the assistant may not be running." -Evidence "LastAttemptedSyncTime=[$lastAttemptedSyncTime]; LastSuccessfulSyncTime=[$lastSuccessfulSyncTime]." -RecommendedNextStep "Inspect SharingSyncAssistant logs for the receiver."
                    } elseif (($null -ne $lastAttemptedSyncTime) -and
                        ($null -ne $lastSuccessfulSyncTime) -and
                        ($lastAttemptedSyncTime -eq $lastSuccessfulSyncTime)) {
                        Write-Host -ForegroundColor Green "The Receiver's copy of the Owner's Calendar appears to be syncing properly (LastAttemptedSyncTime = LastSuccessfulSyncTime)."
                    } elseif (($null -eq $lastAttemptedSyncTime) -or ($null -eq $lastSuccessfulSyncTime)) {
                        Write-Host -ForegroundColor Yellow "Warning: Periodic synchronization timestamps are incomplete, so sync state is indeterminate."
                        Add-SharingFinding -Severity Warning -Area "Periodic synchronization" -Issue "Periodic synchronization timestamps are incomplete." -Evidence "LastAttemptedSyncTime=[$($MBCalFolder.LastAttemptedSyncTime)]; LastSuccessfulSyncTime=[$($MBCalFolder.LastSuccessfulSyncTime)]." -RecommendedNextStep "Inspect SharingSyncAssistant logs and rerun the folder diagnostics." -Incomplete
                    } elseif ($lastAttemptedSyncTime -ne $lastSuccessfulSyncTime) {
                        Write-Host -ForegroundColor Red "Warning: The most recent periodic synchronization attempt was not successful (LastAttemptedSyncTime differs from LastSuccessfulSyncTime)."
                        Add-SharingFinding -Severity Error -Area "Periodic synchronization" -Issue "A recent periodic synchronization attempt failed." -Evidence "LastAttemptedSyncTime=[$lastAttemptedSyncTime]; LastSuccessfulSyncTime=[$lastSuccessfulSyncTime]." -RecommendedNextStep "Inspect SharingSyncAssistant logs; use CDL only if meeting-level synchronization requires investigation."
                    }
                }

                if (($null -eq $MBCalFolder.SharedCalendarSyncStartDate) -or $syncStartDateUninitialized) {
                    Write-Host -ForegroundColor Yellow "Warning: The Receiver's copy of the Owner's Calendar does not have an initialized SharedCalendarSyncStartDate."
                    Add-SharingFinding -RuleId "SHR413" -Status Detected -Area "Synchronization start date" -Evidence @{
                        syncStartDateUninitialized = $syncStartDateUninitialized
                    }
                } elseif (-not $neverSynchronized) {
                    $creationTime = $MBCalFolder.CreationTime -as [DateTime]
                    if ($null -ne $syncStartDate) {
                        Write-Host -ForegroundColor Green "The Receiver's copy of the Owner's Calendar should have data back to: $($syncStartDate.ToShortDateString())."
                    } else {
                        Write-Host -ForegroundColor Green "The Receiver's copy of the Owner's Calendar should have data back to: $($MBCalFolder.SharedCalendarSyncStartDate)."
                        Add-SharingFinding -Severity Warning -Area "Synchronization start date" -Issue "SharedCalendarSyncStartDate could not be interpreted as a date." -Evidence "Value: [$($MBCalFolder.SharedCalendarSyncStartDate)]." -RecommendedNextStep "Inspect the raw folder data and SharingSyncAssistant logs." -Incomplete
                    }
                    Write-Host "`t This can be changed with the Set-MailboxCalendarFolder cmdlet."
                    if (($null -ne $syncStartDate) -and
                        ($null -ne $creationTime) -and
                        ($syncStartDate -gt $creationTime)) {
                        Add-SharingFinding -Severity Warning -Area "Synchronization start date" -Issue "SharedCalendarSyncStartDate is later than the local folder CreationTime." -Evidence "SharedCalendarSyncStartDate=[$syncStartDate]; CreationTime=[$creationTime]." -RecommendedNextStep "Inspect invite/accept and SharingSyncAssistant logs to determine whether backfill was restarted."
                    } elseif (($null -ne $syncStartDate) -and ($null -eq $creationTime)) {
                        Add-SharingFinding -RuleId "SHR411" -Status NotEvaluated -Evidence @{
                            reason = "The receiver folder creation time could not be interpreted as a date."
                        }
                    }
                    if (($null -ne $syncStartDate) -and ($syncStartDate -gt (Get-Date).AddHours(-24))) {
                        Add-SharingFinding -Severity Information -Area "Synchronization start date" -Issue "SharedCalendarSyncStartDate is very recent and may reflect backfill or folder recreation context." -Evidence "SharedCalendarSyncStartDate=[$syncStartDate]." -RecommendedNextStep "Correlate invite/accept and SharingSyncAssistant logs before concluding that synchronization failed."
                    }
                }

                $ownerPermission = Get-PermissionEntriesForIdentity `
                    -PermissionEntries $script:OwnerCalendarPerms `
                    -Identity $Receiver |
                    Select-Object -First 1
                if ($script:OwnerCalendarPermsAvailable -and
                    ($null -ne $script:OwnerActiveReceiver) -and
                    ($null -eq $ownerPermission)) {
                    Add-SharingFinding -Severity Error -Area "Pair permission configuration" -Issue "The expected active relationship has no matching owner calendar permission." -Evidence "Active sharing contains [$Receiver], but owner calendar permissions do not." -RecommendedNextStep "Run SharingPolicyAssistant or calendar-sharing validator diagnostics and compare invite/accept logs."
                } elseif ($script:OwnerActiveSharingAvailable -and
                    ($null -ne $ownerPermission) -and
                    ($null -eq $script:OwnerActiveReceiver)) {
                    Add-SharingFinding -Severity Error -Area "Pair permission configuration" -Issue "The owner calendar permission exists but the expected active relationship is absent." -Evidence "Owner permission was found for [$Receiver], but active-sharing information did not contain the receiver." -RecommendedNextStep "Inspect invite/accept logs and run SharingPolicyAssistant or calendar-sharing validator diagnostics."
                }
                $ownerSharingFlags = @($ownerPermission.SharingPermissionFlags) | Where-Object -FilterScript {
                    -not [string]::IsNullOrWhiteSpace($_)
                }
                $receiverSharingFlags = @($MBCalFolder.SharingPermissionFlags) | Where-Object -FilterScript {
                    -not [string]::IsNullOrWhiteSpace($_)
                }
                $activeSharingFlags = @($script:OwnerActiveReceiver.SharingPermissionFlags) | Where-Object -FilterScript {
                    -not [string]::IsNullOrWhiteSpace($_)
                }
                if (($null -ne $ownerPermission) -and
                    ($ownerSharingFlags.Count -gt 0) -and
                    ($receiverSharingFlags.Count -gt 0) -and
                    (($ownerSharingFlags -join ",") -ne ($receiverSharingFlags -join ","))) {
                    Add-SharingFinding -Severity Warning -Area "Pair permission configuration" -Issue "Owner and receiver sharing permission flags differ." -Evidence "Owner flags=[$($ownerSharingFlags -join ', ')]; receiver flags=[$($receiverSharingFlags -join ', ')]." -RecommendedNextStep "Compare the pair configuration with SharingPolicyAssistant or calendar-sharing validator diagnostics."
                }
                if (($null -ne $script:OwnerActiveReceiver) -and
                    ($activeSharingFlags.Count -gt 0) -and
                    ($receiverSharingFlags.Count -gt 0) -and
                    (($activeSharingFlags -join ",") -ne ($receiverSharingFlags -join ","))) {
                    Add-SharingFinding -Severity Warning -Area "Pair permission configuration" -Issue "Active-sharing and receiver-folder permission flags differ." -Evidence "Active relationship flags=[$($activeSharingFlags -join ', ')]; receiver flags=[$($receiverSharingFlags -join ', ')]." -RecommendedNextStep "Compare the pair configuration with SharingPolicyAssistant or calendar-sharing validator diagnostics."
                }
            } catch {
                Write-Error "Failed to get the Owner's Calendar from the Receiver's Mailbox.  This is fine if not using Modern Sharing."
                Add-SharingFinding -Severity Error -Area "Receiver calendar folder" -Issue "The matched receiver calendar folder could not be queried." -Evidence $_.Exception.Message -RecommendedNextStep "Verify the folder identity from folder statistics and inspect Get-CalendarEntries plus invite/accept logs." -Incomplete
            }

            # Collect Sharing related logs for further analysis if needed
            # Need to Document what to look for in these logs before exposing this functionality
            # $SharingLog =  Export-MailboxDiagnosticLogs $Receiver -ComponentName Sharing
            # $SSA = Export-MailboxDiagnosticLogs $Receiver -ComponentName SharingSyncAssistant
            # $SharingValidator = Export-MailboxDiagnosticLogs $Receiver -ComponentName CalendarSharingInconsistencyValidator
            # $SharingRepair = Export-MailboxDiagnosticLogs $Receiver -ComponentName CalendarSharingInconsistencyRepair
        } else {
            if ($script:PublishedSharing) {
                $script:CollectorStatuses["ReceiverLocalCalendarFolder"] = [PSCustomObject]@{ status = "NotApplicable"; error = $null }
                Write-Host -ForegroundColor Yellow "Published calendar subscriptions use their InternetCalendar local folder and do not use Modern Sharing local-folder checks."
            } elseif ($script:LegacyMapiSharing) {
                $script:CollectorStatuses["ReceiverLocalCalendarFolder"] = [PSCustomObject]@{ status = "NotApplicable"; error = $null }
                Write-Host -ForegroundColor Yellow "Legacy MAPI access uses the owner calendar permissions and does not create a Modern Sharing local folder in the receiver mailbox."
            } else {
                $script:CollectorStatuses["ReceiverLocalCalendarFolder"] = [PSCustomObject]@{ status = "NotEvaluated"; error = $null }
            }
            if ((-not $receiverCalendarFolderNamesRedacted) -and
                (-not $script:LegacyMapiSharing) -and
                (-not $script:PublishedSharing)) {
                if ($script:PIIAccess) {
                    Write-Host -ForegroundColor Yellow "A uniquely matched Modern Sharing local folder was not identified, so receiver local-folder checks cannot run."
                } else {
                    Write-Host "Do Not have PII information for the Owner, so can not check the Receivers Copy of the Owner Calendar."
                    Write-Host "Get PII Access for both mailboxes and try again."
                }
            }
            if ((-not $script:LegacyMapiSharing) -and
                (-not $script:PublishedSharing)) {
                $receiverLocalFolderReason = if ($script:PIIAccess) {
                    "A uniquely matched owner folder was unavailable."
                } else {
                    "PII access was unavailable."
                }
                Add-SharingFinding -Severity Warning -Area "Receiver calendar folder" -Issue "The receiver local-folder detail check could not be completed." -Evidence $receiverLocalFolderReason -RecommendedNextStep "Confirm the folder using Get-CalendarEntries and rerun the pair diagnostics." -Incomplete
            }
        }
    }
}

function Write-SharingSummary {
    param(
        [Parameter(Mandatory)]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Receiver
    )

    Complete-SharingFindings
    $summaryColor = if ($null -ne $script:FatalPrerequisiteFailure) { "Red" } else { "Blue" }
    Write-Host -ForegroundColor $summaryColor "`r`r`r------------------------------------------------"
    Write-Host -ForegroundColor $summaryColor "Summary (from run on $($script:RunStartedAt.ToString('g'))):"
    if ($null -ne $script:FatalPrerequisiteFailure) {
        $rootFinding = $script:SharingFindings |
            Where-Object -Property ruleId -EQ $script:FatalPrerequisiteFailure.ruleId |
            Select-Object -First 1
        Write-Host -ForegroundColor Red "Fatal prerequisite failure"
        Write-Host -ForegroundColor Red "Root rule: [$($script:FatalPrerequisiteFailure.ruleId)]"
        Write-Host -ForegroundColor Red "Reason: $($script:FatalPrerequisiteFailure.reason)"
        if ($null -ne $rootFinding) {
            [PSCustomObject]@{
                severity            = $rootFinding.severity
                ruleId              = $rootFinding.ruleId
                status              = $rootFinding.status
                title               = $rootFinding.title
                evidence            = $script:ConsoleFindingEvidence[$rootFinding.ruleId]
                recommendedNextStep = $rootFinding.recommendedNextStep
            } | Format-Table -AutoSize -Wrap
        }
        if ($script:CollectionErrors.Count -gt 0) {
            Write-Host -ForegroundColor Red "Root prerequisite collection failure:"
            $script:CollectionErrors | Format-Table -AutoSize -Property collector, error
        }
        return
    }

    Write-Host -ForegroundColor Blue "Mailbox Owner [$Owner] and Receiver [$Receiver] are using [$script:SharingType] for Calendar Sharing."
    if ($script:ModernSharing) {
        Write-Host -ForegroundColor Blue "The backend is using Modern Calendar Sharing."
    } elseif ($script:PublishedSharing) {
        Write-Host -ForegroundColor Blue "The receiver is using a published Internet Calendar subscription."
    } elseif ($script:LegacyMapiSharing) {
        Write-Host -ForegroundColor Blue "The internal relationship is using legacy MAPI calendar sharing."
    } else {
        Write-Host -ForegroundColor Blue "The calendar sharing model could not be determined from the available evidence."
    }

    $severityOrder = @{
        Critical    = 0
        Error       = 1
        Warning     = 2
        Information = 3
    }

    $detectedFindings = @($script:SharingFindings | Where-Object -Property status -EQ "Detected")
    $incompleteFindings = @($script:SharingFindings | Where-Object -Property status -EQ "NotEvaluated")

    Write-Host -ForegroundColor Blue "`r`rDetected Issues:"
    if ($detectedFindings.Count -eq 0) {
        Write-Host -ForegroundColor Green "No confirmed issues were detected with the evidence available."
    } else {
        Write-SharingFindingDetails `
            -Findings $detectedFindings `
            -SeverityOrder $severityOrder
    }

    Write-Host -ForegroundColor Blue "`r`rIncomplete Checks:"
    if (($incompleteFindings.Count -eq 0) -and
        ($script:CollectionErrors.Count -eq 0) -and
        ($script:EvaluationErrors.Count -eq 0)) {
        Write-Host -ForegroundColor Green "No incomplete checks were recorded."
    } else {
        Write-SharingFindingDetails `
            -Findings $incompleteFindings `
            -SeverityOrder $severityOrder
        if ($script:CollectionErrors.Count -gt 0) {
            Write-Host -ForegroundColor Yellow "Collection failures:"
            $script:CollectionErrors | Format-Table -AutoSize -Property collector, error
        }
        if ($script:EvaluationErrors.Count -gt 0) {
            Write-Host -ForegroundColor Yellow "Evaluation failures:"
            $script:EvaluationErrors | Format-Table -AutoSize -Property evaluation, error
        }
        Write-Host -ForegroundColor Yellow "The sharing state should not be considered healthy until the incomplete checks are resolved."
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
