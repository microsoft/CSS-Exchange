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
# .EXAMPLE
# .\Check-SharingStatus.ps1 -Owner Owner@contoso.com -Receiver Receiver@contoso.com

# Define the parameters
# cSpell:ignore Dont
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Owner,
    [Parameter(Mandatory=$true)]
    [string]$Receiver,
    [Parameter()]
    [bool]$ModernSharingOnly = $true,
    [Parameter()]
    [switch]$IncludeSensitiveData,
    [Parameter(DontShow)]
    [switch]$SkipMainExecution
)

$BuildVersion = ""

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

if ((-not $SkipMainExecution) -and (Test-ScriptVersion -AutoUpdate)) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command."  -ForegroundColor Yellow
    return
}

Write-Verbose "Script Versions: $BuildVersion"

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
$script:ReceiverMatchedCalendar = $null
$script:ReceiverCalendarCandidates = @()

# Sharing diagnostic rule IDs use the SHR prefix. The hundreds digit identifies the owning area:
# SHR1xx owner, SHR2xx receiver, SHR3xx relationship, and SHR4xx sync/performance.
$script:SharingRuleCatalog = @(
    [PSCustomObject]@{ RuleId = "SHR100"; Severity = "Error"; Title = "Owner mailbox evidence is unavailable"; Aliases = @("The owner mailbox lookup failed.", "The owner mailbox lookup returned no mailbox."); NextStep = "Verify the owner identity and rerun the mailbox diagnostics with sufficient access." }
    [PSCustomObject]@{ RuleId = "SHR101"; Severity = "Warning"; Title = "Owner PII is redacted"; Aliases = @("Owner PII was redacted, limiting pair-specific checks."); NextStep = "Obtain PII access for the owner mailbox database and rerun the pair diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR110"; Severity = "Warning"; Title = "Owner folder statistics are unavailable"; Aliases = @("The owner calendar-folder checks were unavailable.", "The owner default-calendar checks could not be completed."); NextStep = "Rerun Get-MailboxFolderStatistics with sufficient access and inspect the owner calendar." }
    [PSCustomObject]@{ RuleId = "SHR111"; Severity = "Warning"; Title = "Owner calendar permissions are unavailable"; Aliases = @("The pair-specific permission check was unavailable."); NextStep = "Rerun Get-MailboxFolderPermission and compare permissions with the sharing relationship." }
    [PSCustomObject]@{ RuleId = "SHR430"; Severity = "Warning"; Title = "Owner calendar is oversized"; Aliases = @("The owner calendar is larger than 1 GB."); NextStep = "Review folder statistics and item or attachment distribution before remediation." }
    [PSCustomObject]@{ RuleId = "SHR431"; Severity = "Warning"; Title = "Owner calendar has too many items"; Aliases = @("The owner calendar has more than 100,000 visible items."); NextStep = "Review folder statistics and item distribution before remediation." }
    [PSCustomObject]@{ RuleId = "SHR120"; Severity = "Warning"; Title = "Owner calendar folder evidence is unavailable"; Aliases = @("The owner calendar-flag checks were unavailable."); NextStep = "Rerun Get-MailboxCalendarFolder and inspect sharing diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR121"; Severity = "Error"; Title = "Owner calendar is missing SharedOut"; Aliases = @("The owner calendar is missing SharedOut."); NextStep = "Run SharingPolicyAssistant or calendar-sharing validator diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR122"; Severity = "Error"; Title = "Owner calendar is missing ExchangeShareFolder"; Aliases = @("The owner calendar is missing ExchangeShareFolder."); NextStep = "Run SharingPolicyAssistant or calendar-sharing validator diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR130"; Severity = "Warning"; Title = "Owner mailbox permissions are unavailable"; Aliases = @("The owner mailbox-permission check was unavailable."); NextStep = "Rerun Get-MailboxPermission with sufficient access." }
    [PSCustomObject]@{ RuleId = "SHR200"; Severity = "Error"; Title = "Receiver mailbox evidence is unavailable"; Aliases = @("The receiver mailbox lookup failed.", "The receiver mailbox lookup returned no mailbox."); NextStep = "Verify the receiver identity and rerun the mailbox diagnostics with sufficient access." }
    [PSCustomObject]@{ RuleId = "SHR201"; Severity = "Warning"; Title = "Receiver PII is redacted"; Aliases = @("Receiver PII was redacted, limiting folder matching."); NextStep = "Obtain PII access for the receiver mailbox database and rerun the pair diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR210"; Severity = "Warning"; Title = "Receiver folder statistics are unavailable"; Aliases = @("The receiver local-folder checks were unavailable."); NextStep = "Rerun Get-MailboxFolderStatistics and compare calendar entries and logs." }
    [PSCustomObject]@{ RuleId = "SHR211"; Severity = "Warning"; Title = "Receiver has duplicate owner calendar folders"; Aliases = @("Multiple local folders may represent the owner's shared calendar."); NextStep = "Compare folder identifiers, calendar entries, and invite or accept logs." }
    [PSCustomObject]@{ RuleId = "SHR212"; Severity = "Warning"; Title = "Receiver has multiple generically named calendars"; Aliases = @("The receiver has multiple calendars whose names begin with Calendar."); NextStep = "Use folder identifiers and calendar entries to distinguish the shared folder." }
    [PSCustomObject]@{ RuleId = "SHR213"; Severity = "Error"; Title = "Receiver local owner calendar is missing"; Aliases = @("A local folder for the expected owner was not found."); NextStep = "Inspect invite or accept logs and calendar entries for the pair." }
    [PSCustomObject]@{ RuleId = "SHR214"; Severity = "Warning"; Title = "Receiver calendar has a numeric suffix"; Aliases = @("The matched receiver calendar name ends with a numeric suffix."); NextStep = "Compare folder identifiers, calendar entries, and logs to identify the current folder." }
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
    [PSCustomObject]@{ RuleId = "SHR400"; Severity = "Warning"; Title = "Periodic synchronization is stale"; Aliases = @("Periodic synchronization is stale and the assistant may not be running."); NextStep = "Inspect SharingSyncAssistant logs for the receiver." }
    [PSCustomObject]@{ RuleId = "SHR401"; Severity = "Warning"; Title = "Periodic synchronization timestamps are incomplete"; Aliases = @("Periodic synchronization timestamps are incomplete."); NextStep = "Inspect SharingSyncAssistant logs and rerun folder diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR402"; Severity = "Error"; Title = "Recent periodic synchronization attempt failed"; Aliases = @("A recent periodic synchronization attempt failed."); NextStep = "Inspect SharingSyncAssistant logs." }
    [PSCustomObject]@{ RuleId = "SHR410"; Severity = "Warning"; Title = "Synchronization start date cannot be parsed"; Aliases = @("SharedCalendarSyncStartDate could not be interpreted as a date."); NextStep = "Inspect raw folder data and SharingSyncAssistant logs." }
    [PSCustomObject]@{ RuleId = "SHR411"; Severity = "Warning"; Title = "Synchronization start is later than folder creation"; Aliases = @("SharedCalendarSyncStartDate is later than the local folder CreationTime."); NextStep = "Inspect invite, accept, and synchronization logs." }
    [PSCustomObject]@{ RuleId = "SHR412"; Severity = "Information"; Title = "Synchronization start is very recent"; Aliases = @("SharedCalendarSyncStartDate is very recent and may reflect backfill or folder recreation context."); NextStep = "Correlate invite, accept, and synchronization logs." }
    [PSCustomObject]@{ RuleId = "SHR413"; Severity = "Warning"; Title = "Synchronization start date is null"; Aliases = @("SharedCalendarSyncStartDate is null."); NextStep = "Inspect SharingSyncAssistant and validator diagnostics." }
    [PSCustomObject]@{ RuleId = "SHR420"; Severity = "Warning"; Title = "InternetCalendar evidence is unavailable"; Aliases = @("The published-calendar log check was unavailable."); NextStep = "Collect InternetCalendar logs when published-calendar behavior is in scope." }
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
            } elseif ($property.Name -match "(?i)^actualOwner$") {
                $sanitizedEvidence[$property.Name] = Get-SanitizedSharingIdentity -Identity $property.Value
            } elseif ($property.Name -match "(?i)owner") {
                $sanitizedEvidence[$property.Name] = "Owner"
            } elseif ($property.Name -match "(?i)receiver") {
                $sanitizedEvidence[$property.Name] = "Receiver"
            } elseif ($property.Name -match "(?i)identity|email|smtp|displayName") {
                $sanitizedEvidence[$property.Name] = Get-SanitizedSharingIdentity -Identity $property.Value
            } elseif ($property.Value -is [string]) {
                $sanitizedEvidence[$property.Name] = if ($property.Name -in @("reason", "source")) {
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
        "SHR214" {
            $result = @{ receiver = $receiverValue; hasNumericSuffix = $true }
            if ($IncludeSensitiveData -and $values.Count -gt 0) {
                $result.folderName = $values[0]
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
                modernSharingOnly  = $ModernSharingOnly
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
        SHR430 = @("OwnerFolderStatistics"); SHR431 = @("OwnerFolderStatistics")
        SHR120 = @("OwnerCalendarFolder"); SHR121 = @("OwnerCalendarFolder"); SHR122 = @("OwnerCalendarFolder")
        SHR130 = @("OwnerMailboxPermissions")
        SHR200 = @("ReceiverMailbox"); SHR201 = @("ReceiverFolderStatistics")
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
        SHR402 = @("ReceiverLocalCalendarFolder"); SHR410 = @("ReceiverLocalCalendarFolder")
        SHR411 = @("ReceiverLocalCalendarFolder"); SHR412 = @("ReceiverLocalCalendarFolder")
        SHR413 = @("ReceiverLocalCalendarFolder"); SHR420 = @("InternetCalendar")
    }

    if ($ModernSharingOnly -and $script:CollectorStatuses["InternetCalendar"].status -eq "NotRun") {
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
            if ($rule.RuleId -in @("SHR233", "SHR420") -and $ModernSharingOnly) {
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
            $receiverFolderMissing = (
                $script:CollectorStatuses["ReceiverFolderStatistics"].status -eq "Success" -and
                $script:ReceiverCalendarCandidates.Count -eq 0)
            if ($rule.RuleId -eq "SHR214") {
                if ($receiverFolderMissing) {
                    $status = "NotApplicable"
                } elseif (($script:ReceiverCalendarCandidates.Count -gt 1) -and
                    ($null -eq $script:ReceiverMatchedCalendar)) {
                    $status = "NotEvaluated"
                }
            }
            if ($receiverFolderMissing -and
                $rule.RuleId -in @(
                    "SHR240", "SHR241", "SHR242", "SHR243",
                    "SHR400", "SHR401", "SHR402", "SHR410",
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

    # Access the values as properties of the object
    foreach ($row in $csvObject) {
        Write-Debug "$($row.Timestamp) - $($row.SharedCalendarOwner) - $($row.FolderName) "
    }

    Write-Host "Receiver [$Identity] has accepted copies of the shared calendar from the following recipients in the last 180 days:"
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
        $csvObject | Where-Object { [DateTime]::Parse($_.Timestamp, $culture) -gt (Get-Date).AddDays(-180) } | Format-Table -a Timestamp, SharedCalendarOwner, FolderName
    } catch {
        $errorInfo = ConvertTo-SharingErrorInfo -ErrorRecord $_
        $script:EvaluationErrors.Add([PSCustomObject]@{
                evaluation = "Receiver accept-log timestamp parsing"
                error      = $errorInfo
            })
        Write-Error "Error parsing dates in the log entries.  Outputting all entries without date filtering."
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "Accept-log timestamps could not be parsed." -Evidence $_.Exception.Message -RecommendedNextStep "Inspect the raw AcceptCalendarSharingInvite logs and their timestamp culture." -Incomplete
        $csvObject |  Format-Table -a Timestamp, SharedCalendarOwner, FolderName
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
    #Standard Owner information
    Write-Host -ForegroundColor DarkYellow "------------------------------------------------"
    Write-Host -ForegroundColor DarkYellow "Key Owner Mailbox Information:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-Mailbox $Owner'"
    $script:OwnerMB = $null
    try {
        $script:OwnerMB = Invoke-SharingCollector -Name "OwnerMailbox" -Action {
            Get-Mailbox -Identity $Owner -ErrorAction Stop
        }
    } catch {
        Write-Host -ForegroundColor Yellow "Could not find Owner Mailbox [$Owner]."
        Write-Host -ForegroundColor DarkYellow "Defaulting to External Sharing or Publishing."
        Add-SharingFinding -Severity Error -Area "Owner mailbox lookup" -Issue "The owner mailbox lookup failed." -Evidence $_.Exception.Message -RecommendedNextStep "Verify the owner identity and rerun the mailbox diagnostics with sufficient access." -Incomplete
        return
    }

    if (-not $script:OwnerMB) {
        $script:CollectorStatuses["OwnerMailbox"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host -ForegroundColor Yellow "Could not find Owner Mailbox [$Owner]."
        Write-Host -ForegroundColor DarkYellow "Defaulting to External Sharing or Publishing."
        Add-SharingFinding -Severity Error -Area "Owner mailbox lookup" -Issue "The owner mailbox lookup returned no mailbox." -Evidence "Get-Mailbox returned no object for [$Owner]." -RecommendedNextStep "Verify the owner identity and rerun the mailbox diagnostics with sufficient access." -Incomplete
        return
    }

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
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar'"
    try {
        $OwnerCalendarStats = @(Invoke-SharingCollector -Name "OwnerFolderStatistics" -Action {
                @(Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar -ErrorAction Stop)
            })
    } catch {
        Write-Warning "Failed to retrieve Owner Calendar folder statistics for [$Owner]: $($_.Exception.Message)"
        Add-SharingFinding -Severity Warning -Area "Owner calendar folder" -Issue "The owner calendar-folder checks were unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-MailboxFolderStatistics with sufficient access and inspect the owner calendar." -Incomplete
        Write-Host -ForegroundColor DarkYellow "Owner Modern Sharing Sent Invites"
        ProcessCalendarSharingInviteLogs -Identity $Owner
        return
    }
    $ownerCalendarStat = $OwnerCalendarStats |
        Where-Object -Property FolderType -EQ "Calendar" |
        Select-Object -First 1
    if ($null -eq $ownerCalendarStat) {
        $script:CollectorStatuses["OwnerFolderStatistics"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Warning "Could not identify the default calendar folder for Owner [$Owner]."
        Add-SharingFinding -Severity Warning -Area "Owner calendar folder" -Issue "The owner default-calendar checks could not be completed." -Evidence "Get-MailboxFolderStatistics returned no folder with FolderType Calendar." -RecommendedNextStep "Verify the mailbox folder statistics and rerun the calendar-sharing diagnostics." -Incomplete
        Write-Host -ForegroundColor DarkYellow "Owner Modern Sharing Sent Invites"
        ProcessCalendarSharingInviteLogs -Identity $Owner
        return
    }
    $OwnerCalendarName = $ownerCalendarStat.Name

    $OwnerCalendarStats | Format-Table -a FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Permissions:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxFolderPermission "${Owner}:\$OwnerCalendarName" | Format-Table -a User, AccessRights, SharingPermissionFlags'"
    try {
        $script:OwnerCalendarPerms = @(Invoke-SharingCollector -Name "OwnerCalendarPermissions" -Action {
                @(Get-MailboxFolderPermission -Identity "${Owner}:\$OwnerCalendarName" -ErrorAction Stop)
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
        $ownerMailboxPermissions = @(Invoke-SharingCollector -Name "OwnerMailboxPermissions" -Action {
                @(Get-MailboxPermission -Identity $Owner -ErrorAction Stop)
            } -AllowNull)
        $ownerMailboxPermissions | Format-Table -a User, AccessRights, SharingPermissionFlags
    } catch {
        Write-Warning "Failed to retrieve Owner mailbox permissions for [$Owner]: $($_.Exception.Message)"
        Add-SharingFinding -Severity Warning -Area "Owner mailbox permissions" -Issue "The owner mailbox-permission check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-MailboxPermission with sufficient access." -Incomplete
    }

    Write-Host -ForegroundColor DarkYellow "Owner Modern Sharing Sent Invites"
    ProcessCalendarSharingInviteLogs -Identity $Owner

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Folder Information:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxCalendarFolder "${Owner}:\$OwnerCalendarName"'"

    try {
        $OwnerCalendarFolder = Invoke-SharingCollector -Name "OwnerCalendarFolder" -Action {
            Get-MailboxCalendarFolder -Identity "${Owner}:\$OwnerCalendarName" -ErrorAction Stop
        }
    } catch {
        Write-Warning "Failed to retrieve Owner Calendar folder information for [$Owner]: $($_.Exception.Message)"
        Add-SharingFinding -Severity Warning -Area "Owner calendar flags" -Issue "The owner calendar-flag checks were unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-MailboxCalendarFolder and inspect SharingPolicyAssistant or calendar-sharing validator diagnostics." -Incomplete
        return
    }
    if ($OwnerCalendarFolder.PublishEnabled) {
        Write-Host -ForegroundColor Green "Owner Calendar is Published."
        $script:OwnerPublished = $true
    } else {
        Write-Host -ForegroundColor Yellow "Owner Calendar is not Published."
        $script:OwnerPublished = $false
    }

    $ownerExtendedFolderFlags = @($OwnerCalendarFolder.ExtendedFolderFlags)
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
        Write-Host -ForegroundColor DarkYellow "`t Running 'Get-CalendarActiveSharingInformation -Identity "${Owner}:\$OwnerCalendarName"'"
        try {
            $OwnerActiveSharingInfo = Invoke-SharingCollector -Name "ActiveSharing" -Action {
                Get-CalendarActiveSharingInformation -Identity "${Owner}:\$OwnerCalendarName" -ErrorAction Stop
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
    #Standard Receiver information
    Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
    Write-Host -ForegroundColor Cyan "Key Receiver MB Information: [$Receiver]"
    Write-Host -ForegroundColor Cyan "Running: 'Get-Mailbox $Receiver'"
    $script:ReceiverMB = $null
    try {
        $script:ReceiverMB = Invoke-SharingCollector -Name "ReceiverMailbox" -Action {
            Get-Mailbox -Identity $Receiver -ErrorAction Stop
        }
    } catch {
        Write-Host -ForegroundColor Yellow "Could not find Receiver Mailbox [$Receiver]."
        Write-Host -ForegroundColor Yellow "Defaulting to External Sharing or Publishing."
        Add-SharingFinding -Severity Error -Area "Receiver mailbox lookup" -Issue "The receiver mailbox lookup failed." -Evidence $_.Exception.Message -RecommendedNextStep "Verify the receiver identity and rerun the mailbox diagnostics with sufficient access." -Incomplete
        return
    }

    if (-not $script:ReceiverMB) {
        $script:CollectorStatuses["ReceiverMailbox"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host -ForegroundColor Yellow "Could not find Receiver Mailbox [$Receiver]."
        Write-Host -ForegroundColor Yellow "Defaulting to External Sharing or Publishing."
        Add-SharingFinding -Severity Error -Area "Receiver mailbox lookup" -Issue "The receiver mailbox lookup returned no mailbox." -Evidence "Get-Mailbox returned no object for [$Receiver]." -RecommendedNextStep "Verify the receiver identity and rerun the mailbox diagnostics with sufficient access." -Incomplete
        return
    }

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
    Write-Host -ForegroundColor Cyan "Receiver Calendar Folders (look for a copy of [$OwnerCalendarName] Calendar):"
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
    $receiverDefaultCalendar = $CalStats |
        Where-Object -Property FolderType -EQ "Calendar" |
        Select-Object -First 1
    $ReceiverCalendarName = $receiverDefaultCalendar.Name
    if ($receiverFolderStatsAvailable -and ($null -eq $receiverDefaultCalendar)) {
        Add-SharingFinding -RuleId "SHR201" -Status NotEvaluated -Evidence @{
            reason = "The receiver default calendar could not be identified."
        }
    }

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
    $script:ReceiverCalendarCandidates = $matchingOwnerCalendars
    if ($matchingOwnerCalendars.Count -eq 1) {
        $script:ReceiverMatchedCalendar = $matchingOwnerCalendars[0]
    }

    # Warning if there are multiple copies of the Owner Calendar in the Receiver Mailbox.
    if ($matchingOwnerCalendars.Count -gt 1) {
        Write-Host -ForegroundColor Yellow "Warning: Might have found more than one copy of the Owner Calendar in the Receiver Mailbox."
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
        Write-Host -ForegroundColor Green "Looks like we might have found a copy of the Owner Calendar in the Receiver Mailbox."
        Write-Host -ForegroundColor Green "This is a good indication the there is a Modern Sharing Relationship between these users."
        Write-Host -ForegroundColor Green "If the clients use the Modern Sharing or not is a up to the client."
        $script:ModernSharing = $true

        $matchingOwnerCalendars | Format-Table -a FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize
        if ($matchingOwnerCalendars.Count -gt 1) {
            Write-Host -ForegroundColor Yellow "Warning: Might have found more than one copy of the Owner Calendar in the Receiver Mailbox."
        }
    } else {
        Write-Host -ForegroundColor Yellow "Warning: Could not Identify the Owner's [$Owner] Calendar in the Receiver Mailbox."
        if ($receiverFolderStatsAvailable) {
            Add-SharingFinding -Severity Error -Area "Receiver calendar folders" -Issue "A local folder for the expected owner was not found." -Evidence "Receiver calendar folder statistics did not match owner [$Owner] or display name [$OwnerCalendarName]." -RecommendedNextStep "Inspect invite/accept logs and Get-CalendarEntries for the owner/receiver pair."
        }
    }

    if ($ReceiverCalendarName -like "REDACTED-*" ) {
        Write-Host -ForegroundColor Yellow "Do Not have PII information for the Receiver"
        $script:PIIAccess = $false
        Add-SharingFinding -Severity Warning -Area "PII access" -Issue "Receiver PII was redacted, limiting folder matching." -Evidence "The receiver default calendar name begins with REDACTED-." -RecommendedNextStep "Obtain PII access for the receiver mailbox database and rerun the pair diagnostics." -Incomplete
    }

    ProcessCalendarSharingAcceptLogs -Identity $Receiver
    if (!$ModernSharingOnly) {
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
                    (Test-SmtpAddressEqual -First $_.OwnerEmailAddress -Second $Owner)
                })
            if ($calendarEntriesAvailable -and ($pairNewEntries.Count -eq 0)) {
                Add-SharingFinding -Severity Error -Area "Calendar entries" -Issue "The pair-specific new-model calendar entry is missing." -Evidence "Get-CalendarEntries returned data but no New entry for owner [$Owner]." -RecommendedNextStep "Inspect invite/accept logs and SharingPolicyAssistant or calendar-sharing validator diagnostics."
            }
            if (($null -eq $script:ReceiverMatchedCalendar) -and
                ($pairNewEntries.Count -eq 1)) {
                $entryFolderMatches = @($script:ReceiverCalendarCandidates | Where-Object -FilterScript {
                        [string]::Equals(
                            $_.Name,
                            $pairNewEntries[0].CalendarName,
                            [System.StringComparison]::OrdinalIgnoreCase)
                    })
                if ($entryFolderMatches.Count -eq 1) {
                    $script:ReceiverMatchedCalendar = $entryFolderMatches[0]
                }
            }
            foreach ($pairNewEntry in $pairNewEntries) {
                if ($pairNewEntry.IsOrphanedEntry -eq $true) {
                    Add-SharingFinding -Severity Error -Area "Calendar entries" -Issue "The pair-specific new-model calendar entry is orphaned." -Evidence "Calendar [$($pairNewEntry.CalendarName)] has IsOrphanedEntry=True." -RecommendedNextStep "Run SharingPolicyAssistant or calendar-sharing validator diagnostics and inspect invite/accept processing."
                }
            }

            if (!$ModernSharingOnly) {
                Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
                Write-Host "Old Model Calendar Sharing Entries:"
                Write-Host "Consider upgrading these to the new model."
                $ReceiverCalEntries | Where-Object SharingModelType -Like Old | Format-Table CalendarGroupName, CalendarName, OwnerEmailAddress, SharingModelType, IsOrphanedEntry
            }
            if (!$ModernSharingOnly) {
                $pairOldEntries = @($ReceiverCalEntries | Where-Object -FilterScript {
                        ($_.SharingModelType -like "Old") -and
                        (Test-SmtpAddressEqual -First $_.OwnerEmailAddress -Second $Owner)
                    })
                if ($pairOldEntries.Count -gt 0) {
                    Add-SharingFinding -Severity Warning -Area "Calendar entries" -Issue "A relevant old-model calendar entry exists for the expected owner." -Evidence "Get-CalendarEntries returned [$($pairOldEntries.Count)] Old entry or entries for [$Owner]. ModernSharingOnly=[$ModernSharingOnly]." -RecommendedNextStep "Inspect invite/accept logs and SharingPolicyAssistant or calendar-sharing validator diagnostics before considering configuration changes."
                }
            }
        } else {
            $script:CollectorStatuses["CalendarEntries"] = [PSCustomObject]@{ status = "Unavailable"; error = $null }
            Add-SharingFinding -Severity Warning -Area "Calendar entries" -Issue "Get-CalendarEntries is unavailable." -Evidence "The cmdlet was not found in the current session." -RecommendedNextStep "Run the check in a session where Get-CalendarEntries is available." -Incomplete
        }

        # Warning if the resolved Receiver calendar name has a (1) or similar at the end.
        if (($null -ne $script:ReceiverMatchedCalendar) -and
            ($script:ReceiverMatchedCalendar.Name -match "\(\d+\)$")) {
            Write-Host -ForegroundColor Yellow "Warning: Receiver Calendar name has a (1) or similar at the end. This indicates the Receiver has / had multiple Calendars from the Owner."
            Add-SharingFinding -Severity Warning -Area "Receiver calendar naming" -Issue "The matched receiver calendar name ends with a numeric suffix." -Evidence "Matched folder name: [$($script:ReceiverMatchedCalendar.Name)]." -RecommendedNextStep "Compare folder identifiers, Get-CalendarEntries, and invite/accept logs to determine which folder is current."
        }

        #Output key Modern Sharing information
        if (($script:PIIAccess) -and
            ($null -ne $script:OwnerMB) -and
            ($null -ne $script:ReceiverMatchedCalendar) -and
            (-not [string]::IsNullOrWhiteSpace($ReceiverCalendarName))) {
            Write-Host "Checking for Owner copy Calendar in Receiver Calendar:"
            Write-Host "Running cmdlet:"
            $receiverFolderIdentity = Get-ReceiverFolderIdentity -Receiver $Receiver -ReceiverCalendarName $ReceiverCalendarName -FolderPath $script:ReceiverMatchedCalendar.FolderPath.ToString()
            Write-Host -NoNewline -ForegroundColor Yellow "Get-MailboxCalendarFolder -Identity `"$receiverFolderIdentity`""
            $MBCalFolder = $null
            try {
                $MBCalFolder = Invoke-SharingCollector -Name "ReceiverLocalCalendarFolder" -Action {
                    Get-MailboxCalendarFolder -Identity $receiverFolderIdentity -ErrorAction Stop
                }
                $MBCalFolder | Format-List Identity, CreationTime, ExtendedFolderFlags, CalendarSharingFolderFlags, CalendarSharingOwnerSmtpAddress, CalendarSharingPermissionLevel, SharingLevelOfDetails, SharingPermissionFlags, LastAttemptedSyncTime, LastSuccessfulSyncTime, SharedCalendarSyncStartDate

                $receiverExtendedFolderFlags = @($MBCalFolder.ExtendedFolderFlags)
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

                if ($null -ne $MBCalFolder.SharedCalendarSyncStartDate) {
                    $syncStartDate = $MBCalFolder.SharedCalendarSyncStartDate -as [DateTime]
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
                } else {
                    Write-Host -ForegroundColor Yellow "Warning: The Receiver's copy of the Owner's Calendar does not have a SharedCalendarSyncStartDate."
                    Add-SharingFinding -Severity Warning -Area "Synchronization start date" -Issue "SharedCalendarSyncStartDate is null." -Evidence "The receiver local shared folder returned no SharedCalendarSyncStartDate." -RecommendedNextStep "Inspect SharingSyncAssistant logs and SharingPolicyAssistant or validator diagnostics."
                }

                $ownerPermission = @($script:OwnerCalendarPerms | Where-Object -FilterScript {
                        (Test-SmtpAddressEqual -First $_.User -Second $Receiver) -or
                        (Test-SmtpAddressEqual -First $_.User.RecipientPrincipal.PrimarySmtpAddress -Second $Receiver)
                    }) | Select-Object -First 1
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
            $script:CollectorStatuses["ReceiverLocalCalendarFolder"] = [PSCustomObject]@{ status = "NotEvaluated"; error = $null }
            Write-Host "Do Not have PII information for the Owner, so can not check the Receivers Copy of the Owner Calendar."
            Write-Host "Get PII Access for both mailboxes and try again."
            Add-SharingFinding -Severity Warning -Area "Receiver calendar folder" -Issue "The receiver local-folder detail check could not be completed." -Evidence "PII access or a uniquely matched owner folder was unavailable." -RecommendedNextStep "Obtain required PII access, confirm the folder using Get-CalendarEntries, and rerun the pair diagnostics." -Incomplete
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

    Write-Host -ForegroundColor Blue "`r`r`r------------------------------------------------"
    Write-Host -ForegroundColor Blue "Summary:"
    Write-Host -ForegroundColor Blue "Mailbox Owner [$Owner] and Receiver [$Receiver] are using [$script:SharingType] for Calendar Sharing."
    Write-Host -ForegroundColor Blue "It appears like the backend [$(if ($script:ModernSharing) {"IS"} else {"is NOT"})] using Modern Calendar Sharing."

    $severityOrder = @{
        Critical    = 0
        Error       = 1
        Warning     = 2
        Information = 3
    }

    Complete-SharingFindings
    $detectedFindings = @($script:SharingFindings | Where-Object -Property status -EQ "Detected")
    $incompleteFindings = @($script:SharingFindings | Where-Object -Property status -EQ "NotEvaluated")

    Write-Host -ForegroundColor Blue "`r`rDetected Issues:"
    if ($detectedFindings.Count -eq 0) {
        Write-Host -ForegroundColor Green "No confirmed issues were detected with the evidence available."
    } else {
        $detectedFindings |
            ForEach-Object {
                [PSCustomObject]@{
                    severity            = $_.severity
                    ruleId              = $_.ruleId
                    title               = $_.title
                    evidence            = $script:ConsoleFindingEvidence[$_.ruleId]
                    recommendedNextStep = $_.recommendedNextStep
                }
            } |
            Sort-Object -Property @{ Expression = { $severityOrder[$_.severity] } }, ruleId |
            Format-Table -AutoSize -Property severity, ruleId, title, evidence, recommendedNextStep
    }

    Write-Host -ForegroundColor Blue "`r`rIncomplete Checks:"
    if (($incompleteFindings.Count -eq 0) -and
        ($script:CollectionErrors.Count -eq 0) -and
        ($script:EvaluationErrors.Count -eq 0)) {
        Write-Host -ForegroundColor Green "No incomplete checks were recorded."
    } else {
        $incompleteFindings |
            ForEach-Object {
                [PSCustomObject]@{
                    severity            = $_.severity
                    ruleId              = $_.ruleId
                    title               = $_.title
                    evidence            = $script:ConsoleFindingEvidence[$_.ruleId]
                    recommendedNextStep = $_.recommendedNextStep
                }
            } |
            Sort-Object -Property @{ Expression = { $severityOrder[$_.severity] } }, ruleId |
            Format-Table -AutoSize -Property severity, ruleId, title, evidence, recommendedNextStep
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

if ($SkipMainExecution) {
    return
}

# Main
$script:ModernSharing = $false
$script:SharingType = $null
$script:OwnerMB = $null
$script:ReceiverMB = $null
Invoke-SharingEvaluation -Name "Owner diagnostics" -Action { GetOwnerInformation -Owner $Owner }
if ($script:CollectorStatuses["OwnerInviteLog"].status -eq "NotRun") {
    Invoke-SharingEvaluation -Name "Owner invite-log diagnostics" -Action {
        ProcessCalendarSharingInviteLogs -Identity $Owner
    }
}
Invoke-SharingEvaluation -Name "Receiver diagnostics" -Action { GetReceiverInformation -Receiver $Receiver }
if ($script:CollectorStatuses["ReceiverAcceptLog"].status -eq "NotRun") {
    Invoke-SharingEvaluation -Name "Receiver accept-log diagnostics" -Action {
        ProcessCalendarSharingAcceptLogs -Identity $Receiver
    }
}
if ((-not $ModernSharingOnly) -and
    ($script:CollectorStatuses["InternetCalendar"].status -eq "NotRun")) {
    Invoke-SharingEvaluation -Name "InternetCalendar diagnostics" -Action {
        ProcessInternetCalendarLogs -Identity $Receiver
    }
}

Write-SharingSummary -Owner $Owner -Receiver $Receiver
