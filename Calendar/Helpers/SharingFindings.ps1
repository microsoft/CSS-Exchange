# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Sharing finding registration and final status classification.

function Get-SharingRuleNotApplicableReason {
    param(
        [Parameter(Mandatory)]
        [string]$RuleId
    )

    if ($script:PublishedSharing -and ($RuleId -in ($script:ModernSharingRuleIds + @("SHR233", "SHR324", "SHR325")))) {
        return "Not applicable to a published-calendar relationship."
    }
    if ($script:LegacyMapiSharing -and ($RuleId -in $script:ModernSharingRuleIds)) {
        return "Not applicable to an internal legacy MAPI calendar-sharing relationship."
    }
    if (($script:SharingType -eq "ExternalSharing") -and
        ($RuleId -in ($script:InternalRestRuleIds + @("SHR324", "SHR325")))) {
        return "This check applies to internal REST or delegate sharing, not external sharing or publishing."
    }
    if (($RuleId -in @("SHR421", "SHR422", "SHR423", "SHR424")) -and (-not $script:PublishedSharing)) {
        return "The relationship is not a published calendar subscription."
    }
    if (($RuleId -in @("SHR420", "SHR421", "SHR422", "SHR423")) -and
        $script:PublishedSharing -and (-not $script:OwnerPublished)) {
        return "Publishing is not enabled on the owner calendar; verify publishing configuration before subscription checks."
    }
    if (($RuleId -eq "SHR420") -and (-not $script:OwnerPublished) -and (-not $script:PublishedSharing)) {
        return "The owner calendar is not published."
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
    $notApplicableReason = Get-SharingRuleNotApplicableReason -RuleId $rule.RuleId
    if ($null -ne $notApplicableReason) {
        $findingStatus = "NotApplicable"
        $Evidence = @{ reason = $notApplicableReason }
        $script:ConsoleFindingEvidence[$rule.RuleId] = $Evidence
    }
    $title = $rule.Title
    $nextStep = $rule.NextStep
    if (($rule.RuleId -eq "SHR325") -and ($findingStatus -eq "NotEvaluated")) {
        $title = "Receiver delegation check could not be completed"
        $nextStep = "Confirm whether the receiver is intended to be a delegate. Collect the missing permission or sharing evidence and rerun the check; do not grant delegate permissions unless delegation is intended."
    }
    if (($script:SharingType -eq "ExternalSharing") -and
        ($rule.RuleId -in @("SHR400", "SHR401", "SHR402", "SHR403"))) {
        $nextStep = "Inspect the receiver's external sharing configuration and actual synchronization timestamps. Internal REST assistant-log freshness does not determine external sharing health."
    }
    $script:SharingFindings.Add([PSCustomObject]@{
            ruleId              = $rule.RuleId
            severity            = $rule.Severity
            status              = $findingStatus
            title               = $title
            evidence            = ConvertTo-SharingEvidence -RuleId $rule.RuleId -Evidence $Evidence
            recommendedNextStep = $nextStep
            area                = $Area
        })
}

function Complete-SharingFindings {
    $ruleCollectors = @{
        SHR100 = @("OwnerMailbox"); SHR101 = @("OwnerMailbox")
        SHR110 = @("OwnerFolderStatistics"); SHR111 = @("OwnerCalendarPermissions")
        SHR112 = @("OwnerFolderStatistics"); SHR113 = @("OwnerFolderStatistics")
        SHR430 = @("OwnerFolderStatistics"); SHR431 = @("OwnerFolderStatistics")
        SHR120 = @("OwnerCalendarFolder"); SHR121 = @("OwnerCalendarFolder"); SHR122 = @("OwnerCalendarFolder")
        SHR123 = @("OwnerCalendarFolder")
        SHR130 = @("OwnerMailboxPermissions")
        SHR200 = @("ReceiverMailbox"); SHR201 = @("ReceiverMailbox")
        SHR210 = @("ReceiverFolderStatistics"); SHR211 = @("ReceiverFolderStatistics")
        SHR212 = @("ReceiverFolderStatistics"); SHR213 = @("ReceiverFolderStatistics")
        SHR214 = @("ReceiverFolderStatistics"); SHR215 = @("ReceiverFolderStatistics")
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
        SHR404 = @("ReceiverSharingSyncAssistantLog"); SHR405 = @("ReceiverSharingSyncAssistantLog")
        SHR406 = @("ReceiverSharingLog"); SHR407 = @("ReceiverSharingLog")
        SHR410 = @("ReceiverLocalCalendarFolder")
        SHR411 = @("ReceiverLocalCalendarFolder"); SHR412 = @("ReceiverLocalCalendarFolder")
        SHR413 = @("ReceiverLocalCalendarFolder"); SHR420 = @("InternetCalendar")
        SHR421 = @("InternetCalendar"); SHR422 = @("InternetCalendar", "ReceiverFolderStatistics")
        SHR423 = @("OwnerCalendarFolder")
        SHR424 = @("OwnerCalendarFolder")
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

    foreach ($finding in $script:SharingFindings) {
        $notApplicableReason = Get-SharingRuleNotApplicableReason -RuleId $finding.ruleId
        if ($null -ne $notApplicableReason) {
            $finding.status = "NotApplicable"
            $finding.evidence = ConvertTo-SharingEvidence -RuleId $finding.ruleId -Evidence @{
                reason = $notApplicableReason
            }
            $script:ConsoleFindingEvidence[$finding.ruleId] = @{ reason = $notApplicableReason }
        }
    }
    $inapplicableCollectors = if ($script:LegacyMapiSharing -or $script:PublishedSharing) {
        @($script:ModernSharingCollectorNames)
    } elseif ($script:SharingType -eq "ExternalSharing") {
        @($script:InternalRestCollectorNames)
    } else {
        @()
    }
    if ($inapplicableCollectors.Count -gt 0) {
        foreach ($collectorName in $inapplicableCollectors) {
            $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{
                status = "NotApplicable"
                error  = $null
            }
        }
        $relevantCollectionErrors = @($script:CollectionErrors | Where-Object {
                $_.collector -notin $inapplicableCollectors
            })
        $script:CollectionErrors.Clear()
        foreach ($collectionError in $relevantCollectionErrors) {
            $script:CollectionErrors.Add($collectionError)
        }
    }
    $relevantEvaluationErrors = @($script:EvaluationErrors | Where-Object {
            ($_.ruleIds.Count -eq 0) -or
            @($_.ruleIds | Where-Object { $null -eq (Get-SharingRuleNotApplicableReason -RuleId $_) }).Count -gt 0
        })
    $script:EvaluationErrors.Clear()
    foreach ($evaluationError in $relevantEvaluationErrors) {
        $script:EvaluationErrors.Add($evaluationError)
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
        if (($rule.RuleId -eq "SHR325") -and (-not $script:SharingFindingRuleIds.Contains($rule.RuleId))) {
            Add-SharingFinding -RuleId "SHR325" -Status NotEvaluated -Evidence @{
                reason = "The receiver delegate permission check was not performed."
            }
            continue
        }
        if ($script:SharingFindingRuleIds.Add($rule.RuleId)) {
            $status = "NotDetected"
            $reason = $null
            if ($ruleCollectors.ContainsKey($rule.RuleId)) {
                $requiredCollectorStatuses = @($ruleCollectors[$rule.RuleId] | ForEach-Object {
                        $script:CollectorStatuses[$_].status
                    })
                if (($rule.RuleId -eq "SHR420") -and
                    ($requiredCollectorStatuses -eq "NoData")) {
                    $status = "NotDetected"
                } elseif (@($requiredCollectorStatuses | Where-Object { $_ -ne "Success" }).Count -gt 0) {
                    $status = "NotEvaluated"
                    $reason = "Required evidence was unavailable: $((@($ruleCollectors[$rule.RuleId]) | Where-Object { $script:CollectorStatuses[$_].status -ne 'Success' }) -join ', ')."
                }
            }
            if (($rule.RuleId -eq "SHR432") -and
                (-not $script:LegacyMapiSharing) -and
                (-not $script:PublishedSharing) -and
                (-not $script:CalendarStatisticsComparisonPerformed)) {
                $status = "NotEvaluated"
                $reason = "The owner and receiver statistics comparison was not performed."
            }
            if ($rule.RuleId -eq "SHR424") {
                $status = "NotEvaluated"
                $reason = "The published-calendar configuration check was not performed."
            }
            if (($rule.RuleId -in @("SHR408", "SHR409", "SHR414")) -and (-not $script:SharingLogScanPerformed)) {
                $status = "NotEvaluated"
                $reason = "The sharing logs were not scanned."
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
                $reason = "No receiver local calendar folder was matched."
            }
            if ($rule.RuleId -in @("SHR400", "SHR402") -and
                @($script:SharingFindings | Where-Object {
                        $_.ruleId -eq "SHR401" -and $_.status -eq "NotEvaluated"
                    }).Count -gt 0) {
                $status = "NotEvaluated"
                $reason = "The periodic synchronization timestamps are incomplete."
            }
            if ($rule.RuleId -in @("SHR410", "SHR411", "SHR412") -and
                @($script:SharingFindings | Where-Object {
                        $_.ruleId -eq "SHR413" -and $_.status -eq "Detected"
                    }).Count -gt 0) {
                $status = "NotApplicable"
                $reason = "The synchronization start date is unavailable."
            } elseif ($rule.RuleId -in @("SHR411", "SHR412") -and
                @($script:SharingFindings | Where-Object {
                        $_.ruleId -eq "SHR410" -and $_.status -in @("Detected", "NotEvaluated")
                    }).Count -gt 0) {
                $status = "NotEvaluated"
                $reason = "The synchronization start date could not be interpreted."
            }
            $notApplicableReason = Get-SharingRuleNotApplicableReason -RuleId $rule.RuleId
            if ($null -ne $notApplicableReason) {
                $status = "NotApplicable"
                $reason = $notApplicableReason
            }
            $script:SharingFindings.Add([PSCustomObject]@{
                    ruleId              = $rule.RuleId
                    severity            = $rule.Severity
                    status              = $status
                    title               = $rule.Title
                    evidence            = $(if ($null -ne $reason) { @{ reason = $reason } } else { @{} })
                    recommendedNextStep = $rule.NextStep
                    area                = $null
                })
        }
    }
}

function Register-SharingOutboxCalendar {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Owner", "Receiver")]
        [string]$Role,

        [Parameter(Mandatory)]
        [string]$FolderName
    )

    $ruleId = if ($Role -eq "Owner") { "SHR113" } else { "SHR215" }
    if ($script:SharingFindingRuleIds.Contains($ruleId)) {
        return
    }

    Write-Host -ForegroundColor Red "Warning: The $Role calendar [$FolderName] has been renamed Outbox. This is a known issue; escalate to Microsoft Support."
    Add-SharingFinding -RuleId $ruleId -Status Detected -Area "$Role calendar naming" -Evidence @{
        mailboxRole = $Role
        folderName  = $FolderName
    }
}
