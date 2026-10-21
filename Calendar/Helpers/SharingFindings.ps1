# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Sharing finding registration and final status classification.

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
            $reason = $null
            if ($script:LegacyMapiSharing -and
                ($rule.RuleId -in $script:ModernSharingRuleIds)) {
                $status = "NotApplicable"
                $reason = "The relationship uses legacy MAPI sharing, so this Modern Sharing rule does not apply."
            } elseif ($script:PublishedSharing -and
                ($rule.RuleId -in $script:ModernSharingRuleIds)) {
                $status = "NotApplicable"
                $reason = "The receiver uses a published calendar subscription, so this Modern Sharing rule does not apply."
            } elseif (($rule.RuleId -in @("SHR421", "SHR422", "SHR423")) -and
                (-not $script:PublishedSharing)) {
                $status = "NotApplicable"
                $reason = "The relationship is not a published calendar subscription."
            } elseif (($rule.RuleId -eq "SHR420") -and
                (-not $script:OwnerPublished)) {
                $status = "NotApplicable"
                $reason = "The owner calendar is not published."
            } elseif ($ruleCollectors.ContainsKey($rule.RuleId)) {
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
            if ($rule.RuleId -eq "SHR325") {
                $status = "NotEvaluated"
                $reason = "The receiver delegate permission check was not performed."
            }
            if (($rule.RuleId -in @("SHR408", "SHR409")) -and (-not $script:SharingLogScanPerformed)) {
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
