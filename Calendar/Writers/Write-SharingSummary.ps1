# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Console summary of sharing findings and incomplete checks.

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

    $organizationScope = switch ($script:SharingType) {
        "ExternalSharing" { "Cross-organization" }
        "InternalSharing" { "Same organization" }
        default { "Undetermined" }
    }
    Write-Host -ForegroundColor Blue "Mailbox Owner [$Owner] and Receiver [$Receiver]."
    Write-Host -ForegroundColor Blue "Organization scope: $organizationScope [$script:SharingType]."
    Write-Host -ForegroundColor Blue "Sharing relationship: $(Get-SharingRelationshipKind)."
    if ($script:ExternalSharing) {
        Write-Host -ForegroundColor Blue "The receiver is using cross-organization external calendar sharing, not internal REST sharing."
    } elseif ($script:ModernSharing) {
        Write-Host -ForegroundColor Blue "The backend is using Modern Calendar Sharing."
    } elseif ($script:PublishedSharing) {
        Write-Host -ForegroundColor Blue "The receiver is using a published Internet Calendar subscription."
    } elseif ($script:LegacyMapiSharing) {
        Write-Host -ForegroundColor Blue "The internal relationship is using legacy MAPI calendar sharing."
    } else {
        Write-Host -ForegroundColor Blue "The calendar sharing model could not be determined from the available evidence."
        Write-Host -ForegroundColor Yellow "Organization scope does not confirm that a calendar-sharing relationship exists. Verify that this calendar was shared with the receiver before investigating synchronization."
    }

    $relationshipAssessment = Get-SharingRelationshipAssessment
    if ($null -ne $relationshipAssessment) {
        $assessmentColor = if ($relationshipAssessment.status -eq "NotConfirmed") { "Yellow" } else { "Cyan" }
        Write-Host -ForegroundColor $assessmentColor -Object "Selected-calendar sharing assessment: Owner [$Owner], receiver [$Receiver], calendar [$script:NormalizedOwnerCalendarFolderPath]."
        Write-Host -ForegroundColor $assessmentColor -Object $relationshipAssessment.message
    }

    Write-OwnerReceiverInviteSummary -Owner $Owner -Receiver $Receiver

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
