# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Sharing collector and evaluation error handling.

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
        [string[]]$RuleIds = @()
    )

    if (($RuleIds.Count -gt 0) -and
        @($RuleIds | Where-Object { $null -eq (Get-SharingRuleNotApplicableReason -RuleId $_) }).Count -eq 0) {
        foreach ($ruleId in $RuleIds) {
            Add-SharingFinding -RuleId $ruleId -Status NotApplicable
        }
        return
    }
    try {
        & $Action
    } catch {
        $errorInfo = ConvertTo-SharingErrorInfo -ErrorRecord $_
        $script:EvaluationErrors.Add([PSCustomObject]@{
                evaluation = $Name
                error      = $errorInfo
                ruleIds    = @($RuleIds)
            })
        foreach ($ruleId in $RuleIds) {
            Add-SharingFinding -RuleId $ruleId -Status NotEvaluated -Evidence @{
                reason = "$Name evaluation failed."
            }
        }
        Write-Warning "$Name evaluation failed: $($_.Exception.Message) Other safe evaluations will continue."
    }
}
