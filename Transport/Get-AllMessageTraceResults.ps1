# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-AllMessageTraceResults {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseOutputTypeCorrectly", "")]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [DateTime]$StartDate,

        [Parameter(Mandatory)]
        [DateTime]$EndDate,

        [Parameter()]
        [string]$FromIP,

        [Parameter()]
        [string[]]$MessageId,

        [Parameter()]
        [guid]$MessageTraceId,

        [Parameter()]
        [string[]]$RecipientAddress,

        [Parameter()]
        [string[]]$SenderAddress,

        [Parameter()]
        [ValidateSet("Delivered", "Expanded", "Failed", "FilteredAsSpam", "GettingStatus", "Pending", "Quarantined")]
        [string[]]$Status,

        [Parameter()]
        [string]$Subject,

        [Parameter()]
        [ValidateSet("Contains", "StartsWith", "EndsWith")]
        [string]$SubjectFilterType,

        [Parameter()]
        [string]$ToIP,

        [Parameter()]
        [ValidateRange(1, 5000)]
        [int]$PageSize = 5000,

        [Parameter()]
        [ValidateRange(1, 2147483647)]
        [int]$TimeoutMinutes = 30
    )

    $timeout = (Get-Date).AddMinutes($TimeoutMinutes)
    $page = 1
    $allResults = [System.Collections.Generic.List[object]]::new()

    # Build splat from bound parameters, excluding our custom ones
    $splatParams = @{}
    $excludeParams = @("TimeoutMinutes", "PageSize", "Verbose", "Debug", "ErrorAction", "WarningAction",
        "InformationAction", "ErrorVariable", "WarningVariable",
        "InformationVariable", "OutVariable", "OutBuffer", "PipelineVariable")

    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin $excludeParams) {
            $splatParams[$key] = $PSBoundParameters[$key]
        }
    }

    $splatParams["ResultSize"] = $PageSize

    $moreResultsPrefix = "There are more results, use the following command to get more. "

    Write-Progress -Activity "Fetching message trace data" -Status "Page $page..."
    $results = Get-MessageTraceV2 @splatParams -WarningVariable moreAvailable 3>$null
    if ($results) { $allResults.AddRange(@($results)) }

    $nextCommand = "Get-MessageTraceV2 @splatParams"
    $moreResultsMessage = if ($moreAvailable.Count -gt 0) { $moreAvailable[-1].ToString() } else { "" }
    while ($results.Count -eq $PageSize -and $moreResultsMessage.StartsWith($moreResultsPrefix) -and (Get-Date) -lt $timeout) {
        $page++
        Write-Progress -Activity "Fetching message trace data" -Status "Retrieved $($allResults.Count) messages (page $page)..."
        $nextCommand = $moreResultsMessage.Substring($moreResultsPrefix.Length)
        $results = Invoke-Command -ScriptBlock ([ScriptBlock]::Create($nextCommand)) -WarningVariable moreAvailable 3>$null
        if ($results) { $allResults.AddRange(@($results)) }
        $moreResultsMessage = if ($moreAvailable.Count -gt 0) { $moreAvailable[-1].ToString() } else { "" }
    }

    if ($results.Count -eq $PageSize -and -not $moreResultsMessage.StartsWith($moreResultsPrefix)) {
        Write-Warning "Get-MessageTraceV2 pagination failed with unexpected warning message: '$moreResultsMessage'. Last command: '$nextCommand'"
    }

    Write-Progress -Activity "Fetching message trace data" -Completed

    if ((Get-Date) -ge $timeout) {
        Write-Warning "Timed out after $TimeoutMinutes minutes. Returning $($allResults.Count) results collected so far."
    }

    Write-Verbose "Total messages retrieved: $($allResults.Count)"
    return $allResults
}
