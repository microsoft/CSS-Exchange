# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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

Write-Progress -Activity "Fetching message trace data" -Status "Page $page..."
$rawResults = @(Get-MessageTraceV2 @splatParams 3>&1)
$results = @($rawResults | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })
foreach ($w in ($rawResults | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })) {
    Write-Verbose "Get-MessageTraceV2 warning (page $page): $w"
}
if ($results) { $allResults.AddRange($results) }

$timedOut = $false
while ($results.Count -eq $PageSize) {
    if ((Get-Date) -ge $timeout) {
        $timedOut = $true
        break
    }
    $page++
    $lastResult = $results[-1]
    $splatParams["StartingRecipientAddress"] = $lastResult.RecipientAddress
    $splatParams["EndDate"] = $lastResult.Received
    Write-Progress -Activity "Fetching message trace data" -Status "Retrieved $($allResults.Count) messages (page $page)..."
    $rawResults = @(Get-MessageTraceV2 @splatParams 3>&1)
    $results = @($rawResults | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })
    foreach ($w in ($rawResults | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })) {
        Write-Verbose "Get-MessageTraceV2 warning (page $page): $w"
    }
    if ($results) { $allResults.AddRange($results) }
}

Write-Progress -Activity "Fetching message trace data" -Completed

if ($timedOut) {
    Write-Warning "Timed out after $TimeoutMinutes minutes with more results available. Returning $($allResults.Count) results collected so far."
}

Write-Verbose "Total messages retrieved: $($allResults.Count)"
return $allResults

