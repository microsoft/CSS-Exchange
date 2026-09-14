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

. $PSScriptRoot\Shared\Get-AllMessageTraceResultsFunction.ps1

return Get-AllMessageTraceResults @PSBoundParameters
