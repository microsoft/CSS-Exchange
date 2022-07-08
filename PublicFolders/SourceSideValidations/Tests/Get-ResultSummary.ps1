# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ResultSummary {
    [CmdletBinding()]
    param (
        [string]
        $ResultType = $(throw "ResultType is mandatory"),

        [ValidateSet("Information", "Warning", "Error")]
        [string]
        $Severity = $(throw "Severity is mandatory"),

        [int]
        $Count = $(throw "Count is mandatory"),

        [string]
        $Action = $(throw "Action is mandatory")
    )

    process {
        [PSCustomObject]@{
            ResultType = $ResultType
            Severity   = $Severity
            Count      = $Count
            Action     = $Action
        }
    }
}
