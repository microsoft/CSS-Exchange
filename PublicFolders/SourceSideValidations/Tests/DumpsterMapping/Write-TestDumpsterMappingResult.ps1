# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-ResultSummary.ps1

function Write-TestDumpsterMappingResult {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $TestResult
    )

    begin {
        $badDumpsters = New-Object System.Collections.ArrayList
    }

    process {
        if ($TestResult.TestName -eq "DumpsterMapping" -and $TestResult.ResultType -eq "BadDumpsterMapping") {
            $badDumpsters += $TestResult
        }
    }

    end {
        if ($badDumpsters.Count -gt 0) {
            Get-ResultSummary -ResultType $badDumpsters[0].ResultType -Severity $badDumpsters[0].Severity -Count $badDumpsters.Count -Action `
                "Use the -ExcludeDumpsters switch to skip these folders during migration, or delete the folders."
        }
    }
}
