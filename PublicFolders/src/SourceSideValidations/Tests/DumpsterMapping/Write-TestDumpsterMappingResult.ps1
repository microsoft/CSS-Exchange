# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        if ($TestResult.Name -eq "DumpsterMapping" -and $TestResult.ResultType -eq "BadDumpsterMapping") {
            $badDumpsters += $TestResult
        }
    }

    end {
        if ($badDumpsters.Count -gt 0) {
            Write-Host
            Write-Host $badDumpsters.Count "folders have invalid dumpster mappings. These folders"
            Write-Host "are shown in the results CSV with a result type of BadDumpsterMapping."
            Write-Host "The -ExcludeDumpsters switch can be used to skip these folders during migration, or the"
            Write-Host "folders can be deleted."
        }
    }
}
