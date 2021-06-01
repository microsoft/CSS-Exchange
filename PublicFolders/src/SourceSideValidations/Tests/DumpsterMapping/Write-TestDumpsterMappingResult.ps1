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
            Write-Host $badDumpsters.Count "folders have invalid dumpster mappings."
            Write-Host $badDumpsters[0].ActionRequired
        }
    }
}
